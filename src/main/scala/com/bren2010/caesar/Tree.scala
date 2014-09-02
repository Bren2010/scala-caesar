package com.bren2010.caesar
/** A Merkle Tree is a cryptographic primitive that allows efficient commitment 
  * to a set of values.
  *
  * http://en.wikipedia.org/wiki/Merkle_tree
  */

private case class TaggedDigest(tag: Boolean, prev: List[(Int, Digest)], digest: Digest)

/** Represents a proof of committment in a Merkle tree. */
case class Proof(placing: List[Int], candidates: List[Digest])

/** Manages Merkle commitment to a set of values.
  *
  * @param vals Array of values that should be committed to.
  * @param alg  Hash algorithm to use.
  */
case class Committer(vals: List[String], alg: Hash.Algorithm) {
    type KV = (Int, Digest) // Key-Value

    val levels: Int = math.ceil(math.log(vals.length) / math.log(2)).toInt
    val baseSize: Int = math.pow(2, levels).toInt
    
    val masked: List[Digest] = vals.padTo(baseSize, "0").map { hashStr }

    private def hash(input: Array[Byte]): Digest = Hash.chain(alg)(input, 1)
    private def hashStr(input: String): Digest = Hash.chainStr(alg)(input, 1)

    /** Calculates the commitment to the given set of objects.  (The head of the 
      * Merkle tree.)  This is what should be published.  It should be noted, 
      * this function is deterministic.  Given the same set of objects, the same 
      * value will be output.  If this isn't desireable, add a random nonce *to 
      * the end of each committed value.*  Simply adding a random nonce as one 
      * of the committed objects is detectable.
      */
    def getCommit: Digest = {
        def comb(p: List[Digest]) = hash(p.head.toBytes ++ p.last.toBytes)

        (1 to levels).foldLeft[List[Digest]](masked)(
            (level: List[Digest], x: Int) => level.grouped(2).map(comb).toList
        )(0)
    }

    /** Calculates a proof of commitment to the values that satisfy the 
      * predicate.  Publishing one proof with a predicate that's satisfied by n 
      * values is more efficient than publishing n proofs with predicates 
      * that're satisfied by 1 value each.
      *
      * @param filter An implementation of the predicate.
      */
    def getProof(filter: (String) => Boolean): Proof = {
        def comb(lvl: Int)(pair: List[TaggedDigest]): TaggedDigest = {
            val prev: List[KV] = 
                if (pair.head.tag && !pair.last.tag)
                    pair.head.prev ++ pair.last.prev :+ (lvl, pair.last.digest)
                else if (!pair.head.tag && pair.last.tag)
                    pair.head.prev ++ pair.last.prev :+ (lvl, pair.head.digest)
                else 
                    pair.head.prev ++ pair.last.prev

            new TaggedDigest(
                pair.head.tag || pair.last.tag,
                prev,
                hash(pair.head.digest.toBytes ++ pair.last.digest.toBytes)
            )
        }

        val placing = (0 to vals.length - 1).foldLeft[List[Int]](List()) {
            (soFar: List[Int], curr: Int) =>
                if (filter(vals(curr))) soFar :+ curr
                else soFar
        }

        val base: List[TaggedDigest] = vals.map({ (cand: String) =>
            new TaggedDigest(filter(cand), List(), hashStr(cand))
        }).padTo(baseSize, new TaggedDigest(false, List(), hashStr("0")))

        val candidates = (1 to levels).foldLeft[List[TaggedDigest]](base)(
            (level: List[TaggedDigest], x: Int) =>
                level.grouped(2).map(comb(x)).toList
        )(0).prev.sortBy(_._1).map(_._2)

        new Proof(placing, candidates)
    }
}

/** Container for tree verification methods. */
object Verifier {
    type KV = (Int, Digest) // Key-Value
    type Collector = (Option[KV], List[KV], List[Digest])

    /** Verifies a proof of commitment.  Returns true if the given head and 
      * and proof are a commmitment to the given values.
      *
      * The considered values should be a proper subset of the values that were 
      * commited to, with order preserved.  Otherwise, the function returns
      * false.
      *
      * @param head   Head of the Merkle tree in use.
      * @param values The values that are being considered.  (See above.)
      * @param proof  The provided proof of commitment.
      */
    def verify(head: Digest, vals: List[String], proof: Proof, alg: Hash.Algorithm): Boolean =
        forward(vals, proof, alg).getOrElse(new Digest()).toHex == head.toHex

    /** Applies the given proof to the given values and returns a Digest.
      * Represents the full reconstruction of a Merkle tree with only 
      * partial information of its structure.
      *
      * @param values The values that are being considered.  (See above above.)
      * @param proof  The provided proof of commitment.
      */
    def forward(vals: List[String], proof: Proof, alg: Hash.Algorithm): Option[Digest] = {
        def hash(input: Array[Byte]): Digest = Hash.chain(alg)(input, 1)
        def hashStr(input: String): Digest = Hash.chainStr(alg)(input, 1)

        /** Pair keys from proof.placing with values . */
        val base: List[KV] = (proof.placing zip vals).map {
            (kv: (Int, String)) => (kv._1, hashStr(kv._2))
        }

        def RunOnce(kvs: List[KV], cands: List[Digest]): (List[KV], List[Digest]) = {
            val paddedKvs: List[KV] = kvs :+ (kvs.length + 1, new Digest())

            val out = paddedKvs.foldLeft[Collector]((None, List(), cands)) {
                (state: Collector, a: KV) => state match {
                    case (None, y, z) => (Some(a), y, z)
                    case (x, y, List()) => (None, List(), List())
                    case (Some(x), y, z) =>
                        if (x._1 % 2 == 0 && x._1 + 1 == a._1) {
                            val newOut = (x._1 / 2, hash(x._2.toBytes ++ a._2.toBytes))
                            
                            (None, y :+ newOut, z)
                        } else if (x._1 % 2 == 0) {
                            val newOut = (x._1 / 2, hash(x._2.toBytes ++ z.head.toBytes))

                            (Some(a), y :+ newOut, z.tail)
                        } else {
                            val newOut = (x._1 / 2, hash(z.head.toBytes ++ x._2.toBytes))

                            (Some(a), y :+ newOut, z.tail)
                        }
                }
            }

            (out._2, out._3)
        }

        def RunSeveral(i: Int, kvs: List[KV], cands: List[Digest]): Option[Digest] = {
            val out = RunOnce(kvs, cands)

            if (out._1.length == 1 && out._2.length == 0) Some(out._1(0)._2)
            else if (out._1.length != 1 && out._2.length == 0) None
            else if (i > 100) None
            else RunSeveral(i + 1, out._1, out._2)
        }

        RunSeveral(1, base, proof.candidates)
    }
}
