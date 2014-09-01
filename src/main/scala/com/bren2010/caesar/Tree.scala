package com.bren2010.caesar
/** A Merkle Tree is a cryptographic primitive that allows efficient commitment 
  * to a set of values.
  *
  * http://en.wikipedia.org/wiki/Merkle_tree
  */

import javax.xml.bind._

sealed case class TaggedDigest(tag: Boolean, digest: Digest)
sealed case class KV(key: Int, value: Digest)

sealed case class Derp(candidates: List[Digest], level: List[TaggedDigest])
sealed case class Herp(prev: Option[KV], soFar: List[KV])
// sealed case class Foo

/** Represents a proof of committment in a Merkle tree. */
case class Proof(placing: List[Int], candidates: List[Digest])

/** Manages Merkle commitment to a set of values.
  *
  * @param vals Array of values that should be committed to.
  * @param alg  Hash algorithm to use.
  */
case class Committer(vals: List[String], alg: Hash.Algorithm) {
    val levels: Int = math.ceil(math.log(vals.length) / math.log(2)).toInt
    val baseSize: Int = math.pow(2, levels).toInt
    
    val masked: List[Digest] = vals.padTo(baseSize, "0").map { hashStr }

    def hash(input: Array[Byte]): Digest = Hash.chain(alg)(input, 1)
    def hashStr(input: String): Digest = Hash.chainStr(alg)(input, 1)

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
        def comb(p: List[TaggedDigest]) = new TaggedDigest(
            p.head.tag || p.last.tag,
            hash(p.head.digest.toBytes ++ p.last.digest.toBytes)
        )

        val placing = (0 to vals.length - 1).foldLeft[List[Int]](List()) {
            (soFar: List[Int], curr: Int) =>
                if (filter(vals(curr))) soFar :+ curr
                else soFar
        }

        val base: Derp = new Derp(List(), vals.map { (cand: String) =>
            new TaggedDigest(filter(cand), hashStr(cand))
        })

        val derp = (1 to levels).foldLeft[Derp](base) { (derp: Derp, x: Int) =>
            val grouped = derp.level.grouped(2).toList

            val nextLevel = grouped.map(comb).toList
            val newCands = grouped.filter { (pair: List[TaggedDigest]) =>
                pair.head.tag ^ pair.last.tag
            }.map { (pair: List[TaggedDigest]) =>
                if (pair.head.tag) pair.last.digest
                else pair.head.digest
            }
            
            new Derp(derp.candidates ++ newCands, nextLevel)
        }

        new Proof(placing, derp.candidates)
    }
}

/** Container for tree verification methods. */
//object Verifier {
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
//    def verify(head: Digest, values: List[String], proof: Proof): Boolean =
//        forward(values, proof).toHex == head.toHex

    /** Applies the given proof to the given values and returns a Digest.
      * Represents the full reconstruction of a Merkle tree with only 
      * partial information of its structure.
      *
      * @param values The values that are being considered.  (See above above.)
      * @param proof  The provided proof of commitment.
      */
    /*
    def forward(values: List[String], proof: Proof): Digest = {
        Pair keys from proof.placing with values . *
        val size: Int = math.min(values.length, proof.placing.length) - 1
        val base: List[KV] = (0 to size).foldLeft[List[KV](List()) {
            (soFar: List[KV], x: Int) =>
                soFar :+ new KV(proof.placing(x), X.hashStr(values(x))
        }

        def RunOnce(kvs: List[KV], cands: List[Digest]): Foo = {
            val herp = (0 to size).foldLeft[Herp](new Herp(None, List())) {
                ()
            }
        }
    }
    */
//}
