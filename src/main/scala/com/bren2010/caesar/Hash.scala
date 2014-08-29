package com.bren2010.caesar

import java.security._
import javax.xml.bind._

/** A hash digest (the output of a hash function).
  * 
  * @constructor creates a new digest
  * @param out   Bytes of the digest.
  */
case class Digest(out: Array[Byte]) {
    /** Converts digest to a hex string. */
    def toHex: String = DatatypeConverter.printHexBinary(out).toLowerCase

    /** Returns digest's raw bytes. */
    def toBytes: Array[Byte] = out
}

/** Container for hash-related functions. */
object Hash {
    /** ADT of available hashing algorithms. */
    sealed trait Algorithm
    case object Sha1   extends Algorithm { override def toString = "SHA-1" }
    case object Sha256 extends Algorithm { override def toString = "SHA-256" }
    case object Sha512 extends Algorithm { override def toString = "SHA-512" }

    /** Builds a hash chain with a string as the anchor.  Returns a Digest.
      * 
      * @param alg    Hashing algorithm to use.
      * @param anchor Anchor of the chain.
      * @param n      Length of the chain.
      */
    def chainStr(alg: Algorithm)(anchor: String, n: Int): Digest =
        chain(alg)(anchor.getBytes("UTF-8"), n)

    /** Builds a hash chain.  Returns a Digest.
      * 
      * @param alg    Hashing algorithm to use.
      * @param anchor Anchor of the chain.
      * @param n      Length of the chain.
      */
    def chain(alg: Algorithm)(anchor: Array[Byte], n: Int): Digest = {
        def RunOnce(input: Array[Byte]): Digest = {
            val md: MessageDigest = MessageDigest.getInstance(alg.toString)
            new Digest(md.digest(input))
        }

        val base: Digest = RunOnce(anchor)

        (2 to n).foldLeft[Digest](base) { (input, x) =>
          alg match {
            case Sha1 => RunOnce(input.toHex.getBytes("UTF-8"))
            case _    => RunOnce(input.toBytes)
          }
        }
    }
}