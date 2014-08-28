package com.bren2010.caesar

import java.security._
import javax.xml.bind._

case class Digest(out: Array[Byte]) {
	def toHex(): String = DatatypeConverter.printHexBinary(out).toLowerCase()
	def toBytes(): Array[Byte] = out
}

object Hash {
	object Algorithm extends Enumeration {
		val Sha1, Sha256, Sha512 = Value
	}

	def chainStr(alg: Algorithm.Value)(anchor: String, n: Int): Digest =
		chain(alg)(anchor.getBytes("UTF-8"), n)

	def chain(alg: Algorithm.Value)(anchor: Array[Byte], n: Int): Digest = {
		def RunOnce(algName: String, input: Array[Byte]): Digest = {
			val md: MessageDigest = MessageDigest.getInstance(algName)

			new Digest(md.digest(input))
		}

		val algName: String = alg match {
			case Algorithm.Sha1   => "SHA-1"
			case Algorithm.Sha256 => "SHA-256"
			case Algorithm.Sha512 => "SHA-512"
			case _ => "SHA-512"
		}

		val base: Digest = RunOnce(algName, anchor)

		(2 to n).foldLeft[Digest](base) { (input, x) =>
			if (alg == Algorithm.Sha1 && input.toBytes().length == 20) {
				RunOnce(algName, input.toHex().getBytes("UTF-8"))
			} else {
				RunOnce(algName, input.toBytes())
			}
		}
	}
}