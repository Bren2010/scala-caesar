package com.bren2010.caesar

import java.security._
import javax.crypto._

case class Password(pass: String)
case class SymmetricKey(key: Array[Byte])



case class KeyPair(pubKey: PublicKey, privKey: PrivateKey)