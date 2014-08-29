import org.scalatest._
import com.bren2010.caesar._

class HashTest extends FlatSpec with Matchers {
    "Sha1(x)" should "produce value X" in {
        val input: String = "quick fox"
        val X: String = "ef019eee49a7289dc7143d486a200565fedc139d"

        Hash.chainStr(Hash.Sha1)(input, 3).toHex should be (X)
    }

    "Sha256(y)" should "produce value Y" in {
        val input: String = "lazy dog"
        val Y: String = "91c92845824a42fe60fa407cb76729c0ad7ba46cfb1c08879f6dd30e6073d505"

        Hash.chainStr(Hash.Sha256)(input, 3).toHex should be (Y)
    }
}
