import org.scalatest._
import com.bren2010.caesar._

class TreeTest extends FlatSpec with Matchers {
    it should "generate correct head with Sha1" in {
        val vals: List[String] = List("one", "two", "three", "four", "five")
        val comm: Committer = new Committer(vals, Hash.Sha1)

        val X = "107aac493155c90dc11dca227d8f170575f8b7a9"
        comm.getCommit.toHex should be (X)
    }

    it should "generate correct head with Sha256" in {
        val vals: List[String] = List("one", "two", "three", "four", "five")
        val comm: Committer = new Committer(vals, Hash.Sha256)

        val Y = "48b8f3e947b31e2431ef5deb9baccd16c1a4d096d38a10a1b13dceb4bf208ac5"
        comm.getCommit.toHex should be (Y)
    }

    it should "generate the correct proof" in {
        val vals: List[String] = List("one", "two", "three", "four", "five")
        val comm: Committer = new Committer(vals, Hash.Sha256)

        val proof: Proof = comm.getProof { (x: String) => x == "four" || x == "one"}

        proof.placing.foreach { println }
        proof.candidates.foreach { (x: Digest) => println(x.toHex) }
    }
}
