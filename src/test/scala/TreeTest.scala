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

    it should "succeed with the correct proof" in {
        val vals: List[String] = List("one", "two", "three", "four", "five")
        val comm: Committer = new Committer(vals, Hash.Sha256)


        val proof: Proof = comm.getProof { (x: String) => x == "four" || x == "one"}

        val test = List("one", "four")
        val ok = Verifier.verify(comm.getCommit, test, proof, Hash.Sha256)

        ok should be (true)
    }

    it should "fail with incorrect values" in {
        val vals: List[String] = List("one", "two", "three", "four", "five")
        val comm: Committer = new Committer(vals, Hash.Sha256)


        val proof: Proof = comm.getProof { (x: String) => x == "four" || x == "one"}

        val test = List("one", "three")
        val ok = Verifier.verify(comm.getCommit, test, proof, Hash.Sha256)

        ok should be (false)
    }

    it should "fail with a partial proof" in {
        val vals: List[String] = List("one", "two", "three", "four", "five")
        val comm: Committer = new Committer(vals, Hash.Sha256)


        val proof: Proof = comm.getProof { (x: String) => x == "four" || x == "one"}
        val newProof = new Proof(proof.placing, proof.candidates.tail)

        val test = List("one", "four")
        val ok = Verifier.verify(comm.getCommit, test, newProof, Hash.Sha256)
        val none = Verifier.forward(test, newProof, Hash.Sha256)

        ok should be (false)
        none should be (None)
    }

    it should "fail with a lengthened proof" in {
        val vals: List[String] = List("one", "two", "three", "four", "five")
        val comm: Committer = new Committer(vals, Hash.Sha256)


        val proof: Proof = comm.getProof { (x: String) => x == "four" || x == "one"}

        val cands = proof.candidates :+ Hash.chainStr(Hash.Sha256)("hello", 1)
        val newProof = new Proof(proof.placing, cands)

        val test = List("one", "four")
        val ok = Verifier.verify(comm.getCommit, test, newProof, Hash.Sha256)
        val notNone = Verifier.forward(test, newProof, Hash.Sha256)

        ok should be (false)
        notNone should not be (None)
    }
}
