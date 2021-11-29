import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.PublicKey;


public class Crypto {

    public static void main(String[] args) throws Exception {

        ECDSA ecdsa = new ECDSA();

        Signature signature = ecdsa.sign("Hello World");
        System.out.println(ecdsa.verify("Hello World", signature));
        System.out.println(ecdsa.verify("Hello World Wrong", signature));
        System.out.println(ecdsa.verify("Hello World", signature));

    }
}
