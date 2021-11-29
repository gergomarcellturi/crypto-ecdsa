import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.PublicKey;


public class Crypto {

    public static void main(String[] args) throws Exception {

        ECDSA ecdsa = new ECDSA();

        Signature signature = ecdsa.sign("Hello World");
        ecdsa.verify("Hello World", signature);
    }
}
