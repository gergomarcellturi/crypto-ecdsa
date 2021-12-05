import com.starkbank.ellipticcurve.PrivateKey;
import com.starkbank.ellipticcurve.PublicKey;


public class Crypto {

    public static void main(String[] args) throws Exception {

        ECDSA ecdsa = new ECDSA();

        Signature signature1 = ecdsa.sign("Hello World");
        Signature signature2 = ecdsa.sign("This is the second test");
        Signature signature3 = ecdsa.sign("Cryptography");

        System.out.println("true - " + ecdsa.verify("Hello World", signature1));
        System.out.println("false - " + ecdsa.verify("Hello World Wrong", signature1));
        System.out.println("false - " + ecdsa.verify("Hello World Wronffewg", signature1));
        System.out.println("true - " + ecdsa.verify("Hello World", signature1));

        System.out.println("false - " + ecdsa.verify("Hello World", signature2));
        System.out.println("false - " + ecdsa.verify("World", signature2));
        System.out.println("false - " + ecdsa.verify("Heffewg", signature2));
        System.out.println("true - " + ecdsa.verify("This is the second test", signature2));

        System.out.println("false - " + ecdsa.verify("Cryptography", signature1));
        System.out.println("false - " + ecdsa.verify("Is this working?", signature1));
        System.out.println("false - " + ecdsa.verify("Does this work?", signature1));
        System.out.println("false - " + ecdsa.verify("Cryptography", signature1));

        System.out.println("true - " + ecdsa.verify("Cryptography", signature3));
        System.out.println("false - " + ecdsa.verify("Is this working?", signature3));
        System.out.println("false - " + ecdsa.verify("Does this work?", signature3));
        System.out.println("true - " + ecdsa.verify("Cryptography", signature3));

    }
}
