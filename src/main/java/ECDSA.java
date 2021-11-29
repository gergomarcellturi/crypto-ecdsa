import com.starkbank.ellipticcurve.*;
import com.starkbank.ellipticcurve.Math;
import com.starkbank.ellipticcurve.utils.BinaryAscii;
import com.starkbank.ellipticcurve.utils.RandomInteger;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static com.starkbank.ellipticcurve.Math.*;

public class ECDSA {

    public PrivateKey privateKey;
    public PublicKey publicKey;
    public Curve curve;

    public MessageDigest hashfunc;

    public ECDSA() throws NoSuchAlgorithmException {
        this.privateKey = new PrivateKey();
        this.publicKey = this.privateKey.publicKey();
        this.curve = this.privateKey.curve;
        this.hashfunc = MessageDigest.getInstance("SHA-256");
    }
    public ECDSA(String hash) throws NoSuchAlgorithmException {
        this.privateKey = new PrivateKey();
        this.publicKey = this.privateKey.publicKey();
        this.curve = this.privateKey.curve;
        this.hashfunc = MessageDigest.getInstance(hash);
    }

    public Point multiply(Point point, BigInteger number ) {
        return Math.multiply(point, number, this.curve.N, this.curve.A, this.curve.P);
    }

    public Point add(Point p, Point q) {
        return fromJacobian(jacobianAdd(toJacobian(p), toJacobian(q), this.curve.A, this.curve.P), this.curve.P);
    }

    public Signature sign(String message) throws NoSuchAlgorithmException {
        byte[] hashMessage = hashfunc.digest(message.getBytes());
        BigInteger numberMessage = BinaryAscii.numberFromString(hashMessage);
        BigInteger q = this.curve.N;
        Point G = this.curve.G;

        BigInteger randNum = RandomInteger.between(BigInteger.ONE, q); // kE
        Point R = multiply(G, randNum);
        BigInteger r = R.x;
        BigInteger s = ((numberMessage.add(privateKey.secret.multiply(r))).multiply(randNum.modInverse(q))).mod(q);
        return new Signature(r, s);
    }

    public boolean verify(String message, Signature signature) throws NoSuchAlgorithmException {
        byte[] hashMessage = hashfunc.digest(message.getBytes());
        BigInteger numberMessage = BinaryAscii.numberFromString(hashMessage);
        Point G = this.curve.G;
        Curve curve = this.publicKey.curve;
        BigInteger q = this.curve.N;
        BigInteger r = signature.r;
        BigInteger s = signature.s;

        BigInteger w = s.modInverse(q);

        BigInteger u1 = w.multiply(numberMessage).mod(q);
        BigInteger u2 = w.multiply(r).mod(q);


        Point u1G = this.multiply(curve.G, u1);
        Point u2B = this.multiply(this.publicKey.point, u2);

        Point P = add(u1G, u2B);
        return r.equals(P.x.mod(q));

    }

}
