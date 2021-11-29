import com.starkbank.ellipticcurve.*;
import com.starkbank.ellipticcurve.Math;
import com.starkbank.ellipticcurve.utils.BinaryAscii;
import com.starkbank.ellipticcurve.utils.RandomInteger;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ECDSA {

    public PrivateKey privateKey;
    public PublicKey publicKey;
    public Curve curve;

    public ECDSA() {
        this.privateKey = new PrivateKey();
        this.publicKey = this.privateKey.publicKey();
        this.curve = this.privateKey.curve;
    }

    public Point multiply(Point point, BigInteger number ) {
        return Math.multiply(point, number, this.curve.N, this.curve.A, this.curve.P);
    }

    public Signature sign(String message) throws NoSuchAlgorithmException {
        MessageDigest hashfunc = MessageDigest.getInstance("SHA-256");
        byte[] hashMessage = hashfunc.digest(message.getBytes());
        BigInteger numberMessage = BinaryAscii.numberFromString(hashMessage);
        BigInteger q = this.curve.N;
        Point G = this.curve.G;

        BigInteger randNum = RandomInteger.between(BigInteger.ONE, q); // kE
        Point R = multiply(curve.G, randNum);
//        BigInteger r = R.x.mod(curve.N);
        BigInteger r = R.x;
        BigInteger s = ((numberMessage.add(r.multiply(privateKey.secret))).multiply(Math.inv(randNum, curve.N))).mod(q);
        return new Signature(r, s);
    }

    public boolean verify(String message, Signature signature) throws NoSuchAlgorithmException {
        MessageDigest hashfunc = MessageDigest.getInstance("SHA-256");
        byte[] hashMessage = hashfunc.digest(message.getBytes());
        BigInteger numberMessage = BinaryAscii.numberFromString(hashMessage);
        Curve curve = this.publicKey.curve;
        BigInteger r = signature.r;
        BigInteger s = signature.s;

        BigInteger w = Math.inv(s, curve.N);
        Point u1 =Math.multiply(curve.G, numberMessage.multiply(w).mod(curve.N), curve.N, curve.A, curve.P);
        Point u2 = Math.multiply(this.publicKey.point, r.multiply(w).mod(curve.N), curve.N, curve.A, curve.P);
        Point v = Math.add(u1, u2, curve.A, curve.P);
        if (v.isAtInfinity()) {
            return false;
        }
        return v.x.mod(curve.N).equals(r);
    }

}
