package main;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class Spade {

    private final BigInteger q;
    private final BigInteger g;
    private final int n;
    private final SecureRandom random;

    public Spade(BigInteger q, BigInteger g, int n) {
        this.q = q;
        this.g = g;
        this.n = n;
        this.random = new SecureRandom();
    }

    private BigInteger randomIntRange(BigInteger minVal, BigInteger maxVal) {
        BigInteger diff = maxVal.subtract(minVal);

        BigInteger r;

        do {
            r = new BigInteger(diff.bitLength(), random);
        } while (r.compareTo(diff) >= 0);

        return minVal.add(r);
    }

    private BigInteger randomOddInt(BigInteger q) {
        while(true) {
            BigInteger r = randomIntRange(BigInteger.ONE, q);

            if(r.mod(BigInteger.TWO).equals(BigInteger.ONE)) {
                return r;
            }
        }
    }

    public record SetUpResult(List<BigInteger> msk, List<BigInteger> mpk) {}
    
    public SetUpResult setup() {
        List<BigInteger> msk = new ArrayList<>();
        List<BigInteger> mpk = new ArrayList<>();

        for (int i = 0; i < n; i++) {
            BigInteger secret = randomIntRange(BigInteger.ONE, q);
            msk.add(secret);

            BigInteger publicKey = g.modPow(secret, q);
            mpk.add(publicKey);
        }

        return new SetUpResult(msk, mpk);
    }

    public BigInteger register(BigInteger alpha) {
        return g.modPow(alpha, q);
    }

    public record CiphertextPair(BigInteger c0, BigInteger c1) {}

    public List<CiphertextPair> enc(
            List<BigInteger> mpk,
            List<BigInteger> x,
            BigInteger alpha) {
        
        List<CiphertextPair> ciphertext = new ArrayList<>();

        // Precompute mpk[i]^alpha mod q
        List<BigInteger> precomputedAlphaPowers = new ArrayList<>();

        for (int i = 0; i < x.size(); i++) {
            BigInteger value = mpk.get(i).modPow(alpha, q);
            precomputedAlphaPowers.add(value);
        }

        // Compute g^alpha mod q
        BigInteger alphaG = g.modPow(alpha, q);

        for(int i = 0; i < x.size(); i++) {
            BigInteger m = x.get(i);

            // Generate a random odd integer
            BigInteger r = randomOddInt(q);

            // g^r mod q
            BigInteger expGR = g.modPow(r, q);

            // c0 = g^r * g^alpha mod q
            BigInteger c0 = expGR.multiply(alphaG).mod(q);

            // g^(r*m) mod q
            BigInteger expM = expGR.modPow(m, q);

            // c1 = mpk[i]^alpha * g^(r*m) mod q
            BigInteger c1 = precomputedAlphaPowers.get(i).multiply(expM).mod(q);

            ciphertext.add(new CiphertextPair(c0, c1));
        }

        return ciphertext;

    }

    private BigInteger modPow(
            BigInteger base, 
            BigInteger exp, 
            BigInteger mod) {
        
        if(exp.signum() < 0) {
            return base.modInverse(mod).modPow(exp.negate(), mod);
        }

        return base.modPow(exp, mod);
    }

    public List<BigInteger> keyDer(
            BigInteger v,
            List<BigInteger> msk,
            BigInteger rk) {
        
        List<BigInteger> dk = new ArrayList<>();

        for (int i = 0; i < n; i++) {
            BigInteger sub = v.subtract(msk.get(i));

            dk.add(modPow(rk, sub, q));
        }

        return dk;
    }

    public List<BigInteger> dec(
            List<BigInteger> dk,
            List<CiphertextPair> c,
            BigInteger v) {

        List<BigInteger> y = new ArrayList<>();

        for (int i = 0; i < n; i ++){
            BigInteger ci0exp = modPow(
                            c.get(i).c0(), 
                            v.negate(), 
                            q
            );

            BigInteger y_i = c.get(i).c1().
                                    multiply(ci0exp).
                                    multiply(dk.get(i)).
                                    mod(q);
            y.add(y_i);
        }

        return y;
    }
    
}