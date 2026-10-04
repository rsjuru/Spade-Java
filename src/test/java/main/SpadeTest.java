package main;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.security.SecureRandom;

public class SpadeTest {

    @Test
    public void testSetup() {
        BigInteger q = BigInteger.probablePrime(128, new SecureRandom());
        BigInteger g = new BigInteger(q.bitLength(), new SecureRandom()).mod(q.subtract(BigInteger.ONE))
                .add(BigInteger.ONE);     // Ensure g is in the range [1, q-1]
        int n = 3;

        Spade spade = new Spade(q, g, n);
        Spade.SetUpResult result = spade.setup();

        List<BigInteger> msk = result.msk();
        List<BigInteger> mpk = result.mpk();

        assertEquals(n, msk.size());
        assertEquals(n, mpk.size());

        for (int i = 0; i < n; i++) {
            BigInteger secret = msk.get(i);
            BigInteger publicKey = mpk.get(i);

            // Verify that the public key is correctly computed
            assertEquals(publicKey, g.modPow(secret, q));
        }
    }

    @Test 
    public void testRegister() {
        BigInteger q = BigInteger.probablePrime(128, new SecureRandom());
        BigInteger g = new BigInteger(q.bitLength(), new SecureRandom()).mod(q.subtract(BigInteger.ONE))
                .add(BigInteger.ONE);     // Ensure g is in the range [1, q-1]
        int n = 3;

        Spade spade = new Spade(q, g, n);
        BigInteger alpha = new BigInteger("7");

        BigInteger result = spade.register(alpha);

        // Verify that the result is within the expected range
        assert(result.compareTo(BigInteger.ONE) >= 0 && result.compareTo(q) < 0);
    }

    @Test
    void encryptionAndDecryptionIdentifiesMatchingValues() {

        SecureRandom random = new SecureRandom();

        BigInteger q = BigInteger.probablePrime(128, random);

        BigInteger g = new BigInteger(q.bitLength(), random)
                .mod(q.subtract(BigInteger.ONE))
                .add(BigInteger.ONE);

        int n = 10;

        Spade spade = new Spade(q, g, n);

        Spade.SetUpResult setup = spade.setup();

        List<BigInteger> msk = setup.msk();
        List<BigInteger> mpk = setup.mpk();

        // Example plaintext
        List<BigInteger> x = List.of(
                BigInteger.valueOf(3),
                BigInteger.valueOf(7),
                BigInteger.valueOf(5),
                BigInteger.valueOf(2),
                BigInteger.valueOf(5),
                BigInteger.valueOf(9),
                BigInteger.valueOf(1),
                BigInteger.valueOf(4),
                BigInteger.valueOf(5),
                BigInteger.valueOf(8)
        );

        // Value we want to search for
        BigInteger v = BigInteger.valueOf(3);

        // User's private value
        BigInteger alpha = new BigInteger(q.bitLength(), random)
                .mod(q.subtract(BigInteger.ONE))
                .add(BigInteger.ONE);

        // Registration key
        BigInteger rk = spade.register(alpha);

        // Encrypt
        List<Spade.CiphertextPair> ciphertext =
                spade.enc(mpk, x, alpha);

        // Derive decryption key
        List<BigInteger> dk =
                spade.keyDer(v, msk, rk);

        // Perform query/decryption
        List<BigInteger> result =
                spade.dec(dk, ciphertext, v);

        // Check that matching values produce 1
        for (int i = 0; i < x.size(); i++) {

            if (x.get(i).equals(v)) {
                assertEquals(
                        BigInteger.ONE,
                        result.get(i),
                        "Position " + i + " should match value " + v
                );
            } else {
                assertNotEquals(
                        BigInteger.ONE,
                        result.get(i),
                        "Position " + i + " should not match value " + v
                );
            }
        }
    }

}
