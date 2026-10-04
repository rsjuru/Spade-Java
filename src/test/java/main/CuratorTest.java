package main;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger; 

import org.junit.jupiter.api.Test;

public class CuratorTest {

    @Test 
    void testInitializeParameters() throws Exception {

        Curator curator = new Curator();

        curator.initializeParameters();

        assertNotNull(curator.getQ());
        assertNotNull(curator.getG());

        assertTrue(curator.getQ().compareTo(BigInteger.ONE) > 0);
        assertTrue(curator.getG().compareTo(BigInteger.ONE) >= 0);

        assertEquals(40000, curator.getMpk(40000).size());
    }

    @Test 
    void testGetMpkLength() throws Exception {

        Curator curator = new Curator();

        curator.initializeParameters();

        assertEquals(10, curator.getMpk(10).size());
        assertEquals(100, curator.getMpk(100).size());
        assertEquals(40000, curator.getMpk(40000).size());
    }

    @Test 
    void testStoreAndGetUser() throws Exception {

        Curator curator = new Curator();

        curator.initializeParameters();

        int userId = 1234;
        BigInteger rk = BigInteger.valueOf(123456789);

        try (var conn = curator.setupDataBase()) {
            curator.storeUser(conn, userId, rk);

            BigInteger retrieved = curator.getUserRk(conn, userId);

            assertEquals(rk, retrieved);
        }
    }

    @Test
    void testGetMpkBoundaryLengths() throws Exception {

        Curator curator = new Curator();
        curator.initializeParameters();

        assertEquals(1, curator.getMpk(1).size());
        assertEquals(40000, curator.getMpk(40000).size());
    }

    @Test
    void testGetMpkInvalidLengths() throws Exception {

        Curator curator = new Curator();
        curator.initializeParameters();

        assertThrows(
                IllegalArgumentException.class,
                () -> curator.getMpk(0)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> curator.getMpk(40001)
        );
    }

    @Test
    void testGetUserRkForNonexistentUser() throws Exception {

        Curator curator = new Curator();
        curator.initializeParameters();

        try (var conn = curator.setupDataBase()) {

            BigInteger rk =
                    curator.getUserRk(conn, 999999);

            assertNull(rk);
        }
    }

    @Test
    void testDeriveKeyForNonexistentUser() throws Exception {

        Curator curator = new Curator();
        curator.initializeParameters();

        assertThrows(
                IllegalArgumentException.class,
                () -> curator.deriveKey(
                        999999,
                        BigInteger.valueOf(5),
                        10
                )
        );
    }

    @Test
    void testDeriveKeyBoundaryLengths() throws Exception {

        Curator curator = new Curator();
        curator.initializeParameters();

        int userId = 1234;
        BigInteger rk = BigInteger.valueOf(123456789);

        try (var conn = curator.setupDataBase()) {
            curator.storeUser(conn, userId, rk);
        }

        assertEquals(
                1,
                curator.deriveKey(
                        userId,
                        BigInteger.valueOf(5),
                        1
                ).size()
        );

        assertEquals(
                40000,
                curator.deriveKey(
                        userId,
                        BigInteger.valueOf(5),
                        40000
                ).size()
        );
    }

    @Test
    void testDeriveKeyInvalidLengths() throws Exception {

        Curator curator = new Curator();
        curator.initializeParameters();

        int userId = 1234;
        BigInteger rk = BigInteger.valueOf(123456789);

        try (var conn = curator.setupDataBase()) {
            curator.storeUser(conn, userId, rk);
        }

        assertThrows(
                IllegalArgumentException.class,
                () -> curator.deriveKey(
                        userId,
                        BigInteger.valueOf(5),
                        0
                )
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> curator.deriveKey(
                        userId,
                        BigInteger.valueOf(5),
                        40001
                )
        );
    }
}
