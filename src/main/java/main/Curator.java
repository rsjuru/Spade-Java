package main;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class Curator {

    private static final String DB_URL = "jdbc:sqlite:curator_data.db";
    private static int N = 40000;

    private BigInteger q;
    private BigInteger g;
    private List<BigInteger> msk;
    private List<BigInteger> mpk;

    private final SecureRandom random = new SecureRandom();

    public Connection setupDataBase() throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL);

        try (Statement stmt = conn.createStatement()) {
            stmt.execute("""
                    CREATE TABLE IF NOT EXISTS params (
                        param_name TEXT PRIMARY KEY,
                        param_value TEXT
                    )
                    """);
            
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    rk TEXT,
                    ciphertext TEXT
                )
                """);
        }

        return conn;
    }

    public void storeParameters(
            Connection conn,
            BigInteger q,
            BigInteger g,
            List<BigInteger> msk,
            List<BigInteger> mpk) throws SQLException {
        
        storeParameter(conn, "q", q.toString());
        storeParameter(conn, "g", g.toString());

        storeParameter(conn, "msk", joinBigIntegers(msk));
        storeParameter(conn, "mpk", joinBigIntegers(mpk));
    }

    private void storeParameter(
            Connection conn,
            String name,
            String value) throws SQLException {
        
        String sql = """
                INSERT OR REPLACE INTO params
                (param_name, param_value)
                VALUES (?, ?)   
                """;
        
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, name);
            stmt.setString(2, value);
            stmt.executeUpdate();
        }
    }

    public void initializeParameters() throws SQLException {

        try (Connection conn = setupDataBase()) {

            if (!parametersExist(conn)) {

                q = nextPrimeAfterPowerOfTwo(128);

                g = randomBigInteger(
                    BigInteger.ONE,
                    q
                );

                Spade spade = new Spade(q, g, N);

                Spade.SetUpResult setup = spade.setup();

                msk = setup.msk();
                mpk = setup.mpk();

                storeParameters(conn, q, g, msk, mpk);
            }
            else {

                q = new BigInteger(getParameter(conn, "q"));
                g = new BigInteger(getParameter(conn, "g"));

                msk = parseBigIntegers(
                    getParameter(conn, "msk")
                );

                mpk = parseBigIntegers(
                    getParameter(conn, "mpk")
                );
            }
        }
    }

    private boolean parametersExist(Connection conn) throws SQLException {

        String sql = """
                SELECT COUNT(*)
                FROM params
                """;

        try (Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)) {

                return rs.next() && rs.getInt(1) > 0;
        }
    }

    private String getParameter(
            Connection conn,
            String name) throws SQLException {

        String sql = """
                SELECT param_value
                FROM params
                WHERE param_name = ?
                """;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, name);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("param_value");
                }
            }
        }

        return null;
    }


    // ---------- User Management ----------

    public void storeUser(
            Connection conn,
            int userId,
            BigInteger rk) throws SQLException {

        String sql = """
                INSERT OR REPLACE INTO users
                (user_id, rk)
                VALUES (?, ?)
                """;
        
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            stmt.setString(2, rk.toString());
            stmt.executeUpdate();
        }

    }

    public void storeCiphertext(
            Connection conn,
            int userId,
            List<Spade.CiphertextPair> ciphertext)
            throws SQLException {

        String ciphertextString = serializeCiphertext(ciphertext);

        String sql = """
                UPDATE users
                SET ciphertext = ?
                WHERE user_id = ?
                """;
        
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1,ciphertextString);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        }
    }

    public BigInteger getUserRk(
            Connection conn,
            int userId) throws SQLException {

        String sql = """
                SELECT rk
                FROM users
                WHERE user_id = ?
                """;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setInt(1, userId);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new BigInteger(rs.getString("rk"));
                }
            }
        }

        return null;
    }

    // ---------- Key Derivation ----------

    public List<BigInteger> deriveKey(
            int userId,
            BigInteger v,
            int length) throws SQLException {

        if (length < 1 || length > msk.size()) {
            throw new IllegalArgumentException(
                    "Length must be between 1 and " + msk.size()
            );
        }

        try (Connection conn = setupDataBase()) {

            BigInteger rk = getUserRk(conn, userId);

            if (rk == null) {
                throw new IllegalArgumentException(
                        "User not found: " + userId
                );
            }

            Spade spade = new Spade(q, g, length);

            List<BigInteger> mskSubset =
                    new ArrayList<>(msk.subList(0, length));

            return spade.keyDer(
                    v,
                    mskSubset,
                    rk
            );
        }
    }

    // ---------- Getters -----------

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getG() {
        return g;
    }

   public List<BigInteger> getMpk(int length) {

        if (length < 1 || length > mpk.size()) {
            throw new IllegalArgumentException(
                    "Length must be between 1 and " + mpk.size()
            );
        }

        return new ArrayList<>(
                mpk.subList(0, length)
        );
    }

    // ---------- Utility Methods ----------

    private BigInteger randomBigInteger(
            BigInteger min,
            BigInteger max) {

        
        BigInteger range = max.subtract(min);

        BigInteger result;

        do {
            result = new BigInteger(
                    range.bitLength(),
                    random
            );
        } while (result.compareTo(range) >= 0);

        return min.add(result);
    }

    private static String joinBigIntegers(
            List<BigInteger> values) {

        return values.stream()
                .map(BigInteger::toString)
                .reduce((a,b) -> a + "," + b)
                .orElse("");
    }

    private static List<BigInteger> parseBigIntegers(
                String value) {
        
        List<BigInteger> result = new ArrayList<>();

        for (String part : value.split(",")) {
            result.add(new BigInteger(part));
        }

        return result;
    }

    private static String serializeCiphertext(
            List<Spade.CiphertextPair> ciphertext) {

        StringBuilder result = new StringBuilder();

        for (Spade.CiphertextPair pair : ciphertext) {
            result.append("[")
                    .append(pair.c0())
                    .append(",")
                    .append(pair.c1())
                    .append("]");
        }

        return result.toString();
    }

    private static BigInteger nextPrimeAfterPowerOfTwo(
            int bits) {

        BigInteger candidate = BigInteger.ONE.shiftLeft(bits);

        return candidate.nextProbablePrime();    
}
    
    
    
    
    

    
    
    
    
}
