import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the Hashing class.
 */
public class HashingTest {

    /**
     * Tests the hashString method with MD5, SHA-1, and SHA-256 algorithms.
     */
    @Test
    void testHashString() throws Exception {
        String input = "hello";

        String md5Hash = Hashing.hashString(input, HashAlgorithm.MD5);
        assertNotNull(md5Hash, "MD5 hash should not be null");
        assertEquals(32, md5Hash.length(), "MD5 hash should be 32 characters long");

        String sha1Hash = Hashing.hashString(input, HashAlgorithm.SHA1);
        assertNotNull(sha1Hash, "SHA-1 hash should not be null");
        assertEquals(40, sha1Hash.length(), "SHA-1 hash should be 40 characters long");

        String sha256Hash = Hashing.hashString(input, HashAlgorithm.SHA256);
        assertNotNull(sha256Hash, "SHA-256 hash should not be null");
        assertEquals(64, sha256Hash.length(), "SHA-256 hash should be 64 characters long");
    }

    /**
     * Tests the verifyHash method for matching and non-matching hashes.
     */
    @Test
    void testVerifyHash() throws Exception {
        String input = "test123";
        
        // Test MD5
        String md5Hash = Hashing.hashString(input, HashAlgorithm.MD5);
        assertTrue(Hashing.verifyHash(input, md5Hash, HashAlgorithm.MD5), "MD5 hash should match input");
        assertFalse(Hashing.verifyHash("wrongInput", md5Hash, HashAlgorithm.MD5), "MD5 hash should not match wrong input");

        // Test SHA-1
        String sha1Hash = Hashing.hashString(input, HashAlgorithm.SHA1);
        assertTrue(Hashing.verifyHash(input, sha1Hash, HashAlgorithm.SHA1), "SHA-1 hash should match input");
        assertFalse(Hashing.verifyHash("wrongInput", sha1Hash, HashAlgorithm.SHA1), "SHA-1 hash should not match wrong input");

        // Test SHA-256
        String sha256Hash = Hashing.hashString(input, HashAlgorithm.SHA256);
        assertTrue(Hashing.verifyHash(input, sha256Hash, HashAlgorithm.SHA256), "SHA-256 hash should match input");
        assertFalse(Hashing.verifyHash("wrongInput", sha256Hash, HashAlgorithm.SHA256), "SHA-256 hash should not match wrong input");
    }

    /**
     * Tests the generateSaltedHash method with SHA-256 and a provided salt.
     */
    @Test
    void testGenerateSaltedHash() throws Exception {
        String input = "mypassword";
        String salt = "randomSalt";

        String saltedHash = Hashing.generateSaltedHash(input, salt, HashAlgorithm.SHA256);
        assertNotNull(saltedHash, "Salted hash should not be null");
        assertEquals(64, saltedHash.length(), "SHA-256 hash should be 64 characters long");

        // Ensure that salted hashes of different salts are not the same
        String differentSaltedHash = Hashing.generateSaltedHash(input, "differentSalt", HashAlgorithm.SHA256);
        assertNotEquals(saltedHash, differentSaltedHash, "Hashes with different salts should not match");

        // Ensure that reusing the same salt produces the same hash
        String sameSaltedHash = Hashing.generateSaltedHash(input, salt, HashAlgorithm.SHA256);
        assertEquals(saltedHash, sameSaltedHash, "Hashes with the same salt and input should match");
    }
}
