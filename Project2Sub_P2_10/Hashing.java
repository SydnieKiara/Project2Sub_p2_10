import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for hashing operations.
 * Provides methods to hash strings, verify hashes, and generate salted hashes.
 */
public class Hashing {

    /**
     * Hashes the given input string using the specified algorithm.
     *
     * @param input     the string to hash
     * @param algorithm the hashing algorithm to use (MD5, SHA-1, or SHA-256)
     * @return the hashed string in hexadecimal format
     * @throws NoSuchAlgorithmException if the specified hashing algorithm is not supported
     */
    public static String hashString(String input, HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm.toString().replace("SHA1", "SHA-1"));
        byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hashBytes);
    }

    /**
     * Verifies if a given input string matches the provided hash using the specified algorithm.
     *
     * @param input     the string to verify
     * @param hash      the hash to compare against
     * @param algorithm the hashing algorithm to use (MD5, SHA-1, or SHA-256)
     * @return true if the hash of the input matches the provided hash, false otherwise
     * @throws NoSuchAlgorithmException if the specified hashing algorithm is not supported
     */
    public static boolean verifyHash(String input, String hash, HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        String computedHash = hashString(input, algorithm);
        return computedHash.equals(hash);
    }

    /**
     * Generates a salted hash for a given input string using the specified algorithm.
     *
     * @param input     the string to hash
     * @param salt      the salt to append to the input before hashing
     * @param algorithm the hashing algorithm to use (MD5, SHA-1, or SHA-256)
     * @return the salted hash in hexadecimal format
     * @throws NoSuchAlgorithmException if the specified hashing algorithm is not supported
     */
    public static String generateSaltedHash(String input, String salt, HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        String combinedInput = input + salt;
        return hashString(combinedInput, algorithm);
    }

    /**
     * Converts an array of bytes into a hexadecimal string.
     *
     * @param bytes the byte array to convert
     * @return the resulting hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}