package ghidracalculator.utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;
import java.util.zip.Adler32;

/**
 * Utility class for common hash function operations used in reverse engineering.
 */
public class HashUtils {
    /**
     * Hash algorithm enumeration
     */
    public enum HashAlgorithm {
        MD5("MD5", 128),
        SHA1("SHA-1", 160),
        SHA256("SHA-256", 256),
        SHA512("SHA-512", 512),
        CRC32("CRC32", 32),
        ADLER32("Adler32", 32);
        
        private final String algorithmName;
        private final int bitLength;
        
        HashAlgorithm(String algorithmName, int bitLength) {
            this.algorithmName = algorithmName;
            this.bitLength = bitLength;
        }
        
        public String getAlgorithmName() { return algorithmName; }
        public int getBitLength() { return bitLength; }
        public int getByteLength() { return bitLength / 8; }
    }
    
    /**
     * Hash result container
     */
    public static class HashResult {
        private final byte[] hashBytes;
        private final HashAlgorithm algorithm;
        
        public HashResult(byte[] hashBytes, HashAlgorithm algorithm) {
            this.hashBytes = hashBytes.clone();
            this.algorithm = algorithm;
        }
        
        public byte[] getBytes() { return hashBytes.clone(); }
        public HashAlgorithm getAlgorithm() { return algorithm; }
        
        public String toHexString() {
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b & 0xFF));
            }
            return sb.toString();
        }
        
        public String toUpperHexString() {
            return toHexString().toUpperCase();
        }
        
        public BigInteger toBigInteger() {
            return new BigInteger(1, hashBytes);
        }
        
        public long toLong() {
            if (hashBytes.length > 8) {
                throw new IllegalStateException("Hash too large to convert to long");
            }
            
            long result = 0;
            for (int i = 0; i < hashBytes.length; i++) {
                result = (result << 8) | (hashBytes[i] & 0xFF);
            }
            return result;
        }
        
        public int toInt() {
            if (hashBytes.length > 4) {
                throw new IllegalStateException("Hash too large to convert to int");
            }
            
            int result = 0;
            for (int i = 0; i < hashBytes.length; i++) {
                result = (result << 8) | (hashBytes[i] & 0xFF);
            }
            return result;
        }
    }
    
    /**
     * Calculate hash of a string using the specified algorithm
     * @param input Input string
     * @param algorithm Hash algorithm to use
     * @return HashResult containing the hash
     */
    public static HashResult calculateHash(String input, HashAlgorithm algorithm) {
        return calculateHash(input.getBytes(StandardCharsets.UTF_8), algorithm);
    }
    
    /**
     * Calculate hash of byte array using the specified algorithm
     * @param input Input bytes
     * @param algorithm Hash algorithm to use
     * @return HashResult containing the hash
     */
    public static HashResult calculateHash(byte[] input, HashAlgorithm algorithm) {
        switch (algorithm) {
            case CRC32:
                return calculateCRC32(input);
            case ADLER32:
                return calculateAdler32(input);
            default:
                return calculateMessageDigest(input, algorithm);
        }
    }
    
    /**
     * Calculate hash of a BigInteger value
     * @param value Input value
     * @param algorithm Hash algorithm to use
     * @return HashResult containing the hash
     */
    public static HashResult calculateHash(BigInteger value, HashAlgorithm algorithm) {
        return calculateHash(value.toByteArray(), algorithm);
    }
    
    /**
     * Calculate message digest hash (MD5, SHA1, SHA256, SHA512)
     */
    private static HashResult calculateMessageDigest(byte[] input, HashAlgorithm algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm.getAlgorithmName());
            byte[] hashBytes = digest.digest(input);
            return new HashResult(hashBytes, algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not available: " + algorithm.getAlgorithmName(), e);
        }
    }
    
    /**
     * Calculate CRC32 hash
     */
    private static HashResult calculateCRC32(byte[] input) {
        CRC32 crc32 = new CRC32();
        crc32.update(input);
        long crcValue = crc32.getValue();
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((crcValue >> 24) & 0xFF);
        hashBytes[1] = (byte) ((crcValue >> 16) & 0xFF);
        hashBytes[2] = (byte) ((crcValue >> 8) & 0xFF);
        hashBytes[3] = (byte) (crcValue & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.CRC32);
    }
    
    /**
     * Calculate Adler32 hash
     */
    private static HashResult calculateAdler32(byte[] input) {
        Adler32 adler32 = new Adler32();
        adler32.update(input);
        long adlerValue = adler32.getValue();
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((adlerValue >> 24) & 0xFF);
        hashBytes[1] = (byte) ((adlerValue >> 16) & 0xFF);
        hashBytes[2] = (byte) ((adlerValue >> 8) & 0xFF);
        hashBytes[3] = (byte) (adlerValue & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.ADLER32);
    }
    
    /**
     * Calculate MD5 hash (convenience method)
     * @param input Input string
     * @return MD5 hash as hex string
     */
    public static String md5(String input) {
        return calculateHash(input, HashAlgorithm.MD5).toHexString();
    }
    
    /**
     * Calculate SHA1 hash (convenience method)
     * @param input Input string
     * @return SHA1 hash as hex string
     */
    public static String sha1(String input) {
        return calculateHash(input, HashAlgorithm.SHA1).toHexString();
    }
    
    /**
     * Calculate SHA256 hash (convenience method)
     * @param input Input string
     * @return SHA256 hash as hex string
     */
    public static String sha256(String input) {
        return calculateHash(input, HashAlgorithm.SHA256).toHexString();
    }
    
    /**
     * Calculate CRC32 hash (convenience method)
     * @param input Input string
     * @return CRC32 hash as hex string
     */
    public static String crc32(String input) {
        return calculateHash(input, HashAlgorithm.CRC32).toHexString();
    }
    
    /**
     * Calculate hash of memory region
     * @param startValue Start address value
     * @param length Length in bytes
     * @param algorithm Hash algorithm to use
     * @return HashResult containing the hash
     */
    public static HashResult calculateMemoryHash(BigInteger startValue, int length, 
                                               HashAlgorithm algorithm) {
        // Create a byte array representing the memory region
        byte[] memoryBytes = new byte[length];
        
        // Fill with pattern based on start address (for demonstration)
        // In a real implementation, this would read from actual memory
        for (int i = 0; i < length; i++) {
            BigInteger addr = startValue.add(BigInteger.valueOf(i));
            memoryBytes[i] = addr.byteValue();
        }
        
        return calculateHash(memoryBytes, algorithm);
    }
    
    /**
     * Verify hash against expected value
     * @param input Input data
     * @param expectedHash Expected hash value
     * @param algorithm Hash algorithm
     * @return true if hash matches
     */
    public static boolean verifyHash(byte[] input, String expectedHash, HashAlgorithm algorithm) {
        HashResult result = calculateHash(input, algorithm);
        return result.toHexString().equalsIgnoreCase(expectedHash);
    }
    
    /**
     * Compare two hash results
     * @param hash1 First hash
     * @param hash2 Second hash
     * @return true if hashes are equal
     */
    public static boolean compareHashes(HashResult hash1, HashResult hash2) {
        if (hash1.getAlgorithm() != hash2.getAlgorithm()) {
            return false;
        }
        
        byte[] bytes1 = hash1.getBytes();
        byte[] bytes2 = hash2.getBytes();
        
        if (bytes1.length != bytes2.length) {
            return false;
        }
        
        for (int i = 0; i < bytes1.length; i++) {
            if (bytes1[i] != bytes2[i]) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Get hash information string
     * @param result Hash result
     * @return Information string
     */
    public static String getHashInfo(HashResult result) {
        StringBuilder info = new StringBuilder();
        info.append("Algorithm: ").append(result.getAlgorithm().getAlgorithmName()).append("\n");
        info.append("Bit Length: ").append(result.getAlgorithm().getBitLength()).append("\n");
        info.append("Hex: ").append(result.toHexString()).append("\n");
        info.append("Upper Hex: ").append(result.toUpperHexString()).append("\n");
        info.append("BigInteger: ").append(result.toBigInteger().toString()).append("\n");
        
        if (result.getAlgorithm().getBitLength() <= 64) {
            info.append("Long: ").append(result.toLong()).append("\n");
        }
        
        if (result.getAlgorithm().getBitLength() <= 32) {
            info.append("Int: ").append(result.toInt()).append("\n");
        }
        
        return info.toString();
    }
    
    /**
     * Calculate multiple hashes for the same input
     * @param input Input data
     * @param algorithms Algorithms to use
     * @return Array of hash results
     */
    public static HashResult[] calculateMultipleHashes(byte[] input, HashAlgorithm... algorithms) {
        HashResult[] results = new HashResult[algorithms.length];
        for (int i = 0; i < algorithms.length; i++) {
            results[i] = calculateHash(input, algorithms[i]);
        }
        return results;
    }
    
    /**
     * Simple hash function for demonstration (djb2 algorithm)
     * @param input Input string
     * @return Hash value
     */
    public static long djb2Hash(String input) {
        long hash = 5381;
        for (byte b : input.getBytes(StandardCharsets.UTF_8)) {
            hash = ((hash << 5) + hash) + (b & 0xFF);
        }
        return hash;
    }
    
    /**
     * FNV-1a hash function
     * @param input Input string
     * @return Hash value
     */
    public static long fnv1aHash(String input) {
        final long FNV_OFFSET_BASIS = 0xcbf29ce484222325L;
        final long FNV_PRIME = 0x100000001b3L;
        
        long hash = FNV_OFFSET_BASIS;
        for (byte b : input.getBytes(StandardCharsets.UTF_8)) {
            hash ^= (b & 0xFF);
            hash *= FNV_PRIME;
        }
        return hash;
    }
    
    /**
     * Calculate hash chain (hash of hash)
     * @param input Input data
     * @param algorithm Hash algorithm
     * @param iterations Number of iterations
     * @return Final hash result
     */
    public static HashResult calculateHashChain(byte[] input, HashAlgorithm algorithm, int iterations) {
        HashResult result = calculateHash(input, algorithm);
        
        for (int i = 1; i < iterations; i++) {
            result = calculateHash(result.getBytes(), algorithm);
        }
        
        return result;
    }
}
