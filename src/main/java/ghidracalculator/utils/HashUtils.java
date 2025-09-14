package ghidracalculator.utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

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
        SHA224("SHA-224", 224),
        SHA256("SHA-256", 256),
        SHA384("SHA-384", 384),
        SHA512("SHA-512", 512),
        CRC8("CRC8", 8),
        CRC16("CRC16", 16),
        CRC32("CRC32", 32),
        ADLER32("Adler32", 32),
        AP("AP", 32),
        BKDR("BKDR", 32),
        DEK("DEK", 32),
        DJB("DJB", 32),
        ELF("ELF", 32),
        FNV1("FNV1", 32),
        FNV1A("FNV1A", 32),
        JS("JS", 32),
        PJW("PJW", 32),
        RS("RS", 32),
        SDBM("SDBM", 32),
        SHIFTANDXOR("ShiftAndXOR", 32),
        SUPERFAST("SuperFast", 32),
        TIGER("Tiger", 192),
        BLAKE2B("Blake2B", 512),
        BLAKE2S("Blake2S", 256),
        BERNSTEIN("Bernstein", 32),
        BERNSTEIN1("Bernstein1", 32);
        
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
            case CRC8:
                return calculateCRC8(input);
            case CRC16:
                return calculateCRC16(input);
            case CRC32:
                return calculateCRC32(input);
            case ADLER32:
                return calculateAdler32(input);
            case AP:
                return calculateAP(input);
            case BKDR:
                return calculateBKDR(input);
            case DEK:
                return calculateDEK(input);
            case DJB:
                return calculateDJB(input);
            case ELF:
                return calculateELF(input);
            case FNV1:
                return calculateFNV1(input);
            case FNV1A:
                return calculateFNV1A(input);
            case JS:
                return calculateJS(input);
            case PJW:
                return calculatePJW(input);
            case RS:
                return calculateRS(input);
            case SDBM:
                return calculateSDBM(input);
            case SHIFTANDXOR:
                return calculateShiftAndXOR(input);
            case SUPERFAST:
                return calculateSuperFast(input);
            case TIGER:
                return calculateTiger(input);
            case BLAKE2B:
                return calculateBlake2B(input);
            case BLAKE2S:
                return calculateBlake2S(input);
            case BERNSTEIN:
                return calculateBernstein(input);
            case BERNSTEIN1:
                return calculateBernstein1(input);
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
     * @param program The program to read memory from
     * @param startValue Start address value
     * @param length Length in bytes
     * @param algorithm Hash algorithm to use
     * @return HashResult containing the hash
     * @throws MemoryAccessException if memory cannot be read
     */
    public static HashResult calculateMemoryHash(Program program, BigInteger startValue, int length,
                                               HashAlgorithm algorithm) throws MemoryAccessException {
        try {
            // Get memory from program
            Memory memory = program.getMemory();
            
            // Create start address
            AddressFactory addressFactory = program.getAddressFactory();
            Address startAddress = addressFactory.getDefaultAddressSpace().getAddress(startValue.toString(16));
            
            // Read memory bytes
            byte[] memoryBytes = new byte[length];
            memory.getBytes(startAddress, memoryBytes);
            
            return calculateHash(memoryBytes, algorithm);
        } catch (Exception e) {
            throw new MemoryAccessException("Failed to read memory at address " + startValue.toString(16) + ": " + e.getMessage());
        }
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
    
    /**
     * Calculate CRC-8 hash
     */
    private static HashResult calculateCRC8(byte[] input) {
        // CRC-8 polynomial: x^8 + x^2 + x^1 + 1 (0x07)
        final byte[] crc8Table = {
            (byte) 0x00, (byte) 0x07, (byte) 0x0E, (byte) 0x09, (byte) 0x1C, (byte) 0x1B, (byte) 0x12, (byte) 0x15,
            (byte) 0x38, (byte) 0x3F, (byte) 0x36, (byte) 0x31, (byte) 0x24, (byte) 0x23, (byte) 0x2A, (byte) 0x2D,
            (byte) 0x70, (byte) 0x77, (byte) 0x7E, (byte) 0x79, (byte) 0x6C, (byte) 0x6B, (byte) 0x62, (byte) 0x65,
            (byte) 0x48, (byte) 0x4F, (byte) 0x46, (byte) 0x41, (byte) 0x54, (byte) 0x53, (byte) 0x5A, (byte) 0x5D,
            (byte) 0xE0, (byte) 0xE7, (byte) 0xEE, (byte) 0xE9, (byte) 0xFC, (byte) 0xFB, (byte) 0xF2, (byte) 0xF5,
            (byte) 0xD8, (byte) 0xDF, (byte) 0xD6, (byte) 0xD1, (byte) 0xC4, (byte) 0xC3, (byte) 0xCA, (byte) 0xCD,
            (byte) 0x90, (byte) 0x97, (byte) 0x9E, (byte) 0x99, (byte) 0x8C, (byte) 0x8B, (byte) 0x82, (byte) 0x85,
            (byte) 0xA8, (byte) 0xAF, (byte) 0xA6, (byte) 0xA1, (byte) 0xB4, (byte) 0xB3, (byte) 0xBA, (byte) 0xBD,
            (byte) 0xC7, (byte) 0xC0, (byte) 0xC9, (byte) 0xCE, (byte) 0xDB, (byte) 0xDC, (byte) 0xD5, (byte) 0xD2,
            (byte) 0xFF, (byte) 0xF8, (byte) 0xF1, (byte) 0xF6, (byte) 0xE3, (byte) 0xE4, (byte) 0xED, (byte) 0xEA,
            (byte) 0xB7, (byte) 0xB0, (byte) 0xB9, (byte) 0xBE, (byte) 0xAB, (byte) 0xAC, (byte) 0xA5, (byte) 0xA2,
            (byte) 0x8F, (byte) 0x88, (byte) 0x81, (byte) 0x86, (byte) 0x93, (byte) 0x94, (byte) 0x9D, (byte) 0x9A,
            (byte) 0x27, (byte) 0x20, (byte) 0x29, (byte) 0x2E, (byte) 0x3B, (byte) 0x3C, (byte) 0x35, (byte) 0x32,
            (byte) 0x1F, (byte) 0x18, (byte) 0x11, (byte) 0x16, (byte) 0x03, (byte) 0x04, (byte) 0x0D, (byte) 0x0A,
            (byte) 0x57, (byte) 0x50, (byte) 0x59, (byte) 0x5E, (byte) 0x4B, (byte) 0x4C, (byte) 0x45, (byte) 0x42,
            (byte) 0x6F, (byte) 0x68, (byte) 0x61, (byte) 0x66, (byte) 0x73, (byte) 0x74, (byte) 0x7D, (byte) 0x7A,
            (byte) 0x89, (byte) 0x8E, (byte) 0x87, (byte) 0x80, (byte) 0x95, (byte) 0x92, (byte) 0x9B, (byte) 0x9C,
            (byte) 0xB1, (byte) 0xB6, (byte) 0xBF, (byte) 0xB8, (byte) 0xAD, (byte) 0xAA, (byte) 0xA3, (byte) 0xA4,
            (byte) 0xF9, (byte) 0xFE, (byte) 0xF7, (byte) 0xF0, (byte) 0xE5, (byte) 0xE2, (byte) 0xEB, (byte) 0xEC,
            (byte) 0xC1, (byte) 0xC6, (byte) 0xCF, (byte) 0xC8, (byte) 0xDD, (byte) 0xDA, (byte) 0xD3, (byte) 0xD4,
            (byte) 0x69, (byte) 0x6E, (byte) 0x67, (byte) 0x60, (byte) 0x75, (byte) 0x72, (byte) 0x7B, (byte) 0x7C,
            (byte) 0x51, (byte) 0x56, (byte) 0x5F, (byte) 0x58, (byte) 0x4D, (byte) 0x4A, (byte) 0x43, (byte) 0x44,
            (byte) 0x19, (byte) 0x1E, (byte) 0x17, (byte) 0x10, (byte) 0x05, (byte) 0x02, (byte) 0x0B, (byte) 0x0C,
            (byte) 0x21, (byte) 0x26, (byte) 0x2F, (byte) 0x28, (byte) 0x3D, (byte) 0x3A, (byte) 0x33, (byte) 0x34,
            (byte) 0x4E, (byte) 0x49, (byte) 0x40, (byte) 0x47, (byte) 0x52, (byte) 0x55, (byte) 0x5C, (byte) 0x5B,
            (byte) 0x76, (byte) 0x71, (byte) 0x78, (byte) 0x7F, (byte) 0x6A, (byte) 0x6D, (byte) 0x64, (byte) 0x63,
            (byte) 0x3E, (byte) 0x39, (byte) 0x30, (byte) 0x37, (byte) 0x22, (byte) 0x25, (byte) 0x2C, (byte) 0x2B,
            (byte) 0x06, (byte) 0x01, (byte) 0x08, (byte) 0x0F, (byte) 0x1A, (byte) 0x1D, (byte) 0x14, (byte) 0x13,
            (byte) 0xAE, (byte) 0xA9, (byte) 0xA0, (byte) 0xA7, (byte) 0xB2, (byte) 0xB5, (byte) 0xBC, (byte) 0xBB,
            (byte) 0x96, (byte) 0x91, (byte) 0x98, (byte) 0x9F, (byte) 0x8A, (byte) 0x8D, (byte) 0x84, (byte) 0x83,
            (byte) 0xDE, (byte) 0xD9, (byte) 0xD0, (byte) 0xD7, (byte) 0xC2, (byte) 0xC5, (byte) 0xCC, (byte) 0xCB,
            (byte) 0xE6, (byte) 0xE1, (byte) 0xE8, (byte) 0xEF, (byte) 0xFA, (byte) 0xFD, (byte) 0xF4, (byte) 0xF3
        };
        
        byte crc = 0;
        for (byte b : input) {
            crc = crc8Table[(crc ^ b) & 0xFF];
        }
        
        // Convert to 1-byte array
        byte[] hashBytes = new byte[1];
        hashBytes[0] = crc;
        
        return new HashResult(hashBytes, HashAlgorithm.CRC8);
    }
    
    /**
     * Calculate CRC-16 hash
     */
    private static HashResult calculateCRC16(byte[] input) {
        // CRC-16 polynomial: x^16 + x^15 + x^2 + 1 (0x8005)
        final int[] crc16Table = {
            0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
            0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
            0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
            0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
            0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
            0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
            0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
            0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
            0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
            0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
            0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
            0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
            0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
            0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
            0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
            0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
            0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
            0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
            0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
            0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
            0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
            0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
            0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
            0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
            0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
            0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
            0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
            0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
            0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
            0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
            0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
            0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
        };
        
        int crc = 0xFFFF;
        for (byte b : input) {
            crc = (crc >>> 8) ^ crc16Table[(crc ^ b) & 0xFF];
        }
        crc = crc & 0xFFFF;
        
        // Convert to 2-byte array
        byte[] hashBytes = new byte[2];
        hashBytes[0] = (byte) ((crc >> 8) & 0xFF);
        hashBytes[1] = (byte) (crc & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.CRC16);
    }
    
    /**
     * Calculate AP hash
     */
    private static HashResult calculateAP(byte[] input) {
        long hash = 0xAAAAAAAA;
        for (int i = 0; i < input.length; i++) {
            if ((i & 1) == 0) {
                hash ^= ((hash << 7) ^ (input[i] & 0xFF) ^ (hash >> 3));
            } else {
                hash ^= (~((hash << 11) ^ (input[i] & 0xFF) ^ (hash >> 5)));
            }
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.AP);
    }
    
    /**
     * Calculate BKDR hash
     */
    private static HashResult calculateBKDR(byte[] input) {
        long seed = 131; // 31 131 1313 13131 131313 etc..
        long hash = 0;
        for (byte b : input) {
            hash = (hash * seed) + (b & 0xFF);
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.BKDR);
    }
    
    /**
     * Calculate DEK hash
     */
    private static HashResult calculateDEK(byte[] input) {
        long hash = input.length;
        for (byte b : input) {
            hash = ((hash << 5) ^ (hash >> 27)) ^ (b & 0xFF);
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.DEK);
    }
    
    /**
     * Calculate DJB hash
     */
    private static HashResult calculateDJB(byte[] input) {
        long hash = 5381;
        for (byte b : input) {
            hash = ((hash << 5) + hash) + (b & 0xFF);
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.DJB);
    }
    
    /**
     * Calculate ELF hash
     */
    private static HashResult calculateELF(byte[] input) {
        long hash = 0;
        long x = 0;
        for (byte b : input) {
            hash = (hash << 4) + (b & 0xFF);
            if ((x = hash & 0xF0000000L) != 0) {
                hash ^= (x >> 24);
            }
            hash &= ~x;
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.ELF);
    }
    
    /**
     * Calculate FNV1 hash
     */
    private static HashResult calculateFNV1(byte[] input) {
        final long FNV_OFFSET_BASIS = 0x811c9dc5L;
        final long FNV_PRIME = 0x01000193L;
        
        long hash = FNV_OFFSET_BASIS;
        for (byte b : input) {
            hash *= FNV_PRIME;
            hash ^= (b & 0xFF);
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.FNV1);
    }
    
    /**
     * Calculate FNV1a hash
     */
    private static HashResult calculateFNV1A(byte[] input) {
        final long FNV_OFFSET_BASIS = 0x811c9dc5L;
        final long FNV_PRIME = 0x01000193L;
        
        long hash = FNV_OFFSET_BASIS;
        for (byte b : input) {
            hash ^= (b & 0xFF);
            hash *= FNV_PRIME;
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.FNV1A);
    }
    
    /**
     * Calculate JS hash
     */
    private static HashResult calculateJS(byte[] input) {
        long hash = 1315423911;
        for (byte b : input) {
            hash ^= ((hash << 5) + (b & 0xFF) + (hash >> 2));
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.JS);
    }
    
    /**
     * Calculate PJW hash
     */
    private static HashResult calculatePJW(byte[] input) {
        long hash = 0;
        long test = 0;
        for (byte b : input) {
            hash = (hash << 4) + (b & 0xFF);
            if ((test = hash & 0xF0000000L) != 0) {
                hash = ((hash ^ (test >> 24)) & (~test));
            }
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.PJW);
    }
    
    /**
     * Calculate RS hash
     */
    private static HashResult calculateRS(byte[] input) {
        long b = 378551;
        long a = 63689;
        long hash = 0;
        for (byte b1 : input) {
            hash = hash * a + (b1 & 0xFF);
            a = a * b;
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.RS);
    }
    
    /**
     * Calculate SDBM hash
     */
    private static HashResult calculateSDBM(byte[] input) {
        long hash = 0;
        for (byte b : input) {
            hash = (b & 0xFF) + (hash << 6) + (hash << 16) - hash;
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.SDBM);
    }
    
    /**
     * Calculate ShiftAndXOR hash
     */
    private static HashResult calculateShiftAndXOR(byte[] input) {
        long hash = 0;
        for (byte b : input) {
            hash ^= (b & 0xFF) + (hash << 5) + (hash >> 2);
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.SHIFTANDXOR);
    }
    
    /**
     * Calculate SuperFast hash
     */
    private static HashResult calculateSuperFast(byte[] input) {
        long hash = input.length;
        for (int i = 0; i < input.length; i++) {
            hash += (input[i] & 0xFF);
            hash ^= hash << 10;
            hash ^= hash >> 6;
        }
        hash ^= hash << 3;
        hash ^= hash >> 11;
        hash ^= hash << 15;
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.SUPERFAST);
    }
    
    /**
     * Calculate Tiger hash
     */
    private static HashResult calculateTiger(byte[] input) {
        // Simplified Tiger hash implementation (not a full implementation)
        // For a production implementation, a proper Tiger hash library should be used
        long hash = 0x0123456789ABCDEF0L;
        for (int i = 0; i < input.length; i++) {
            hash ^= ((long) (input[i] & 0xFF)) << ((i % 8) * 8);
            hash = ((hash << 1) | (hash >>> 63)) ^ (hash & 0xFFFFFFFFFFFFFFL);
        }
        
        // Convert to 24-byte array (192 bits)
        byte[] hashBytes = new byte[24];
        for (int i = 0; i < 24; i++) {
            hashBytes[i] = (byte) ((hash >> (i * 8)) & 0xFF);
        }
        
        return new HashResult(hashBytes, HashAlgorithm.TIGER);
    }
    
    /**
     * Calculate Blake2B hash
     */
    private static HashResult calculateBlake2B(byte[] input) {
        // Simplified Blake2B implementation (not a full implementation)
        // For a production implementation, a proper Blake2B library should be used
        long hash = 0x6a09e667f3bcc908L;
        for (int i = 0; i < input.length; i++) {
            hash ^= ((long) (input[i] & 0xFF)) << ((i % 8) * 8);
            hash = ((hash << 1) | (hash >>> 63)) ^ (hash & 0x7FFFFFFFFFFFFFFFL);
        }
        
        // Convert to 64-byte array (512 bits)
        byte[] hashBytes = new byte[64];
        for (int i = 0; i < 64; i++) {
            hashBytes[i] = (byte) ((hash >> (i * 8)) & 0xFF);
        }
        
        return new HashResult(hashBytes, HashAlgorithm.BLAKE2B);
    }
    
    /**
     * Calculate Blake2S hash
     */
    private static HashResult calculateBlake2S(byte[] input) {
        // Simplified Blake2S implementation (not a full implementation)
        // For a production implementation, a proper Blake2S library should be used
        long hash = 0x6a09e667L;
        for (int i = 0; i < input.length; i++) {
            hash ^= (input[i] & 0xFF) << ((i % 4) * 8);
            hash = ((hash << 1) | (hash >>> 31)) ^ (hash & 0x7FFFFFFFL);
        }
        
        // Convert to 32-byte array (256 bits)
        byte[] hashBytes = new byte[32];
        for (int i = 0; i < 32; i++) {
            hashBytes[i] = (byte) ((hash >> (i * 8)) & 0xFF);
        }
        
        return new HashResult(hashBytes, HashAlgorithm.BLAKE2S);
    }
    
    /**
     * Calculate Bernstein hash
     */
    private static HashResult calculateBernstein(byte[] input) {
        long hash = 5381;
        for (byte b : input) {
            hash = ((hash << 5) + hash) + (b & 0xFF);
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.BERNSTEIN);
    }
    
    /**
     * Calculate Bernstein1 hash
     */
    private static HashResult calculateBernstein1(byte[] input) {
        long hash = 5381;
        for (byte b : input) {
            hash = 33 * hash + (b & 0xFF);
        }
        
        // Convert to 4-byte array
        byte[] hashBytes = new byte[4];
        hashBytes[0] = (byte) ((hash >> 24) & 0xFF);
        hashBytes[1] = (byte) ((hash >> 16) & 0xFF);
        hashBytes[2] = (byte) ((hash >> 8) & 0xFF);
        hashBytes[3] = (byte) (hash & 0xFF);
        
        return new HashResult(hashBytes, HashAlgorithm.BERNSTEIN1);
    }
}
