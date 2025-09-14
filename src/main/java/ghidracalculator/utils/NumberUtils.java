package ghidracalculator.utils;

import java.math.BigInteger;

public class NumberUtils {

    /**
     * Enumeration for endianness types
     */
    public enum Endianness {
        LITTLE_ENDIAN,
        BIG_ENDIAN
    }

    /**
     * Convert a value from one endianness to another
     * @param value The value to convert
     * @param bitWidth The bit width (8, 16, 32, 64)
     * @param fromEndian Source endianness
     * @param toEndian Target endianness
     * @return The converted value
     */
    public static BigInteger convertEndianness(BigInteger value, int bitWidth, 
                                             Endianness fromEndian, Endianness toEndian) {
        if (fromEndian == toEndian) {
            return value;
        }
        
        // Mask the value to the specified bit width
        BigInteger mask = BigInteger.ONE.shiftLeft(bitWidth).subtract(BigInteger.ONE);
        value = value.and(mask);
        
        // Convert based on bit width
        switch (bitWidth) {
            case 8:
                return value; // 8-bit values are the same regardless of endianness
            case 16:
                return swapBytes16(value);
            case 32:
                return swapBytes32(value);
            case 64:
                return swapBytes64(value);
            default:
                throw new IllegalArgumentException("Unsupported bit width: " + bitWidth);
        }
    }
    
    /**
     * Swap bytes in a 16-bit value
     */
    private static BigInteger swapBytes16(BigInteger value) {
        int val = value.intValue();
        int swapped = ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
        return BigInteger.valueOf(swapped & 0xFFFF);
    }
    
    /**
     * Swap bytes in a 32-bit value
     */
    private static BigInteger swapBytes32(BigInteger value) {
        long val = value.longValue();
        long swapped = ((val & 0xFF) << 24) |
                      ((val & 0xFF00) << 8) |
                      ((val & 0xFF0000) >> 8) |
                      ((val & 0xFF000000L) >> 24);
        return BigInteger.valueOf(swapped & 0xFFFFFFFFL);
    }
    
    /**
     * Swap bytes in a 64-bit value
     */
    private static BigInteger swapBytes64(BigInteger value) {
        long val = value.longValue();
        long swapped = ((val & 0xFFL) << 56) |
                      ((val & 0xFF00L) << 40) |
                      ((val & 0xFF0000L) << 24) |
                      ((val & 0xFF000000L) << 8) |
                      ((val & 0xFF00000000L) >> 8) |
                      ((val & 0xFF0000000000L) >> 24) |
                      ((val & 0xFF000000000000L) >> 40) |
                      ((val & 0xFF00000000000000L) >> 56);
        return new BigInteger(Long.toUnsignedString(swapped));
    }
    
    /**
     * Perform sign extension on a value
     * @param value The value to sign extend
     * @param fromBits The current bit width of the value
     * @param toBits The target bit width
     * @return The sign-extended value
     */
    public static BigInteger signExtend(BigInteger value, int fromBits, int toBits) {
        if (fromBits >= toBits) {
            // Truncate to target bits
            BigInteger mask = BigInteger.ONE.shiftLeft(toBits).subtract(BigInteger.ONE);
            return value.and(mask);
        }
        
        // Check if the sign bit is set
        BigInteger signBit = BigInteger.ONE.shiftLeft(fromBits - 1);
        boolean isNegative = value.and(signBit).compareTo(BigInteger.ZERO) != 0;
        
        if (isNegative) {
            // Extend with 1s
            BigInteger mask = BigInteger.ONE.shiftLeft(toBits).subtract(BigInteger.ONE);
            BigInteger extensionMask = mask.xor(BigInteger.ONE.shiftLeft(fromBits).subtract(BigInteger.ONE));
            return value.or(extensionMask);
        } else {
            // Value is positive, no extension needed
            return value;
        }
    }
    
    /**
     * Convert a value to its 2's complement representation
     * @param value The value to convert
     * @param bitWidth The bit width for the operation
     * @return The 2's complement value
     */
    public static BigInteger twosComplement(BigInteger value, int bitWidth) {
        // Create mask for the bit width
        BigInteger mask = BigInteger.ONE.shiftLeft(bitWidth).subtract(BigInteger.ONE);
        
        // Invert all bits and add 1
        BigInteger inverted = value.not().and(mask);
        return inverted.add(BigInteger.ONE).and(mask);
    }
    
    /**
     * Check if a value is negative in 2's complement representation
     * @param value The value to check
     * @param bitWidth The bit width
     * @return true if the value is negative
     */
    public static boolean isNegativeTwosComplement(BigInteger value, int bitWidth) {
        BigInteger signBit = BigInteger.ONE.shiftLeft(bitWidth - 1);
        return value.and(signBit).compareTo(BigInteger.ZERO) != 0;
    }
    
    /**
     * Convert from 2's complement to signed decimal
     * @param value The 2's complement value
     * @param bitWidth The bit width
     * @return The signed decimal value
     */
    public static BigInteger fromTwosComplement(BigInteger value, int bitWidth) {
        if (isNegativeTwosComplement(value, bitWidth)) {
            // Convert back from 2's complement
            BigInteger mask = BigInteger.ONE.shiftLeft(bitWidth).subtract(BigInteger.ONE);
            BigInteger inverted = value.subtract(BigInteger.ONE).not().and(mask);
            return inverted.negate();
        }
        return value;
    }
    
    /**
     * Convert a signed value to 2's complement representation
     * @param value The signed value
     * @param bitWidth The bit width
     * @return The 2's complement representation
     */
    public static BigInteger toTwosComplement(BigInteger value, int bitWidth) {
        if (value.compareTo(BigInteger.ZERO) < 0) {
            // Negative value - convert to 2's complement
            BigInteger mask = BigInteger.ONE.shiftLeft(bitWidth).subtract(BigInteger.ONE);
            BigInteger positive = value.negate();
            BigInteger inverted = positive.subtract(BigInteger.ONE).not().and(mask);
            return inverted.add(BigInteger.ONE).and(mask);
        }
        return value;
    }
    
}
