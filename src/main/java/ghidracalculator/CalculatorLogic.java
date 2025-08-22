package ghidracalculator;

import java.math.BigInteger;

/**
 * Calculator Logic class to handle core arithmetic operations and state management
 */
public class CalculatorLogic {
    private CalculatorProvider provider;
    
    // Calculator state
    protected BigInteger currentValue = BigInteger.ZERO;
    private BigInteger previousValue = BigInteger.ZERO;
    private String currentOperation = "";
    protected boolean newNumber = true;
    private String inputMode = "HEX"; // Default to hex
    
    // Marking functionality
    private BigInteger markedValue = null;
    private long markedAddress = -1;
    
    public CalculatorLogic(CalculatorProvider provider) {
        this.provider = provider;
    }
    
    public BigInteger getCurrentValue() {
        return currentValue;
    }
    
    public void setCurrentValue(BigInteger value) {
        this.currentValue = value;
    }
    
    public String getInputMode() {
        return inputMode;
    }
    
    public void setInputMode(String mode) {
        this.inputMode = mode;
    }
    
    public BigInteger getPreviousValue() {
        return previousValue;
    }
    
    public void setPreviousValue(BigInteger value) {
        this.previousValue = value;
    }
    
    public String getCurrentOperation() {
        return currentOperation;
    }
    
    public void setCurrentOperation(String operation) {
        this.currentOperation = operation;
    }
    
    public boolean isNewNumber() {
        return newNumber;
    }
    
    public void setNewNumber(boolean newNumber) {
        this.newNumber = newNumber;
    }
    
    public BigInteger getMarkedValue() {
        return markedValue;
    }
    
    public void setMarkedValue(BigInteger value) {
        this.markedValue = value;
    }
    
    public long getMarkedAddress() {
        return markedAddress;
    }
    
    public void setMarkedAddress(long address) {
        this.markedAddress = address;
    }
    
    /**
     * Set the current operation
     */
    public void setOperation(String operation) {
        if (!currentOperation.isEmpty()) {
            provider.performEquals();
        }
        previousValue = currentValue;
        currentOperation = operation;
        newNumber = true;
    }
    
    /**
     * Perform the equals operation
     */
    public BigInteger performEquals() {
        if (currentOperation.isEmpty()) {
            String operationString = "";
            provider.addToHistory(currentValue, operationString);
            return currentValue;
        }
        
        BigInteger result = BigInteger.ZERO;
        String operationString = String.format("%s %s %s",
            previousValue.toString(16).toUpperCase(),
            currentOperation,
            currentValue.toString(16).toUpperCase());
        
        switch (currentOperation) {
            case "+":
                result = previousValue.add(currentValue);
                break;
            case "-":
                result = previousValue.subtract(currentValue);
                break;
            case "\u00D7":
                result = previousValue.multiply(currentValue);
                break;
            case "\u00F7":
                if (!currentValue.equals(BigInteger.ZERO)) {
                    result = previousValue.divide(currentValue);
                } else {
                    result = BigInteger.ZERO; // Division by zero
                    operationString += " (Division by zero)";
                }
                break;
            case "AND":
                result = previousValue.and(currentValue);
                break;
            case "OR":
                result = previousValue.or(currentValue);
                break;
            case "XOR":
                result = previousValue.xor(currentValue);
                break;
            case "NOR":
                long mask = 0xFFFFFFFFL;  //Mask to 32 bits
                result = BigInteger.valueOf((~previousValue.or(currentValue).longValue()) & mask);
                break;
            case "MOD":
                result = previousValue.mod(currentValue);
                break;
            case "RoR": // 32-bit circular rotation
                int rval = previousValue.intValue();
                result = BigInteger.valueOf(Integer.rotateRight(rval, currentValue.intValue()));
                break;
            case "RoL":
                int lval = previousValue.intValue();
                result = BigInteger.valueOf(Integer.rotateLeft(lval, currentValue.intValue()));
                break;
            case "<<":
                result = previousValue.shiftLeft(currentValue.intValue());
                break;
            case ">>":
                result = previousValue.shiftRight(currentValue.intValue());
                break;
        }
        
        currentValue = result;
        currentOperation = "";
        newNumber = true;
        
        // Add to history
        provider.addToHistory(result, operationString);
        return result;
    }
    
    /**
     * Flip sign of current value
     */
    public void flipSign() {
        currentValue = currentValue.negate();
    }
    
    /**
     * Clear the calculator
     */
    public void clearCalculator() {
        currentValue = BigInteger.ZERO;
        previousValue = BigInteger.ZERO;
        currentOperation = "";
        newNumber = true;
    }
    
    /**
     * Increment the current value by the specified amount
     */
    public void increment(BigInteger amount) {
        BigInteger previousValue = currentValue;
        currentValue = currentValue.add(amount);
        newNumber = true;
        
        String operationString = String.format("%s + %s",
            previousValue.toString(16).toUpperCase(),
            amount.toString(16).toUpperCase());
        provider.addToHistory(currentValue, operationString);
    }
    
    /**
     * Perform bitwise NOT operation
     */
    public void bitwiseNot() {
        BigInteger previousValue = currentValue;
        // For display purposes, limit to 32-bit NOT
        long mask = 0xFFFFFFFFL;
        currentValue = BigInteger.valueOf((~currentValue.longValue()) & mask);
        newNumber = true;
        
        String operationString = String.format("NOT %s",
            previousValue.toString(16).toUpperCase());
        provider.addToHistory(currentValue, operationString);
    }
    
    /**
     * Mark the current value for later recall
     */
    public void markCurrentValue() {
        markedValue = currentValue;
    }
    
    /**
     * Recall the marked value
     */
    public void recallMarkedValue() {
        if (markedValue != null) {
            currentValue = markedValue;
            newNumber = true;
        }
    }
    
    /**
     * Clear marked values and addresses
     */
    public void clearMark() {
        markedValue = null;
        markedAddress = -1;
    }
    
    /**
     * Mark a value for comparison operations
     */
    public void markValueForComparison(BigInteger value) {
        markedValue = value;
    }
    
    /**
     * Check if a value is marked for comparison
     */
    public boolean hasMarkedValue() {
        return markedValue != null;
    }
    
    /**
     * Perform operation between current value and marked value
     */
    public BigInteger performMarkedValueOperation(BigInteger currentMemValue, String operation) {
        if (markedValue != null) {
            BigInteger result = BigInteger.ZERO;
            String operationSymbol = "";
            
            switch (operation) {
                case "add":
                    result = markedValue.add(currentMemValue);
                    operationSymbol = "+";
                    break;
                case "subtract":
                    result = markedValue.subtract(currentMemValue);
                    operationSymbol = "-";
                    break;
                case "xor":
                    result = markedValue.xor(currentMemValue);
                    operationSymbol = "XOR";
                    break;
            }
            
            // Show result in calculator
            currentValue = result;
            newNumber = true;
            
            // Add to history
            String operationString = String.format("%s %s %s",
                markedValue.toString(16).toUpperCase(),
                operationSymbol,
                currentMemValue.toString(16).toUpperCase());
            provider.addToHistory(currentValue, operationString);
            
            return result;
        }
        return currentValue;
    }
    
    /**
     * Calculate distance from current address to marked address
     */
    public void calculateDistanceToMarked(long currentAddress) {
        if (markedAddress != -1) {
            long distance = Math.abs(currentAddress - markedAddress);
            BigInteger distanceValue = BigInteger.valueOf(distance);
            
            // Show result in calculator and display dialog
            currentValue = distanceValue;
            newNumber = true;
            
            // Add to history
            String operationString = String.format("%s - %s",
                BigInteger.valueOf(currentAddress).toString(16).toUpperCase(),
                BigInteger.valueOf(markedAddress).toString(16).toUpperCase());
            provider.addToHistory(currentValue, operationString);
        }
    }
    
    /**
     * Check if an address is marked
     */
    public boolean hasMarkedAddress() {
        return markedAddress != -1;
    }
}