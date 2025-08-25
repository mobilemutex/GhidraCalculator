package ghidracalculator;

import java.math.BigInteger;

import ghidra.app.services.ConsoleService;

/**
 * Calculator Logic class to handle core arithmetic operations and state management
 */
public class CalculatorLogic {
    private CalculatorProvider provider;
    private CalculatorModel model;
    
    /**
     * Constructor
     * @param provider The calculator provider
     * @throws IllegalArgumentException if provider is null
     */
    public CalculatorLogic(CalculatorProvider provider) {
        if (provider == null) {
            throw new IllegalArgumentException("CalculatorProvider cannot be null");
        }
        this.provider = provider;
        this.model = new CalculatorModel();
    }
    
    public CalculatorModel getModel() {
        return model;
    }
    
    public BigInteger getCurrentValue() {
        return model.getCurrentValue();
    }
    
    public void setCurrentValue(BigInteger value) {
        model.setCurrentValue(value);
    }
    
    public String getInputMode() {
        return model.getInputMode();
    }
    
    public void setInputMode(String mode) {
        model.setInputMode(mode);
    }
    
    public BigInteger getPreviousValue() {
        return model.getPreviousValue();
    }
    
    public void setPreviousValue(BigInteger value) {
        model.setPreviousValue(value);
    }
    
    public String getCurrentOperation() {
        return model.getCurrentOperation();
    }
    
    public void setCurrentOperation(String operation) {
        model.setCurrentOperation(operation);
    }
    
    public boolean isNewNumber() {
        return model.isNewNumber();
    }
    
    public void setNewNumber(boolean newNumber) {
        model.setNewNumber(newNumber);
    }
    
    public BigInteger getMarkedValue() {
        return model.getMarkedValue();
    }
    
    public void setMarkedValue(BigInteger value) {
        model.setMarkedValue(value);
    }
    
    public long getMarkedAddress() {
        return model.getMarkedAddress();
    }
    
    public void setMarkedAddress(long address) {
        model.setMarkedAddress(address);
    }
    
    /**
     * Set the current operation
     * @param operation the operation to set
     * @throws IllegalArgumentException if operation is null
     */
    public void setOperation(String operation) {
        if (operation == null) {
            model.notifyError("Operation cannot be null");
            return;
        }
        model.setPreviousValue(model.getCurrentValue());
        model.setCurrentOperation(operation);
        model.setNewNumber(true);
    }
    
    /**
     * Perform the equals operation
     */
    public BigInteger performEquals() {
        if (model.getCurrentOperation().isEmpty()) {
            String operationString = "";
            provider.addToHistory(model.getCurrentValue(), operationString);
            return model.getCurrentValue();
        }
        
        BigInteger result = BigInteger.ZERO;
        String operationString = String.format("%s %s %s",
            model.getPreviousValue().toString(16).toUpperCase(),
            model.getCurrentOperation(),
            model.getCurrentValue().toString(16).toUpperCase());
        
        try {
            switch (model.getCurrentOperation()) {
                case "+":
                    result = model.getPreviousValue().add(model.getCurrentValue());
                    break;
                case "-":
                    result = model.getPreviousValue().subtract(model.getCurrentValue());
                    break;
                case "\u00D7":
                    // Check for potential overflow in multiplication
                    if (!model.getPreviousValue().equals(BigInteger.ZERO) &&
                        !model.getCurrentValue().equals(BigInteger.ZERO)) {
                        // Estimate the size of the result to prevent excessive memory usage
                        int bitLength = model.getPreviousValue().bitLength() + model.getCurrentValue().bitLength();
                        if (bitLength > 100000) { // Arbitrary limit to prevent excessive memory usage
                            model.notifyError("Multiplication result would be too large");
                            operationString += " (Result too large)";
                            break;
                        }
                    }
                    result = model.getPreviousValue().multiply(model.getCurrentValue());
                    break;
                case "\u00F7":
                    if (!model.getCurrentValue().equals(BigInteger.ZERO)) {
                        result = model.getPreviousValue().divide(model.getCurrentValue());
                    } else {
                        model.notifyError("Division by zero");
                        operationString += " (Division by zero)";
                    }
                    break;
                case "AND":
                    result = model.getPreviousValue().and(model.getCurrentValue());
                    break;
                case "OR":
                    result = model.getPreviousValue().or(model.getCurrentValue());
                    break;
                case "XOR":
                    result = model.getPreviousValue().xor(model.getCurrentValue());
                    break;
                case "NOR":
                    // Check for excessively large values that could cause issues with the 32-bit mask
                    if (model.getPreviousValue().bitLength() > 32 || model.getCurrentValue().bitLength() > 32) {
                        model.notifyError("NOR operation requires 32-bit values or smaller");
                        operationString += " (Value too large for NOR)";
                        break;
                    }
                    long mask = 0xFFFFFFFFL;  //Mask to 32 bits
                    result = BigInteger.valueOf((~model.getPreviousValue().or(model.getCurrentValue()).longValue()) & mask);
                    break;
                case "MOD":
                    if (model.getCurrentValue().compareTo(BigInteger.ZERO) <= 0) {
                        model.notifyError("Modulus must be positive");
                        operationString += " (Invalid modulus)";
                    } else {
                        result = model.getPreviousValue().mod(model.getCurrentValue().abs());
                    }
                    break;
                case "RoR": // 32-bit circular rotation
                    // Limit shift amount to prevent excessive rotation
                    if (model.getCurrentValue().compareTo(BigInteger.valueOf(32)) >= 0) {
                        model.notifyError("Rotation amount must be less than 32");
                        operationString += " (Rotation amount too large)";
                        break;
                    }
                    int rval = model.getPreviousValue().intValue();
                    result = BigInteger.valueOf(Integer.rotateRight(rval, model.getCurrentValue().intValue()));
                    break;
                case "RoL":
                    // Limit shift amount to prevent excessive rotation
                    if (model.getCurrentValue().compareTo(BigInteger.valueOf(32)) >= 0) {
                        model.notifyError("Rotation amount must be less than 32");
                        operationString += " (Rotation amount too large)";
                        break;
                    }
                    int lval = model.getPreviousValue().intValue();
                    result = BigInteger.valueOf(Integer.rotateLeft(lval, model.getCurrentValue().intValue()));
                    break;
                case "<<":
                    // Limit shift amount to prevent excessive shifting
                    if (model.getCurrentValue().compareTo(BigInteger.valueOf(10000)) >= 0) {
                        model.notifyError("Shift amount must be less than 10000");
                        operationString += " (Shift amount too large)";
                        break;
                    }
                    result = model.getPreviousValue().shiftLeft(model.getCurrentValue().intValue());
                    break;
                case ">>":
                    // Limit shift amount to prevent excessive shifting
                    if (model.getCurrentValue().compareTo(BigInteger.valueOf(10000)) >= 0) {
                        model.notifyError("Shift amount must be less than 10000");
                        operationString += " (Shift amount too large)";
                        break;
                    }
                    result = model.getPreviousValue().shiftRight(model.getCurrentValue().intValue());
                    break;
            }
        } catch (Exception e) {
            model.notifyError("Error performing operation: " + e.getMessage());
            operationString += " (Error: " + e.getMessage() + ")";
        }
        
        model.setCurrentValue(result);
        model.setCurrentOperation("");
        model.setNewNumber(true);
        
        // Add to history
        provider.addToHistory(result, operationString);

        return result;
    }

    /**
     * Perform operation for specified operator
     * @param op the operation to perform
     * @throws IllegalArgumentException if op is null
     */
 public void performOperation(String op) {
  if (op == null) {
   model.notifyError("Operation cannot be null");
   return;
  }
  
  switch (op) {
   case "\u00F7":
   case "\u00D7":
   case "-":
   case "+":
   case "AND":
   case "OR":
   case "XOR":
   case "NOR":
   case "MOD":
   case "RoR":
   case "RoL":
   case "<<":
   case ">>":
    setOperation(op);
    break;
   case "NOT":
    bitwiseNot();
    break;
   case "+/-":
    flipSign();
    break;
   case "=":
    performEquals();
    break;
   case "CLR":
    clearCalculator();
    break;
   default:
    model.notifyError("Unknown operation: " + op);
    break;
  }
  return;
 }

    /**
  * Append a digit to the current number
  * @param digit the digit to append
  * @throws IllegalArgumentException if digit is null or empty
  */
 public void appendDigit(String digit) {
  if (digit == null) {
   model.notifyError("Digit cannot be null");
   return;
  }
  
  if (digit.isEmpty()) {
   model.notifyError("Digit cannot be empty");
   return;
  }
  
  if (isNewNumber()) {
   setCurrentValue(BigInteger.ZERO);
   setNewNumber(false);
  }
  
  // Validate digit for current input mode
  int digitValue;
  try {
   switch (getInputMode()) {
    case "HEX":
    	digitValue = Integer.parseInt(digit, 16);
    	setCurrentValue(getCurrentValue().multiply(BigInteger.valueOf(16)).add(BigInteger.valueOf(digitValue)));
    	break;
    case "DEC":
    	if (digit.matches("[0-9]")) {
    		digitValue = Integer.parseInt(digit, 10);
    		setCurrentValue(getCurrentValue().multiply(BigInteger.valueOf(10)).add(BigInteger.valueOf(digitValue)));
    	} else {
    		model.notifyError("Invalid decimal digit: " + digit);
    	}
    	break;
    case "BIN":
    	if (digit.matches("[01]")) {
    		digitValue = Integer.parseInt(digit, 2);
    		setCurrentValue(getCurrentValue().multiply(BigInteger.valueOf(2)).add(BigInteger.valueOf(digitValue)));
    	} else {
    		model.notifyError("Invalid binary digit: " + digit);
    	}
    	break;
    case "OCT":
    	if (digit.matches("[0-7]")) {
    		digitValue = Integer.parseInt(digit, 8);
    		setCurrentValue(getCurrentValue().multiply(BigInteger.valueOf(8)).add(BigInteger.valueOf(digitValue)));
    	} else {
    		model.notifyError("Invalid octal digit: " + digit);
    	}
    	break;
    default:
    	model.notifyError("Invalid input mode: " + getInputMode());
    	break;
   }
  } catch (NumberFormatException e) {
   model.notifyError("Invalid digit for current mode: " + digit);
   return;
  }
 }

    /**
  * Add a value to the calculator
  * @param value the value to add
  * @throws IllegalArgumentException if value is null
  */
 public void addValue(BigInteger value) {
  if (value == null) {
   model.notifyError("Value cannot be null");
   return;
  }
  setCurrentValue(value);
  setNewNumber(true);
 }
    
    /**
     * Flip sign of current value
     */
    public void flipSign() {
        model.setCurrentValue(model.getCurrentValue().negate());
    }
    
    /**
     * Clear the calculator
     */
    public void clearCalculator() {
        model.setCurrentValue(BigInteger.ZERO);
        model.setPreviousValue(BigInteger.ZERO);
        model.setCurrentOperation("");
        model.setNewNumber(true);
    }
    
    /**
     * Increment the current value by the specified amount
     * @param amount the amount to increment by
     * @throws IllegalArgumentException if amount is null
     */
    public void increment(BigInteger amount) {
        if (amount == null) {
            model.notifyError("Amount cannot be null");
            return;
        }
        
        BigInteger previousValue = model.getCurrentValue();
        model.setCurrentValue(model.getCurrentValue().add(amount));
        model.setNewNumber(true);
        
        String operationString = String.format("%s + %s",
            previousValue.toString(16).toUpperCase(),
            amount.toString(16).toUpperCase());
        provider.addToHistory(model.getCurrentValue(), operationString);
    }
    
    /**
     * Perform bitwise NOT operation
     */
    public void bitwiseNot() {
        BigInteger previousValue = model.getCurrentValue();
        
        // Check if the value is too large for a 32-bit operation
        if (previousValue.bitLength() > 32) {
            model.notifyError("NOT operation requires 32-bit values or smaller");
            return;
        }
        
        // For display purposes, limit to 32-bit NOT
        long mask = 0xFFFFFFFFL;
        model.setCurrentValue(BigInteger.valueOf((~model.getCurrentValue().longValue()) & mask));
        model.setNewNumber(true);
        
        String operationString = String.format("NOT %s",
            previousValue.toString(16).toUpperCase());
        provider.addToHistory(model.getCurrentValue(), operationString);
    }
    
    /**
     * Mark the current value for later recall
     */
    public void markCurrentValue() {
        model.setMarkedValue(model.getCurrentValue());
    }
    
    /**
     * Recall the marked value
     */
    public void recallMarkedValue() {
        if (model.getMarkedValue() != null) {
            model.setCurrentValue(model.getMarkedValue());
            model.setNewNumber(true);
        }
    }
    
    /**
     * Clear marked values and addresses
     */
    public void clearMark() {
        model.setMarkedValue(null);
        model.setMarkedAddress(-1);
    }
    
    /**
     * Mark a value for comparison operations
     * @param value the value to mark
     * @throws IllegalArgumentException if value is null
     */
    public void markValueForComparison(BigInteger value) {
        if (value == null) {
            model.notifyError("Value cannot be null");
            return;
        }
        model.setMarkedValue(value);
    }
    
    /**
     * Check if a value is marked for comparison
     */
    public boolean hasMarkedValue() {
        return model.getMarkedValue() != null;
    }
    
    /**
     * Perform operation between current value and marked value
     * @param currentMemValue the current memory value
     * @param operation the operation to perform
     * @throws IllegalArgumentException if currentMemValue is null or operation is null/empty
     */
    public BigInteger performMarkedValueOperation(BigInteger currentMemValue, String operation) {
        if (currentMemValue == null) {
            model.notifyError("Current memory value cannot be null");
            return model.getCurrentValue();
        }
        
        if (operation == null) {
            model.notifyError("Operation cannot be null");
            return model.getCurrentValue();
        }
        
        if (operation.isEmpty()) {
            model.notifyError("Operation cannot be empty");
            return model.getCurrentValue();
        }
        
        if (model.getMarkedValue() != null) {
            BigInteger result = BigInteger.ZERO;
            String operationSymbol = "";
            
            switch (operation) {
                case "add":
                    result = model.getMarkedValue().add(currentMemValue);
                    operationSymbol = "+";
                    break;
                case "subtract":
                    result = model.getMarkedValue().subtract(currentMemValue);
                    operationSymbol = "-";
                    break;
                case "xor":
                    result = model.getMarkedValue().xor(currentMemValue);
                    operationSymbol = "XOR";
                    break;
                default:
                    model.notifyError("Unknown operation: " + operation);
                    return model.getCurrentValue();
            }
            
            // Show result in calculator
            model.setCurrentValue(result);
            model.setNewNumber(true);
            
            // Add to history
            String operationString = String.format("%s %s %s",
                model.getMarkedValue().toString(16).toUpperCase(),
                operationSymbol,
                currentMemValue.toString(16).toUpperCase());
            provider.addToHistory(model.getCurrentValue(), operationString);

            //Print results to console
            String message = String.format(
                "\nMarked Value Operation:\n" +
                "Marked: 0x%s\n" +
                "Current: 0x%s\n" +
                "Operation: %s\n" +
                "Result: 0x%s (%s)",
                model.getMarkedValue().toString(16).toUpperCase(),
                model.getCurrentValue().toString(16).toUpperCase(),
                operationSymbol,
                result.toString(16).toUpperCase(),
                result.toString(10)
            );

            ConsoleService consoleService = provider.plugin.getTool().getService(ConsoleService.class);
            consoleService.println(message);
            
            return result;
        }
        return model.getCurrentValue();
    }
    
    /**
     * Calculate distance from current address to marked address
     * @param currentAddress the current address
     * @throws IllegalArgumentException if currentAddress is negative
     */
    public void calculateDistanceToMarked(long currentAddress) {
        if (currentAddress < 0) {
            model.notifyError("Current address cannot be negative");
            return;
        }
        
        long markedAddress = model.getMarkedAddress();
        if (markedAddress != -1) {
            if (markedAddress < 0) {
                model.notifyError("Marked address cannot be negative");
                return;
            }
            
            long distance = Math.abs(currentAddress - markedAddress);
            BigInteger distanceValue = BigInteger.valueOf(distance);
            
            // Show result in calculator and display dialog
            model.setCurrentValue(distanceValue);
            model.setNewNumber(true);
            
            // Add to history
            String operationString = String.format("%s - %s",
                BigInteger.valueOf(currentAddress).toString(16).toUpperCase(),
                BigInteger.valueOf(markedAddress).toString(16).toUpperCase());
            provider.addToHistory(model.getCurrentValue(), operationString);

            // Show detailed information
            String message = String.format(
                "\nDistance Calculation:\n" +
                "From: 0x%X\n" +
                "To: 0x%X\n" +
                "Distance: 0x%X (%d bytes)",
                markedAddress, currentAddress, distance, distance);

            ConsoleService consoleService = provider.plugin.getTool().getService(ConsoleService.class);
   consoleService.println(message);
        }
    }
    
    /**
     * Check if an address is marked
     */
    public boolean hasMarkedAddress() {
        return model.getMarkedAddress() != -1;
    }
}