package ghidracalculator;

import java.math.BigInteger;

import ghidra.app.services.ConsoleService;

/**
 * Calculator Logic class to handle core arithmetic operations and state management
 */
public class CalculatorLogic {
    private CalculatorProvider provider;
    private ConsoleService consoleService;
    private CalculatorModel model;
    
    public CalculatorLogic(CalculatorProvider provider, ConsoleService consoleService) {
        this.provider = provider;
        this.consoleService = consoleService;
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
     */
    public void setOperation(String operation) {
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
        
        switch (model.getCurrentOperation()) {
            case "+":
                result = model.getPreviousValue().add(model.getCurrentValue());
                break;
            case "-":
                result = model.getPreviousValue().subtract(model.getCurrentValue());
                break;
            case "\u00D7":
                result = model.getPreviousValue().multiply(model.getCurrentValue());
                break;
            case "\u00F7":
                if (!model.getCurrentValue().equals(BigInteger.ZERO)) {
                    result = model.getPreviousValue().divide(model.getCurrentValue());
                } else {
                    result = BigInteger.ZERO; // Division by zero
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
                long mask = 0xFFFFFFFFL;  //Mask to 32 bits
                result = BigInteger.valueOf((~model.getPreviousValue().or(model.getCurrentValue()).longValue()) & mask);
                break;
            case "MOD":
                result = model.getPreviousValue().mod(model.getCurrentValue());
                break;
            case "RoR": // 32-bit circular rotation
                int rval = model.getPreviousValue().intValue();
                result = BigInteger.valueOf(Integer.rotateRight(rval, model.getCurrentValue().intValue()));
                break;
            case "RoL":
                int lval = model.getPreviousValue().intValue();
                result = BigInteger.valueOf(Integer.rotateLeft(lval, model.getCurrentValue().intValue()));
                break;
            case "<<":
                result = model.getPreviousValue().shiftLeft(model.getCurrentValue().intValue());
                break;
            case ">>":
                result = model.getPreviousValue().shiftRight(model.getCurrentValue().intValue());
                break;
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
	 */
	public void performOperation(String op) {
		if (op != null) {
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
			}
		}
		return;
	}

    /**
	 * Append a digit to the current number
	 */
	public void appendDigit(String digit) {
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
					}
					break;
				case "BIN":
					if (digit.matches("[01]")) {
						digitValue = Integer.parseInt(digit, 2);
						setCurrentValue(getCurrentValue().multiply(BigInteger.valueOf(2)).add(BigInteger.valueOf(digitValue)));
					}
					break;
				case "OCT":
					if (digit.matches("[0-7]")) {
						digitValue = Integer.parseInt(digit, 8);
						setCurrentValue(getCurrentValue().multiply(BigInteger.valueOf(8)).add(BigInteger.valueOf(digitValue)));
					}
					break;
			}
		} catch (NumberFormatException e) {
			// Invalid digit for current mode, ignore
			return;
		}
	}

    /**
	 * Add a value to the calculator
	 */
	public void addValue(BigInteger value) {
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
     */
    public void increment(BigInteger amount) {
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
     */
    public void markValueForComparison(BigInteger value) {
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
     */
    public BigInteger performMarkedValueOperation(BigInteger currentMemValue, String operation) {
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
                "Marked Value Operation:\n" +
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
            consoleService.println(message);
            
            return result;
        }
        return model.getCurrentValue();
    }
    
    /**
     * Calculate distance from current address to marked address
     */
    public void calculateDistanceToMarked(long currentAddress) {
        if (model.getMarkedAddress() != -1) {
            long distance = Math.abs(currentAddress - model.getMarkedAddress());
            BigInteger distanceValue = BigInteger.valueOf(distance);
            
            // Show result in calculator and display dialog
            model.setCurrentValue(distanceValue);
            model.setNewNumber(true);
            
            // Add to history
            String operationString = String.format("%s - %s",
                BigInteger.valueOf(currentAddress).toString(16).toUpperCase(),
                BigInteger.valueOf(model.getMarkedAddress()).toString(16).toUpperCase());
            provider.addToHistory(model.getCurrentValue(), operationString);
        }
    }
    
    /**
     * Check if an address is marked
     */
    public boolean hasMarkedAddress() {
        return model.getMarkedAddress() != -1;
    }
}