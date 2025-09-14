package ghidracalculator;

import java.math.BigInteger;
import java.util.EventObject;
import java.util.EventListener;
import java.util.Set;
import java.util.HashSet;
import ghidra.util.datastruct.ListenerSet;

/**
 * CalculatorModel encapsulates all the state for the calculator
 */
public class CalculatorModel {
    // Calculator state
    private BigInteger currentValue = BigInteger.ZERO;
    private BigInteger previousValue = BigInteger.ZERO;
    private String currentOperation = "";
    private boolean newNumber = true;
    private String inputMode = "HEX"; // Default to hex
    private int bitWidth = 32;
    
    // Validation constants
    private static final Set<String> VALID_INPUT_MODES = new HashSet<>();
    private static final Set<String> VALID_OPERATIONS = new HashSet<>();
    
    // Marking functionality
    private BigInteger markedValue = null;
    private long markedAddress = -1;
    
    // Event listener list for observer pattern
    private ListenerSet<CalculatorModelListener> listenerList = new ListenerSet<>(CalculatorModelListener.class, true);
    
    static {
        // Initialize valid input modes
        VALID_INPUT_MODES.add("HEX");
        VALID_INPUT_MODES.add("DEC");
        VALID_INPUT_MODES.add("BIN");
        VALID_INPUT_MODES.add("OCT");
        
        // Initialize valid operations
        VALID_OPERATIONS.add("+");
        VALID_OPERATIONS.add("-");
        VALID_OPERATIONS.add("\u00D7"); // ×
        VALID_OPERATIONS.add("\u00F7"); // ÷
        VALID_OPERATIONS.add("AND");
        VALID_OPERATIONS.add("OR");
        VALID_OPERATIONS.add("XOR");
        VALID_OPERATIONS.add("NOR");
        VALID_OPERATIONS.add("MOD");
        VALID_OPERATIONS.add("RoR");
        VALID_OPERATIONS.add("RoL");
        VALID_OPERATIONS.add("<<");
        VALID_OPERATIONS.add(">>");
    }
    
    public CalculatorModel() {
        // Default constructor
    }
    
    //================================================================================
    // Getters and setters for all state variables
    //================================================================================
    
    /**
     * Get the current value
     */
    public BigInteger getCurrentValue() {
        return currentValue;
    }
    
    /**
     * Set the current value
     * @param value the value to set (null will be treated as BigInteger.ZERO)
     */
    public void setCurrentValue(BigInteger value) {
        this.currentValue = (value != null) ? value : BigInteger.ZERO;
        fireStateChanged();
    }
    
    /**
     * Get the previous value
     */
    public BigInteger getPreviousValue() {
        return previousValue;
    }
    
    /**
     * Set the previous value
     * @param value the value to set (null will be treated as BigInteger.ZERO)
     */
    public void setPreviousValue(BigInteger value) {
        this.previousValue = (value != null) ? value : BigInteger.ZERO;
        fireStateChanged();
    }
    
    /**
     * Get the current operation string
     */
    public String getCurrentOperation() {
        return currentOperation;
    }
    
    /**
     * Set the current operation
     * @param operation the operation to set (must be one of the valid operations)
     * @throws IllegalArgumentException if operation is not a valid operation
     */
    public void setCurrentOperation(String operation) {
        if (operation == null) {
            notifyError("Operation cannot be null");
            return;
        }
        
        // Empty string is allowed (represents no operation)
        if (operation.isEmpty()) {
            this.currentOperation = operation;
            fireStateChanged();
            return;
        }
        
        if (!VALID_OPERATIONS.contains(operation)) {
            notifyError("Invalid operation: " + operation + ". Must be one of: " + VALID_OPERATIONS);
            return;
        }
        
        this.currentOperation = operation;
        fireStateChanged();
    }
    
    /**
     * Checks if the newNumber member is true or false
     */
    public boolean isNewNumber() {
        return newNumber;
    }
    
    /**
     * Set the newNumber member to true or false
     */
    public void setNewNumber(boolean newNumber) {
        this.newNumber = newNumber;
        fireStateChanged();
    }
    
    /**
     * Get the current input mode
     */
    public String getInputMode() {
        return inputMode;
    }

    /** 
     * Set bit width 
     */
    public void setBitWidth(int bitWidth) {
        this.bitWidth = bitWidth;
        fireStateChanged();
    }

    /** 
     * Get current bit width 
     */
    public int getBitWidth() {
        return bitWidth;
    }
    
    /**
     * Set the input mode
     * @param mode the input mode (must be one of "HEX", "DEC", "BIN", "OCT")
     * @throws IllegalArgumentException if mode is not a valid input mode
     */
    public void setInputMode(String mode) {
        if (mode == null) {
            notifyError("Input mode cannot be null");
            return;
        }
        
        if (!VALID_INPUT_MODES.contains(mode)) {
            notifyError("Invalid input mode: " + mode + ". Must be one of: " + VALID_INPUT_MODES);
            return;
        }
        
        this.inputMode = mode;
        fireStateChanged();
    }
    
    public BigInteger getMarkedValue() {
        return markedValue;
    }
    
    /**
     * Set the marked value
     * @param value the value to set (null is allowed and represents no marked value)
     */
    public void setMarkedValue(BigInteger value) {
        this.markedValue = value;
        fireStateChanged();
    }
    
    public long getMarkedAddress() {
        return markedAddress;
    }
    
    /**
     * Set the marked address
     * @param address the address to set (-1 represents no marked address)
     */
    public void setMarkedAddress(long address) {
        // Validate address range (allowing -1 for "no address" and reasonable positive values)
        if (address < -1) {
            notifyError("Invalid address: " + address + ". Address must be -1 (no address) or a positive value.");
            return;
        }
        
        this.markedAddress = address;
        fireStateChanged();
    }
    
    //================================================================================
    // Utility Methods
    //================================================================================

    /**
     * Reset the calculator state to initial values
     */
    public void reset() {
        currentValue = BigInteger.ZERO;
        previousValue = BigInteger.ZERO;
        currentOperation = "";
        newNumber = true;
        markedValue = null;
        markedAddress = -1;
        fireStateChanged();
    }
    
    /**
     * Check if a value is marked for comparison
     */
    public boolean hasMarkedValue() {
        return markedValue != null;
    }
    
    /**
     * Check if an address is marked
     */
    public boolean hasMarkedAddress() {
        return markedAddress != -1;
    }
    
    //================================================================================
    // Observer pattern/Listener methods
    //================================================================================
    
    public void addCalculatorModelListener(CalculatorModelListener listener) {
        listenerList.add(listener);
    }
    
    public void removeCalculatorModelListener(CalculatorModelListener listener) {
        listenerList.remove(listener);
    }
    
    protected void fireStateChanged() {
        CalculatorModelEvent event = new CalculatorModelEvent(this);
        listenerList.invoke().modelChanged(event);
    }
    
    //================================================================================
    // Interface classes and Event Listener Methods
    //================================================================================

    /**
     * Notify listeners of an error
     */
    public void notifyError(String errorMessage) {
        listenerList.invoke().modelError(new CalculatorModelErrorEvent(this, errorMessage));
    }
    
    /**
     * Listener interface for calculator model changes
     */
    public interface CalculatorModelListener extends EventListener {
        void modelChanged(CalculatorModelEvent event);
        void modelError(CalculatorModelErrorEvent event);
    }
    
    /**
     * Event class for calculator model changes
     */
    public static class CalculatorModelEvent extends EventObject {
        public CalculatorModelEvent(CalculatorModel source) {
            super(source);
        }
        
        public CalculatorModel getModel() {
            return (CalculatorModel) getSource();
        }
    }

    /**
     * Error event class for calculator model
     */
    public static class CalculatorModelErrorEvent extends EventObject {
        private String errorMessage;
        
        public CalculatorModelErrorEvent(CalculatorModel source, String errorMessage) {
            super(source);
            this.errorMessage = errorMessage;
        }
        
        public String getErrorMessage() {
            return errorMessage;
        }
    }
}