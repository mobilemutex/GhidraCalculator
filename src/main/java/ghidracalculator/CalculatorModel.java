package ghidracalculator;

import java.math.BigInteger;
import java.util.EventObject;
import java.util.EventListener;
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
    
    // Marking functionality
    private BigInteger markedValue = null;
    private long markedAddress = -1;
    
    // Event listener list for observer pattern
    private ListenerSet<CalculatorModelListener> listenerList = new ListenerSet<>(CalculatorModelListener.class, true);
    
    public CalculatorModel() {
        // Default constructor
    }
    
    // Getters and setters for all state variables
    public BigInteger getCurrentValue() {
        return currentValue;
    }
    
    public void setCurrentValue(BigInteger value) {
        this.currentValue = value;
        fireStateChanged();
    }
    
    public BigInteger getPreviousValue() {
        return previousValue;
    }
    
    public void setPreviousValue(BigInteger value) {
        this.previousValue = value;
        fireStateChanged();
    }
    
    public String getCurrentOperation() {
        return currentOperation;
    }
    
    public void setCurrentOperation(String operation) {
        this.currentOperation = operation;
        fireStateChanged();
    }
    
    public boolean isNewNumber() {
        return newNumber;
    }
    
    public void setNewNumber(boolean newNumber) {
        this.newNumber = newNumber;
        fireStateChanged();
    }
    
    public String getInputMode() {
        return inputMode;
    }
    
    public void setInputMode(String mode) {
        this.inputMode = mode;
        fireStateChanged();
    }
    
    public BigInteger getMarkedValue() {
        return markedValue;
    }
    
    public void setMarkedValue(BigInteger value) {
        this.markedValue = value;
        fireStateChanged();
    }
    
    public long getMarkedAddress() {
        return markedAddress;
    }
    
    public void setMarkedAddress(long address) {
        this.markedAddress = address;
        fireStateChanged();
    }
    
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
    
    // Observer pattern implementation
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