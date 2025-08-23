package ghidracalculator.util;

import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.KeyEvent;
import java.math.BigInteger;

import javax.swing.JOptionPane;
import javax.swing.Timer;

import generic.theme.GThemeDefaults;
import ghidracalculator.CalculatorLogic;
import ghidracalculator.CalculatorProvider;

/**
 * Input Handler class to handle all input-related functionality
 */
public class InputHandler {
    private CalculatorProvider provider;
    private CalculatorLogic calculatorLogic;
    
    public InputHandler(CalculatorProvider provider, CalculatorLogic calculatorLogic) {
        this.provider = provider;
        this.calculatorLogic = calculatorLogic;
    }
    
    /**
     * Handle keyboard input for calculator operations
     */
    public void handleKeyPress(KeyEvent e) {
        int keyCode = e.getKeyCode();
        char keyChar = e.getKeyChar();
        
        // Handle special keys
        switch (keyCode) {
            case KeyEvent.VK_ENTER:
                parseDisplayInput();
                e.consume();
                return;
            case KeyEvent.VK_ESCAPE:
                calculatorLogic.clearCalculator();
                e.consume();
                return;
            case KeyEvent.VK_BACK_SPACE:
            case KeyEvent.VK_DELETE:
                // Allow normal backspace/delete behavior
                return;
        }
        
        // Handle operation keys
        if (keyChar == '+') {
            calculatorLogic.setOperation("+");
            e.consume();
        } else if (keyChar == '-') {
            calculatorLogic.setOperation("-");
            e.consume();
        } else if (keyChar == '*') {
            calculatorLogic.setOperation("*");
            e.consume();
        } else if (keyChar == '/') {
            calculatorLogic.setOperation("/");
            e.consume();
        } else if (keyChar == '=') {
            calculatorLogic.performEquals();
            e.consume();
        } else if (keyChar == '&') {
            calculatorLogic.setOperation("AND");
            e.consume();
        } else if (keyChar == '|') {
            calculatorLogic.setOperation("OR");
            e.consume();
        } else if (keyChar == '^') {
            calculatorLogic.setOperation("XOR");
            e.consume();
        } else if (keyChar == '~') {
            calculatorLogic.bitwiseNot();
            e.consume();
        }
        // For other characters, let the text field handle them normally (This is kind of broken and clunky)
    }
    
    /**
     * Parse the input from the display field and update the calculator value
     */
    public void parseDisplayInput() {
        String input = provider.getDisplayField().getText().trim();
        if (input.isEmpty()) {
            return;
        }

        try {
            BigInteger value = provider.parseInputValue(input);
            provider.getCalculatorLogic().setCurrentValue(value);
            provider.getCalculatorLogic().setNewNumber(true);
            provider.getUI().updateDisplay();
        } catch (NumberFormatException e) {
            // Invalid input, show error briefly
            String originalText = provider.getDisplayField().getText();
            provider.getDisplayField().setText("ERROR");
            provider.getDisplayField().setBackground(GThemeDefaults.Colors.Palette.PINK);
            
            // Reset after 1 second
            Timer timer = new Timer(1000, evt -> {
                provider.getDisplayField().setText(originalText);
                provider.getDisplayField().setBackground(GThemeDefaults.Colors.BACKGROUND);
            });
            timer.setRepeats(false);
            timer.start();
        }
    }
    
    /**
     * Copy current value to clipboard
     */
    public void copyValueToClipboard() {
        try {
            String value = provider.getDisplayField().getText();
            StringSelection selection = new StringSelection(value);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            
            // Show brief feedback
            provider.getDisplayField().setToolTipText("Value copied to clipboard: " + value);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(provider.getComponent(), 
                "Error copying to clipboard: " + ex.getMessage(), 
                "Copy Error", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * Paste value from clipboard
     */
    public void pasteValueFromClipboard() {
        try {
            String clipboardText = (String) Toolkit.getDefaultToolkit()
                .getSystemClipboard().getData(DataFlavor.stringFlavor);
            
            if (clipboardText != null && !clipboardText.trim().isEmpty()) {
                provider.getDisplayField().setText(clipboardText.trim());
                provider.parseInputValue(clipboardText.trim());
                parseDisplayInput();
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(provider.getComponent(), 
                "Error pasting from clipboard: " + ex.getMessage(), 
                "Paste Error", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
}