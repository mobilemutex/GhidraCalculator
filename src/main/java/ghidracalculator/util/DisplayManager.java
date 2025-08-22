package ghidracalculator.util;

import java.awt.*;
import java.math.BigInteger;
import javax.swing.*;

import generic.theme.GThemeDefaults;
import ghidracalculator.CalculatorProvider;

/**
 * Display Manager class to handle all display-related functionality
 */
public class DisplayManager {
    private CalculatorProvider provider;
    
    public DisplayManager(CalculatorProvider provider) {
        this.provider = provider;
    }
    
    /**
     * Update the display with current value in all number bases
     */
    public void updateDisplay() {
        // Update main display field based on input mode
        String displayText;
        String sign;
        BigInteger currentValue = provider.getCalculatorLogic().getCurrentValue();

        if (currentValue.signum() == -1) {
            sign = "-";
        } else {
            sign = "";
        }

        switch (provider.getCalculatorLogic().getInputMode()) {
            case "HEX":
                displayText = sign + "0x" + currentValue.abs().toString(16).toUpperCase();
                break;
            case "DEC":
                displayText = currentValue.toString(10);
                break;
            case "BIN":
                displayText = sign + "0b" + currentValue.abs().toString(2);
                break;
            case "OCT":
                displayText = sign + "0" + currentValue.abs().toString(8);
                break;
            default:
                displayText = currentValue.toString(16).toUpperCase();
        }
        provider.getDisplayField().setText(displayText);
        
        // Update multi-base labels
        provider.hexValueLabel.setText(sign + "0x" + currentValue.abs().toString(16).toUpperCase());
        provider.decValueLabel.setText(currentValue.toString(10));
        provider.octValueLabel.setText(sign + "0" + currentValue.abs().toString(8));

        // Binary Display: Pad to 4-bit alignment and add spaces
        String binaryStr = currentValue.abs().toString(2);
        int padLen = (4 - (binaryStr.length() % 4)) % 4;
        String paddedBinary = "0".repeat(padLen) + binaryStr;
        String binFormatted = paddedBinary.replaceAll("(.{4})", "$1 ").trim();
        provider.binValueLabel.setText(sign + binFormatted);
        
        // Update address validation info in tooltip
        String addressInfo = getAddressInfo(currentValue);
        provider.getDisplayField().setToolTipText(addressInfo);
    }
    
    /**
     * Get address information for the current value
     */
    private String getAddressInfo(BigInteger value) {
        try {
            if (provider.plugin.getCurrentProgram() == null) {
                return "No program loaded";
            }
            
            var addressFactory = provider.plugin.getCurrentProgram().getAddressFactory();
            var address = addressFactory.getDefaultAddressSpace().getAddress(value.longValue());
            
            if (provider.plugin.getCurrentProgram().getMemory().contains(address)) {
                return String.format("Valid address: %s", address.toString());
            } else {
                return "Address not in program memory";
            }
        } catch (Exception e) {
            return "Invalid address format";
        }
    }
    
    /**
     * Create a clickable label for input mode selection
     */
    public JLabel createModeLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        label.setOpaque(false);
        label.setBorder(BorderFactory.createMatteBorder(0, 3, 0, 0, GThemeDefaults.Colors.Viewport.UNEDITABLE_BACKGROUND));
        label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return label;
    }
    
    /**
     * Create value label
     */
    public JLabel createValueLabel() {
        JLabel label = new JLabel("0");
        label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return label;
    }
}