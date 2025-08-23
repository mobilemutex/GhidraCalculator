package ghidracalculator.util;

import java.math.BigInteger;

import javax.swing.JOptionPane;

import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.util.ProgramLocation;
import ghidracalculator.CalculatorLogic;
import ghidracalculator.CalculatorProvider;

/**
 * Address Navigator class to handle address navigation functionality
 */
public class AddressNavigator {
    private CalculatorProvider provider;
    private CalculatorLogic calculatorLogic;
    
    public AddressNavigator(CalculatorProvider provider, CalculatorLogic calculatorLogic) {
        this.provider = provider;
        this.calculatorLogic = calculatorLogic;
    }
    
    /**
     * Navigate to an address if the value represents a valid address
     */
    public void navigateToAddress(BigInteger value) {
        try {
            // Check if we have an active program
            if (provider.plugin.getCurrentProgram() == null) {
                JOptionPane.showMessageDialog(provider.getComponent(), 
                    "No program loaded. Cannot navigate to address.", 
                    "Navigation Error", 
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            // Convert value to address
            AddressFactory addressFactory = provider.plugin.getCurrentProgram().getAddressFactory();
            Address address = addressFactory.getDefaultAddressSpace().getAddress(value.longValue());
            
            // Check if address is valid in the program
            if (!provider.plugin.getCurrentProgram().getMemory().contains(address)) {
                JOptionPane.showMessageDialog(provider.getComponent(), 
                    String.format("Address 0x%s is not valid in the current program.", 
                        value.toString(16).toUpperCase()), 
                    "Invalid Address", 
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            // Navigate to the address
            GoToService goToService = provider.plugin.getTool().getService(GoToService.class);
            if (goToService != null) {
                ProgramLocation location = new ProgramLocation(provider.plugin.getCurrentProgram(), address);
                goToService.goTo(location);
            } else {
                JOptionPane.showMessageDialog(provider.getComponent(), 
                    "GoTo service not available.", 
                    "Navigation Error", 
                    JOptionPane.ERROR_MESSAGE);
            }
            
        } catch (Exception e) {
            JOptionPane.showMessageDialog(provider.getComponent(), 
                String.format("Error navigating to address: %s", e.getMessage()), 
                "Navigation Error", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * Validate if a value represents a valid address in the current program
     */
    public boolean isValidAddress(BigInteger value) {
        try {
            if (provider.plugin.getCurrentProgram() == null) {
                return false;
            }
            
            AddressFactory addressFactory = provider.plugin.getCurrentProgram().getAddressFactory();
            Address address = addressFactory.getDefaultAddressSpace().getAddress(value.longValue());
            
            return provider.plugin.getCurrentProgram().getMemory().contains(address);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Jump to the current calculator value as an address in the listing
     */
    public void jumpToCurrentAddress() {
        navigateToAddress(calculatorLogic.getCurrentValue());
    }
}