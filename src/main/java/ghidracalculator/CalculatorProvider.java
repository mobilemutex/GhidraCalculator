package ghidracalculator;

import java.math.BigInteger;

import javax.swing.*;

import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.util.ProgramLocation;
import ghidracalculator.resources.GhidraCalcIcons;
import resources.ResourceManager;
import ghidracalculator.ui.CalculatorUI;

/**
 * Calculator Provider
 *
 * This class provides the main calculator interface.
 */
public class CalculatorProvider extends ComponentProvider {

	public CalculatorPlugin plugin;
	private JComponent mainPanel;
	private CalculatorUI ui;
	
	// Utility classes
	private CalculatorLogic calculatorLogic;

	/**
	 * Constructor
	 * @param plugin The calculator plugin instance
	 */
	public CalculatorProvider(CalculatorPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;

		setTitle("Calculator");
		setWindowMenuGroup("Calculator");
		
		// Initialize utility classes
		ConsoleService consoleService = this.plugin.getTool().getService(ConsoleService.class);
		calculatorLogic = new CalculatorLogic(this, consoleService);

		// Build UI
		ui = new CalculatorUI(this.plugin, this, calculatorLogic);
		mainPanel = ui.getComponent();
		setDefaultWindowPosition(docking.WindowPosition.RIGHT);

		// Add toolbar actions
		createActions();
		setIcon(GhidraCalcIcons.GHIDRACALC_ICON);

		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public CalculatorLogic getCalculatorLogic() {
		return calculatorLogic;
	}

	/**
	 * Create toolbar actions for the calculator
	 */
	private void createActions() {
		// Clear action
		DockingAction clearAction = new DockingAction("Clear Calculator", plugin.getName()) {
			@Override
			public void actionPerformed(docking.ActionContext context) {
				calculatorLogic.clearCalculator();
				calculatorLogic.clearMark();
			}
		};
		clearAction.setDescription("Clear the calculator");
		clearAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/erase16.png"), null));
		addLocalAction(clearAction);
	}

	/**
	 * Calculate distance from current address to marked address
	 */
	public void calculateDistanceToMarked(long currentAddress) {
		calculatorLogic.calculateDistanceToMarked(currentAddress);
		
		// Show detailed information
		long markedAddress = calculatorLogic.getMarkedAddress();
		if (markedAddress != -1) {
			long distance = Math.abs(currentAddress - markedAddress);
			String message = String.format(
				"Distance Calculation:\n" +
				"From: 0x%X\n" +
				"To: 0x%X\n" +
				"Distance: 0x%X (%d bytes)",
				markedAddress, currentAddress, distance, distance
			);

			ConsoleService consoleService = this.plugin.getTool().getService(ConsoleService.class);
			consoleService.println(message);
		}
	}

	/**
	 * Parse input value based on prefix or current input mode
	 */
	public BigInteger parseInputValue(String input) throws NumberFormatException {
		// Remove common prefixes and determine base
		if (input.startsWith("0x") || input.startsWith("0X")) {
			return new BigInteger(input.substring(2), 16);
		} else if (input.startsWith("0b") || input.startsWith("0B")) {
			return new BigInteger(input.substring(2), 2);
		} else if (input.startsWith("0") && input.length() > 1 && input.matches("0[0-7]+")) {
			return new BigInteger(input.substring(1), 8);
		} else {
			// Use current input mode
			switch (calculatorLogic.getInputMode()) {
				case "HEX":
					// Remove any 0x prefix if present
					String hexInput = input.startsWith("0x") || input.startsWith("0X") ?
						input.substring(2) : input;
					return new BigInteger(hexInput, 16);
				case "DEC":
					return new BigInteger(input, 10);
				case "BIN":
					// Remove any 0b prefix if present
					String binInput = input.startsWith("0b") || input.startsWith("0B") ?
						input.substring(2) : input;
					return new BigInteger(binInput, 2);
				case "OCT":
					// Remove any leading 0 if present
					String octInput = input.startsWith("0") && input.length() > 1 ?
						input.substring(1) : input;
					return new BigInteger(octInput, 8);
				default:
					return new BigInteger(input, 10);
			}
		}
	}

	/**
	 * Navigate to an address if the value represents a valid address
	 */
	public void navigateToAddress(BigInteger value) {
		// Get the GoToService from the tool
		GoToService goToService = plugin.getTool().getService(GoToService.class);
		
		// Check if we have an active program
		if (plugin.getCurrentProgram() == null) {
			// Notify UI of error through model/listener pattern
			calculatorLogic.getModel().notifyError("No program loaded. Cannot navigate to address.");
			return;
		}
		
		try {
			// Convert value to address
			AddressFactory addressFactory = plugin.getCurrentProgram().getAddressFactory();
			Address address = addressFactory.getDefaultAddressSpace().getAddress(value.longValue());
			
			// Check if address is valid in the program
			if (!plugin.getCurrentProgram().getMemory().contains(address)) {
				// Notify UI of error through model/listener pattern
				calculatorLogic.getModel().notifyError(
					String.format("Address 0x%s is not valid in the current program.",
						value.toString(16).toUpperCase()));
				return;
			}
			
			// Navigate to the address
			if (goToService != null) {
				ProgramLocation location = new ProgramLocation(plugin.getCurrentProgram(), address);
				goToService.goTo(location);
			} else {
				// Notify UI of error through model/listener pattern
				calculatorLogic.getModel().notifyError("GoTo service not available.");
			}
		} catch (Exception e) {
			// Notify UI of error through model/listener pattern
			calculatorLogic.getModel().notifyError(
				String.format("Error navigating to address: %s", e.getMessage()));
		}
	}

	/**
	 * Add a value to the history
	 */
	public void addToHistory(BigInteger value, String operation) {
		plugin.getHistoryProvider().addToHistory(value, operation);
	}
}
