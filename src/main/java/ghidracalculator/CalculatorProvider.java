package ghidracalculator;

import java.math.BigInteger;
import java.util.Map;

import javax.swing.*;

import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GThemeDefaults;
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
	
	// GUI Components
	private JTextField displayField;
	
	// Calculator state
	// State variables are now managed by CalculatorLogic

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
		buildPanel();

		// Add toolbar actions
		createActions();
		setIcon(GhidraCalcIcons.GHIDRACALC_ICON);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public CalculatorUI getUI() {
		return ui;
	}

	public CalculatorLogic getCalculatorLogic() {
		return calculatorLogic;
	}


	public JTextField getDisplayField() {
		return displayField;
	}


	private void buildPanel() {
		// Create the main component
		ui = new CalculatorUI(this, calculatorLogic);
		mainPanel = ui.getComponent();
		setDefaultWindowPosition(docking.WindowPosition.RIGHT);
		setVisible(true);
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
				clearMark();
			}
		};
		clearAction.setDescription("Clear the calculator");
		clearAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/erase16.png"), null));
		addLocalAction(clearAction);

		// History window toggle action Not working, maybe ghidra doesnt allow toggling other providers?
		// DockingAction historyAction = new DockingAction("Toggle History Window", plugin.getName()) {
		// 	@Override
		// 	public void actionPerformed(docking.ActionContext context) {
		// 		plugin.getHistoryProvider().toggleHistoryWindow();
		// 	}
		// };
		// historyAction.setDescription("Show/Hide calculator history window");
		// historyAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/history.png"), null));
		// addLocalAction(historyAction);
	}


	public void setCurrentMode(String mode) {
		Map<String, JLabel> modeLabels = ui.getModeLabels();

        // Update highlighting
        modeLabels.get(calculatorLogic.getInputMode()).setBorder(BorderFactory.createMatteBorder(0, 3, 0, 0, GThemeDefaults.Colors.Viewport.UNEDITABLE_BACKGROUND));
		modeLabels.get(mode).setBorder(BorderFactory.createMatteBorder(0,3,0,0,GThemeDefaults.Colors.Palette.BLUE));
        
        calculatorLogic.setInputMode(mode);
    }

	public void setValueLabels(BigInteger currentValue, String sign) {
		 // Update multi-base labels
        ui.hexValueLabel.setText(sign + "0x" + currentValue.abs().toString(16).toUpperCase());
        ui.decValueLabel.setText(currentValue.toString(10));
        ui.octValueLabel.setText(sign + "0" + currentValue.abs().toString(8));

		// Binary Display: Pad to 4-bit alignment and add spaces
        String binaryStr = currentValue.abs().toString(2);
        int padLen = (4 - (binaryStr.length() % 4)) % 4;
        String paddedBinary = "0".repeat(padLen) + binaryStr;
        String binFormatted = paddedBinary.replaceAll("(.{4})", "$1 ").trim();
        ui.binValueLabel.setText(sign + binFormatted);
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
	 * Mark the current value for later recall
	 */
	public void markCurrentValue() {
		calculatorLogic.markCurrentValue();
		// Update UI
		BigInteger markedValue = calculatorLogic.getMarkedValue();
		String sign;
		if (markedValue.signum() == -1) {
			sign = "-";
		} else {
			sign = "";
		}

		ui.markedValueLabel.setText("Marked Value: " + sign + "0x" + markedValue.abs().toString(16).toUpperCase());
	}

	/**
	 * Recall the marked value
	 */
	public void recallMarkedValue() {
		calculatorLogic.recallMarkedValue();
	}

	/**
	 * Add a value to the calculator (used by context menu actions)
	 */
	public void addValue(BigInteger value) {
		calculatorLogic.setCurrentValue(value);
		calculatorLogic.setNewNumber(true);
	}

	/**
	 * Mark an address for distance calculation
	 */
	public void markAddress(long address) {
		calculatorLogic.setMarkedAddress(address);
		ui.markedAddressLabel.setText("Marked Address: 0x" + Long.toHexString(address).toUpperCase());
	}

	/**
	 * Mark a value for comparison operations
	 */
	public void markValueForComparison(BigInteger value) {
		calculatorLogic.markValueForComparison(value);
		// Update UI
		BigInteger markedValue = calculatorLogic.getMarkedValue();
		String sign;

		if (markedValue.signum() == -1) {
			sign = "-";
		} else {
			sign = "";
		}

		ui.markedValueLabel.setText("Marked Value: " + sign + "0x" + markedValue.abs().toString(16).toUpperCase());
	}

	/**
	 * Clear marked values and addresses
	 */
	private void clearMark() {
		calculatorLogic.clearMark();
		// Update UI
		ui.markedValueLabel.setText("Marked Value: None");
		ui.markedAddressLabel.setText("Marked Address: None");
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
	 * Check if a value is marked for comparison
	 */
	public boolean hasMarkedValue() {
		return calculatorLogic.hasMarkedValue();
	}
	
	/**
	 * Check if an address is marked
	 */
	public boolean hasMarkedAddress() {
		return calculatorLogic.hasMarkedAddress();
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
