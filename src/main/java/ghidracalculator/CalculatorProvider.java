package ghidracalculator;

import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.KeyListener;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.DataFlavor;
import java.math.BigInteger;
import javax.swing.*;


import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.util.ProgramLocation;
import ghidra.app.services.ConsoleService;
import ghidracalculator.resources.GhidraCalcIcons;
import resources.ResourceManager;

/**
 * Calculator Provider
 * 
 * This class provides the main calculator interface.
 */
public class CalculatorProvider extends ComponentProvider {

	private CalculatorPlugin plugin;
	private JComponent mainPanel;
	
	// GUI Components
	private JTextField displayField;
	private JLabel hexLabel;
	private JLabel decLabel;
	private JLabel binLabel;
	private JLabel octLabel;
	private JLabel markedValueLabel;
	private JLabel markedAddressLabel;
	private JComboBox<String> inputModeCombo;
	
	// Calculator state
	protected BigInteger currentValue = BigInteger.ZERO;
	private BigInteger previousValue = BigInteger.ZERO;
	private String currentOperation = "";
	protected boolean newNumber = true;
	private String inputMode = "HEX"; // HEX, DEC, BIN, OCT
	
	// Marking functionality
	private BigInteger markedValue = null;
	private long markedAddress = -1;

	/**
	 * Constructor
	 * @param plugin The calculator plugin instance
	 */
	public CalculatorProvider(CalculatorPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;

		setTitle("Calculator");
		setWindowMenuGroup("Calculator");
		
		// Create the main component
		mainPanel = createMainComponent();
		setDefaultWindowPosition(docking.WindowPosition.RIGHT);
		
		// Add toolbar actions
		createActions();
		setIcon(GhidraCalcIcons.GHIDRACALC_ICON);
		
		// Set the component
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	/**
	 * Create toolbar actions for the calculator
	 */
	private void createActions() {
		// Clear action
		DockingAction clearAction = new DockingAction("Clear Calculator", plugin.getName()) {
			@Override
			public void actionPerformed(docking.ActionContext context) {
				clearCalculator();
			}
		};
		clearAction.setDescription("Clear the calculator");
		clearAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/erase16.png"), null));
		addLocalAction(clearAction);

		// History window toggle action
		DockingAction historyAction = new DockingAction("Toggle History Window", plugin.getName()) {
			@Override
			public void actionPerformed(docking.ActionContext context) {
				plugin.getHistoryProvider().toggleHistoryWindow();
			}
		};
		historyAction.setDescription("Show/Hide calculator history window");
		historyAction.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/history.png"), null));
		addLocalAction(historyAction);
	}

	/**
	 * Create the main calculator component
	 */
	private JComponent createMainComponent() {
		JPanel mainPanel = new JPanel(new BorderLayout());
		
		// Create display panel
		JPanel displayPanel = createDisplayPanel();
		mainPanel.add(displayPanel, BorderLayout.NORTH);
		
		// Create button panel
		JPanel buttonPanel = createButtonPanel();
		mainPanel.add(buttonPanel, BorderLayout.CENTER);
		
		// Create increment panel
		JPanel incrementPanel = createIncrementPanel();
		mainPanel.add(incrementPanel, BorderLayout.SOUTH);
		
		// Initialize display
		updateDisplay();
		
		return mainPanel;
	}

	/**
	 * Navigate to an address if the value represents a valid address
	 */
	public void navigateToAddress(BigInteger value) {
		try {
			// Check if we have an active program
			if (plugin.getCurrentProgram() == null) {
				JOptionPane.showMessageDialog(getComponent(), 
					"No program loaded. Cannot navigate to address.", 
					"Navigation Error", 
					JOptionPane.WARNING_MESSAGE);
				return;
			}
			
			// Convert value to address
			AddressFactory addressFactory = plugin.getCurrentProgram().getAddressFactory();
			Address address = addressFactory.getDefaultAddressSpace().getAddress(value.longValue());
			
			// Check if address is valid in the program
			if (!plugin.getCurrentProgram().getMemory().contains(address)) {
				JOptionPane.showMessageDialog(getComponent(), 
					String.format("Address 0x%s is not valid in the current program.", 
						value.toString(16).toUpperCase()), 
					"Invalid Address", 
					JOptionPane.WARNING_MESSAGE);
				return;
			}
			
			// Navigate to the address
			GoToService goToService = plugin.getTool().getService(GoToService.class);
			if (goToService != null) {
				ProgramLocation location = new ProgramLocation(plugin.getCurrentProgram(), address);
				goToService.goTo(location);
			} else {
				JOptionPane.showMessageDialog(getComponent(), 
					"GoTo service not available.", 
					"Navigation Error", 
					JOptionPane.ERROR_MESSAGE);
			}
			
		} catch (Exception e) {
			JOptionPane.showMessageDialog(getComponent(), 
				String.format("Error navigating to address: %s", e.getMessage()), 
				"Navigation Error", 
				JOptionPane.ERROR_MESSAGE);
		}
	}

	/**
	 * Create the display panel with multi-base output
	 */
	private JPanel createDisplayPanel() {
		JPanel panel = new JPanel(new GridBagLayout());
		panel.setBorder(BorderFactory.createTitledBorder("Display"));
		GridBagConstraints gbc = new GridBagConstraints();
		
		// Input mode selector
		gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
		panel.add(new JLabel("Input Mode:"), gbc);
		
		gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
		inputModeCombo = new JComboBox<>(new String[]{"HEX", "DEC", "BIN", "OCT"});
		inputModeCombo.setSelectedItem(inputMode);
		inputModeCombo.addActionListener(e -> {
			inputMode = (String) inputModeCombo.getSelectedItem();
			updateDisplay();
		});
		panel.add(inputModeCombo, gbc);

		// Main display field
		gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2; gbc.weightx = 1.0;
		displayField = new JTextField();
		displayField.setFont(new Font(Font.MONOSPACED, Font.BOLD, 16));
		displayField.setHorizontalAlignment(JTextField.RIGHT);
		displayField.setEditable(true); // Allow keyboard input
		//displayField.setBackground(Color.WHITE);
		//displayField.setForeground(Color.BLACK);

		displayField.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showDisplayContextMenu(e);
				}
			}
			
			@Override
			public void mouseReleased(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showDisplayContextMenu(e);
				}
			}
		});
		
		// Add keyboard input support
		displayField.addKeyListener(new KeyListener() {
			@Override
			public void keyPressed(KeyEvent e) {
				handleKeyPress(e);
			}
			
			@Override
			public void keyReleased(KeyEvent e) {
				// Not used
			}
			
			@Override
			public void keyTyped(KeyEvent e) {
				// Not used - we handle in keyPressed
			}
		});
		
		// Add action listener for Enter key
		displayField.addActionListener(e -> {
			parseDisplayInput();
		});
		
		panel.add(displayField, gbc);
		
		// Multi-base display labels
		gbc.gridwidth = 1; gbc.weightx = 0.0;

		gbc.gridx = 0; gbc.gridy = 2; 
		panel.add(new JLabel("HEX:"), gbc);
		gbc.gridx = 1; gbc.weightx = 1.0;
		hexLabel = new JLabel("0");
		hexLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		panel.add(hexLabel, gbc);
		
		gbc.gridx = 0; gbc.gridy = 3; gbc.weightx = 0.0;
		panel.add(new JLabel("DEC:"), gbc);
		gbc.gridx = 1; gbc.weightx = 1.0;
		decLabel = new JLabel("0");
		decLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		panel.add(decLabel, gbc);
		
		gbc.gridx = 0; gbc.gridy = 4; gbc.weightx = 0.0;
		panel.add(new JLabel("BIN:"), gbc);
		gbc.gridx = 1; gbc.weightx = 1.0;
		binLabel = new JLabel("0");
		binLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		panel.add(binLabel, gbc);
		
		gbc.gridx = 0; gbc.gridy = 5; gbc.weightx = 0.0;
		panel.add(new JLabel("OCT:"), gbc);
		gbc.gridx = 1; gbc.weightx = 1.0;
		octLabel = new JLabel("0");
		octLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		panel.add(octLabel, gbc);
		
		// Status labels for marked values
		gbc.gridx = 0; gbc.gridy = 6; gbc.gridwidth = 2; gbc.weightx = 1.0;
		markedValueLabel = new JLabel("Marked Value: None");
		markedValueLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 10));
		//markedValueLabel.setForeground(Color.BLUE);
		panel.add(markedValueLabel, gbc);
		
		gbc.gridy = 7;
		markedAddressLabel = new JLabel("Marked Address: None");
		markedAddressLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 10));
		//markedAddressLabel.setForeground(Color.BLUE);
		panel.add(markedAddressLabel, gbc);
		
		return panel;
	}

	/**
	 * Create the main button panel with calculator operations
	 */
	private JPanel createButtonPanel() {
		JPanel panel = new JPanel(new GridLayout(6, 4, 2, 2));
		panel.setBorder(BorderFactory.createTitledBorder("Operations"));
		
		// Row 1: Clear, Mark, Recall, and special operations
		panel.add(createButton("C", e -> clearCalculator()));
		panel.add(createButton("Mark", e -> markCurrentValue()));
		panel.add(createButton("Recall", e -> recallMarkedValue()));
		panel.add(createButton("=", e -> performEquals()));
		
		// Row 2: Hex digits and operations
		panel.add(createButton("A", e -> appendDigit("A")));
		panel.add(createButton("B", e -> appendDigit("B")));
		panel.add(createButton("C", e -> appendDigit("C")));
		panel.add(createButton("/", e -> setOperation("/")));
		
		// Row 3: Hex digits and operations  
		panel.add(createButton("D", e -> appendDigit("D")));
		panel.add(createButton("E", e -> appendDigit("E")));
		panel.add(createButton("F", e -> appendDigit("F")));
		panel.add(createButton("*", e -> setOperation("*")));
		
		// Row 4: Numbers and operations
		panel.add(createButton("7", e -> appendDigit("7")));
		panel.add(createButton("8", e -> appendDigit("8")));
		panel.add(createButton("9", e -> appendDigit("9")));
		panel.add(createButton("-", e -> setOperation("-")));
		
		// Row 5: Numbers and operations
		panel.add(createButton("4", e -> appendDigit("4")));
		panel.add(createButton("5", e -> appendDigit("5")));
		panel.add(createButton("6", e -> appendDigit("6")));
		panel.add(createButton("+", e -> setOperation("+")));
		
		// Row 6: Numbers and operations
		panel.add(createButton("1", e -> appendDigit("1")));
		panel.add(createButton("2", e -> appendDigit("2")));
		panel.add(createButton("3", e -> appendDigit("3")));
		panel.add(createButton("0", e -> appendDigit("0")));
		
		return panel;
	}

	/**
	 * Create the increment/decrement and bitwise operations panel
	 */
	private JPanel createIncrementPanel() {
		JPanel panel = new JPanel(new GridLayout(3, 4, 2, 2));
		panel.setBorder(BorderFactory.createTitledBorder("Quick Operations"));
		
		// Row 1: Increment operations
		panel.add(createButton("+1", e -> increment(BigInteger.ONE)));
		panel.add(createButton("+0x10", e -> increment(BigInteger.valueOf(0x10))));
		panel.add(createButton("+0x100", e -> increment(BigInteger.valueOf(0x100))));
		panel.add(createButton("+0x1000", e -> increment(BigInteger.valueOf(0x1000))));
		
		// Row 2: Decrement operations
		panel.add(createButton("-1", e -> increment(BigInteger.ONE.negate())));
		panel.add(createButton("-0x10", e -> increment(BigInteger.valueOf(-0x10))));
		panel.add(createButton("-0x100", e -> increment(BigInteger.valueOf(-0x100))));
		panel.add(createButton("-0x1000", e -> increment(BigInteger.valueOf(-0x1000))));
		
		// Row 3: Bitwise operations
		panel.add(createButton("AND", e -> setOperation("AND")));
		panel.add(createButton("OR", e -> setOperation("OR")));
		panel.add(createButton("XOR", e -> setOperation("XOR")));
		panel.add(createButton("NOT", e -> bitwiseNot()));
		
		return panel;
	}

	/**
	 * Create a button with the specified text and action
	 */
	private JButton createButton(String text, ActionListener action) {
		JButton button = new JButton(text);
		button.addActionListener(action);
		button.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
		return button;
	}

	/**
	 * Update the display with current value in all number bases
	 */
	protected void updateDisplay() {
		// Update main display field based on input mode
		String displayText;
		switch (inputMode) {
			case "HEX":
				displayText = "0x" + currentValue.toString(16).toUpperCase();
				break;
			case "DEC":
				displayText = currentValue.toString(10);
				break;
			case "BIN":
				displayText = "0b" + currentValue.toString(2);
				break;
			case "OCT":
				displayText = "0" + currentValue.toString(8);
				break;
			default:
				displayText = currentValue.toString(16).toUpperCase();
		}
		displayField.setText(displayText);
		
		// Update multi-base labels
		hexLabel.setText("0x" + currentValue.toString(16).toUpperCase());
		decLabel.setText(currentValue.toString(10));
		binLabel.setText("0b" + currentValue.toString(2));
		octLabel.setText("0" + currentValue.toString(8));

		// Update address validation info in tooltip
		String addressInfo = getAddressInfo(currentValue);
		displayField.setToolTipText(addressInfo);
		
		// Change display field color based on address validity
		if (isValidAddress(currentValue)) {
			displayField.setBackground(new Color(230, 255, 230)); // Light green
		} else {
			displayField.setBackground(Color.WHITE);
		}
	}

	/**
	 * Append a digit to the current number
	 */
	private void appendDigit(String digit) {
		if (newNumber) {
			currentValue = BigInteger.ZERO;
			newNumber = false;
		}
		
		// Validate digit for current input mode
		int digitValue;
		try {
			switch (inputMode) {
				case "HEX":
					digitValue = Integer.parseInt(digit, 16);
					currentValue = currentValue.multiply(BigInteger.valueOf(16)).add(BigInteger.valueOf(digitValue));
					break;
				case "DEC":
					if (digit.matches("[0-9]")) {
						digitValue = Integer.parseInt(digit, 10);
						currentValue = currentValue.multiply(BigInteger.valueOf(10)).add(BigInteger.valueOf(digitValue));
					}
					break;
				case "BIN":
					if (digit.matches("[01]")) {
						digitValue = Integer.parseInt(digit, 2);
						currentValue = currentValue.multiply(BigInteger.valueOf(2)).add(BigInteger.valueOf(digitValue));
					}
					break;
				case "OCT":
					if (digit.matches("[0-7]")) {
						digitValue = Integer.parseInt(digit, 8);
						currentValue = currentValue.multiply(BigInteger.valueOf(8)).add(BigInteger.valueOf(digitValue));
					}
					break;
			}
		} catch (NumberFormatException e) {
			// Invalid digit for current mode, ignore
			return;
		}
		
		updateDisplay();
	}

	/**
	 * Set the current operation
	 */
	private void setOperation(String operation) {
		if (!currentOperation.isEmpty()) {
			performEquals();
		}
		previousValue = currentValue;
		currentOperation = operation;
		newNumber = true;
	}

	/**
	 * Perform the equals operation
	 */
	private void performEquals() {
		if (currentOperation.isEmpty()) {
			return;
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
			case "*":
				result = previousValue.multiply(currentValue);
				break;
			case "/":
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
		}
		
		currentValue = result;
		currentOperation = "";
		newNumber = true;

		// Add to history
		plugin.getHistoryProvider().addToHistory(result, operationString);
		updateDisplay();
	}

	/**
	 * Clear the calculator
	 */
	private void clearCalculator() {
		currentValue = BigInteger.ZERO;
		previousValue = BigInteger.ZERO;
		currentOperation = "";
		newNumber = true;
		updateDisplay();
	}

	/**
	 * Increment the current value by the specified amount
	 */
	private void increment(BigInteger amount) {
		currentValue = currentValue.add(amount);
		newNumber = true;
		updateDisplay();
	}

	/**
	 * Perform bitwise NOT operation
	 */
	private void bitwiseNot() {
		// For display purposes, limit to 32-bit NOT
		long mask = 0xFFFFFFFFL;
		currentValue = BigInteger.valueOf((~currentValue.longValue()) & mask);
		newNumber = true;
		updateDisplay();
	}

	/**
	 * Mark the current value for later recall
	 */
	private void markCurrentValue() {
		markedValue = currentValue;
		markedValueLabel.setText("Marked Value: " + markedValue.toString(16).toUpperCase() + "h");
	}

	/**
	 * Recall the marked value
	 */
	private void recallMarkedValue() {
		if (markedValue != null) {
			currentValue = markedValue;
			newNumber = true;
			updateDisplay();
		}
	}

	/**
	 * Add a value to the calculator (used by context menu actions)
	 */
	public void addValue(BigInteger value) {
		currentValue = value;
		newNumber = true;
		updateDisplay();
	}

	/**
	 * Mark an address for distance calculation
	 */
	public void markAddress(long address) {
		markedAddress = address;
		markedAddressLabel.setText("Marked Address: 0x" + Long.toHexString(address).toUpperCase());
	}

	/**
	 * Check if an address is marked
	 */
	public boolean hasMarkedAddress() {
		return markedAddress != -1;
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
			updateDisplay();
			
			// Show detailed information
			String message = String.format(
				"Distance Calculation:\n" +
				"From: 0x%X\n" +
				"To: 0x%X\n" +
				"Distance: 0x%X (%d bytes)",
				markedAddress, currentAddress, distance, distance
			);
			ConsoleService consoleService = this.plugin.getTool().getService(ConsoleService.class);
			consoleService.println(message);
			JOptionPane.showMessageDialog(getComponent(), message, "Address Distance", JOptionPane.INFORMATION_MESSAGE);
		}
	}

	/**
	 * Mark a value for comparison operations
	 */
	public void markValueForComparison(BigInteger value) {
		markedValue = value;
		markedValueLabel.setText("Marked Value: 0x" + value.toString(16).toUpperCase());
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
	public void performMarkedValueOperation(BigInteger currentMemValue, String operation) {
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
			updateDisplay();
			
			// Show detailed operation information
			String message = String.format(
				"Marked Value Operation:\n" +
				"Marked: 0x%s\n" +
				"Current: 0x%s\n" +
				"Operation: %s\n" +
				"Result: 0x%s (%s)",
				markedValue.toString(16).toUpperCase(),
				currentMemValue.toString(16).toUpperCase(),
				operationSymbol,
				result.toString(16).toUpperCase(),
				result.toString(10)
			);
			ConsoleService consoleService = this.plugin.getTool().getService(ConsoleService.class);
			consoleService.println(message);
			JOptionPane.showMessageDialog(getComponent(), message, "Value Operation Result", JOptionPane.INFORMATION_MESSAGE);
		}
	}

	/**
	 * Clear marked values and addresses
	 */
	// private void clearMark() {
	// 	markedValue = null;
	// 	markedAddress = -1;
	// 	markedValueLabel.setText("Marked Value: None");
	// 	markedAddressLabel.setText("Marked Address: None");
	// }

	/**
	 * Handle keyboard input for calculator operations
	 */
	private void handleKeyPress(KeyEvent e) {
		int keyCode = e.getKeyCode();
		char keyChar = e.getKeyChar();
		
		// Handle special keys
		switch (keyCode) {
			case KeyEvent.VK_ENTER:
				parseDisplayInput();
				e.consume();
				return;
			case KeyEvent.VK_ESCAPE:
				clearCalculator();
				e.consume();
				return;
			case KeyEvent.VK_BACK_SPACE:
			case KeyEvent.VK_DELETE:
				// Allow normal backspace/delete behavior
				return;
		}
		
		// Handle operation keys
		if (keyChar == '+') {
			setOperation("+");
			e.consume();
		} else if (keyChar == '-') {
			setOperation("-");
			e.consume();
		} else if (keyChar == '*') {
			setOperation("*");
			e.consume();
		} else if (keyChar == '/') {
			setOperation("/");
			e.consume();
		} else if (keyChar == '=') {
			performEquals();
			e.consume();
		} else if (keyChar == '&') {
			setOperation("AND");
			e.consume();
		} else if (keyChar == '|') {
			setOperation("OR");
			e.consume();
		} else if (keyChar == '^') {
			setOperation("XOR");
			e.consume();
		} else if (keyChar == '~') {
			bitwiseNot();
			e.consume();
		}
		// For other characters, let the text field handle them normally
	}

	/**
	 * Parse the input from the display field and update the calculator value
	 */
	private void parseDisplayInput() {
		String input = displayField.getText().trim();
		if (input.isEmpty()) {
			return;
		}
		
		try {
			BigInteger value = parseInputValue(input);
			currentValue = value;
			newNumber = true;
			updateDisplay();
		} catch (NumberFormatException e) {
			// Invalid input, show error briefly
			String originalText = displayField.getText();
			displayField.setText("ERROR");
			displayField.setBackground(Color.PINK);
			
			// Reset after 1 second
			Timer timer = new Timer(1000, evt -> {
				displayField.setText(originalText);
				displayField.setBackground(Color.WHITE);
			});
			timer.setRepeats(false);
			timer.start();
		}
	}

	/**
	 * Parse input value based on prefix or current input mode
	 */
	private BigInteger parseInputValue(String input) throws NumberFormatException {
		// Remove common prefixes and determine base
		if (input.startsWith("0x") || input.startsWith("0X")) {
			return new BigInteger(input.substring(2), 16);
		} else if (input.startsWith("0b") || input.startsWith("0B")) {
			return new BigInteger(input.substring(2), 2);
		} else if (input.startsWith("0") && input.length() > 1 && input.matches("0[0-7]+")) {
			return new BigInteger(input.substring(1), 8);
		} else {
			// Use current input mode
			switch (inputMode) {
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
	 * Jump to the current calculator value as an address in the listing
	 */
	private void jumpToCurrentAddress() {
		navigateToAddress(currentValue);
	}

	/**
	 * Validate if a value represents a valid address in the current program
	 */
	private boolean isValidAddress(BigInteger value) {
		try {
			if (plugin.getCurrentProgram() == null) {
				return false;
			}
			
			AddressFactory addressFactory = plugin.getCurrentProgram().getAddressFactory();
			Address address = addressFactory.getDefaultAddressSpace().getAddress(value.longValue());
			
			return plugin.getCurrentProgram().getMemory().contains(address);
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Show context menu for the display field
	 */
	private void showDisplayContextMenu(MouseEvent e) {
		JPopupMenu popup = new JPopupMenu();
		
		// Jump to Address option (only if valid address)
		if (isValidAddress(currentValue)) {
			JMenuItem jumpItem = new JMenuItem("Jump to Address");
			jumpItem.setToolTipText("Navigate to 0x" + currentValue.toString(16).toUpperCase() + " in the listing");
			jumpItem.addActionListener(evt -> jumpToCurrentAddress());
			popup.add(jumpItem);
		}
		
		// Copy Value option
		JMenuItem copyItem = new JMenuItem("Copy Value");
		copyItem.setToolTipText("Copy current value to clipboard");
		copyItem.addActionListener(evt -> copyValueToClipboard());
		popup.add(copyItem);
		
		// Paste Value option
		JMenuItem pasteItem = new JMenuItem("Paste Value");
		pasteItem.setToolTipText("Paste value from clipboard");
		pasteItem.addActionListener(evt -> pasteValueFromClipboard());
		popup.add(pasteItem);
		
		// Only show popup if it has items
		if (popup.getComponentCount() > 0) {
			popup.show(displayField, e.getX(), e.getY());
		}
	}

	/**
	 * Copy current value to clipboard
	 */
	private void copyValueToClipboard() {
		try {
			String value = displayField.getText();
			StringSelection selection = new StringSelection(value);
			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
			
			// Show brief feedback
			displayField.setToolTipText("Value copied to clipboard: " + value);
		} catch (Exception ex) {
			JOptionPane.showMessageDialog(getComponent(), 
				"Error copying to clipboard: " + ex.getMessage(), 
				"Copy Error", 
				JOptionPane.ERROR_MESSAGE);
		}
	}

	/**
	 * Paste value from clipboard
	 */
	private void pasteValueFromClipboard() {
		try {
			String clipboardText = (String) Toolkit.getDefaultToolkit()
				.getSystemClipboard().getData(DataFlavor.stringFlavor);
			
			if (clipboardText != null && !clipboardText.trim().isEmpty()) {
				displayField.setText(clipboardText.trim());
				parseInputValue(clipboardText.trim());
			}
		} catch (Exception ex) {
			JOptionPane.showMessageDialog(getComponent(), 
				"Error pasting from clipboard: " + ex.getMessage(), 
				"Paste Error", 
				JOptionPane.ERROR_MESSAGE);
		}
	}

	/**
	 * Get address information for the current value
	 */
	private String getAddressInfo(BigInteger value) {
		try {
			if (plugin.getCurrentProgram() == null) {
				return "No program loaded";
			}
			
			AddressFactory addressFactory = plugin.getCurrentProgram().getAddressFactory();
			Address address = addressFactory.getDefaultAddressSpace().getAddress(value.longValue());
			
			if (plugin.getCurrentProgram().getMemory().contains(address)) {
				return String.format("Valid address: %s", address.toString());
			} else {
				return "Address not in program memory";
			}
		} catch (Exception e) {
			return "Invalid address format";
		}
	}
}