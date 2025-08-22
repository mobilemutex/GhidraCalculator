package ghidracalculator;

import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.KeyListener;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GThemeDefaults;
import ghidra.app.services.ConsoleService;
import ghidracalculator.resources.GhidraCalcIcons;
import resources.ResourceManager;
import ghidracalculator.util.*;

/**
 * Calculator Provider
 * 
 * This class provides the main calculator interface.
 */
public class CalculatorProvider extends ComponentProvider {

	public CalculatorPlugin plugin;
	private JComponent mainPanel;
	
	// Utility classes
	private CalculatorLogic calculatorLogic;
	private DisplayManager displayManager;
	private AddressNavigator addressNavigator;
	private InputHandler inputHandler;
	private ContextMenuHandler contextMenuHandler;
	
	// GUI Components
	private JTextField displayField;
	private JLabel hexModeLabel, decModeLabel, octModeLabel, binModeLabel;
	public JLabel hexValueLabel, decValueLabel, octValueLabel, binValueLabel;
	public JLabel markedValueLabel, markedAddressLabel;
	private Map<String, JLabel> modeLabels, valueLabels;
	
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
		
		// Create the main component
		mainPanel = createMainComponent();
		setDefaultWindowPosition(docking.WindowPosition.RIGHT);
		
		// Initialize utility classes
		calculatorLogic = new CalculatorLogic(this);
		displayManager = new DisplayManager(this);
		addressNavigator = new AddressNavigator(this);
		inputHandler = new InputHandler(this);
		contextMenuHandler = new ContextMenuHandler(this);
		
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

	public CalculatorLogic getCalculatorLogic() {
		return calculatorLogic;
	}

	public JTextField getDisplayField() {
		return displayField;
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
		setCurrentMode("HEX");
		
		return mainPanel;
	}

	/**
	 * Create the display panel with multi-base output
	 */
	private JPanel createDisplayPanel() {
		hexModeLabel = displayManager.createModeLabel("HEX:   ");
		decModeLabel = displayManager.createModeLabel("DEC:   ");
		octModeLabel = displayManager.createModeLabel("OCT:   ");
		binModeLabel = displayManager.createModeLabel("BIN:   ");

		hexValueLabel = displayManager.createValueLabel();
		decValueLabel = displayManager.createValueLabel();
		octValueLabel = displayManager.createValueLabel();
		binValueLabel = displayManager.createValueLabel();

		modeLabels = new HashMap<>();
        modeLabels.put("HEX", hexModeLabel);
        modeLabels.put("DEC", decModeLabel);
        modeLabels.put("OCT", octModeLabel);
        modeLabels.put("BIN", binModeLabel);

		valueLabels = new HashMap<>();
        valueLabels.put("HEX", hexValueLabel);
        valueLabels.put("DEC", decValueLabel);
        valueLabels.put("OCT", octValueLabel);
        valueLabels.put("BIN", binValueLabel);

		JPanel panel = new JPanel(new GridBagLayout());
		panel.setBorder(BorderFactory.createTitledBorder("Display"));
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.HORIZONTAL;

		// Main display field
		gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2; gbc.weightx = 1.0;
		displayField = new JTextField();
		displayField.setFont(new Font(Font.MONOSPACED, Font.BOLD, 16));
		displayField.setHorizontalAlignment(JTextField.RIGHT);
		displayField.setEditable(true); // Allow keyboard input
		displayField.setBackground(GThemeDefaults.Colors.BACKGROUND);
		displayField.setForeground(GThemeDefaults.Colors.FOREGROUND);

		displayField.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (e.isPopupTrigger()) {
					contextMenuHandler.showDisplayContextMenu(e);
				}
			}
			
			@Override
			public void mouseReleased(MouseEvent e) {
				if (e.isPopupTrigger()) {
					contextMenuHandler.showDisplayContextMenu(e);
				}
			}
		});
		
		// Add keyboard input support
		displayField.addKeyListener(new KeyListener() {
			@Override
			public void keyPressed(KeyEvent e) {
				inputHandler.handleKeyPress(e);
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
			inputHandler.parseDisplayInput();
		});
		
		panel.add(displayField, gbc);
		
		// Multi-base display labels
		gbc.gridwidth = 1; 

		String[] modes = {"HEX", "DEC", "OCT", "BIN"};
		for (int i = 0; i < modes.length; i++) {
            String mode = modes[i];

			gbc.gridx = 0; gbc.gridy = 1 + i; gbc.weightx = 0.0;
			panel.add(modeLabels.get(mode), gbc);

			gbc.gridx = 1; gbc.weightx = 1.0;
			panel.add(valueLabels.get(mode), gbc);
		}

		// Add mouse listeners to mode labels
        for (Map.Entry<String, JLabel> entry : modeLabels.entrySet()) {
            String mode = entry.getKey();
            JLabel label = entry.getValue();
            
            label.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    setCurrentMode(mode);
                }
            });
        }

		// Status labels for marked values
		gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2; gbc.weightx = 1.0;
		markedValueLabel = new JLabel("Marked Value: None");
		markedValueLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 10));
		//markedValueLabel.setForeground(Color.BLUE);
		panel.add(markedValueLabel, gbc);
		
		gbc.gridy = 6;
		markedAddressLabel = new JLabel("Marked Address: None");
		markedAddressLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 10));
		//markedAddressLabel.setForeground(Color.BLUE);
		panel.add(markedAddressLabel, gbc);
		
		return panel;
	}

	private void setCurrentMode(String mode) {
	       // Update highlighting
	       modeLabels.get(calculatorLogic.getInputMode()).setBorder(BorderFactory.createMatteBorder(0, 3, 0, 0, GThemeDefaults.Colors.Viewport.UNEDITABLE_BACKGROUND));
		   modeLabels.get(mode).setBorder(BorderFactory.createMatteBorder(0,3,0,0,GThemeDefaults.Colors.Palette.BLUE));
	       
	       calculatorLogic.setInputMode(mode);
	       updateDisplay();
	   }

	private JPanel createButtonPanel() {
		JPanel buttonPanel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(0, 2, 0, 2);
        gbc.fill = GridBagConstraints.BOTH;
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.weightx = .6;
		gbc.weighty = 1;
		gbc.gridwidth = 1;

		JPanel operationsPanel = createOperationsPanel();
		buttonPanel.add(operationsPanel, gbc);

		gbc.gridx = 1;
		gbc.weightx = 1;
		gbc.insets = new Insets(0, 0, 0, 2);
		JPanel basicPanel = createBasicPanel();
		buttonPanel.add(basicPanel, gbc);
		
		return buttonPanel;
	}

	/**
	 * Create the main button panel with calculator operations
	 */
	private JPanel createBasicPanel() {
		JPanel basicPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 2, 2, 2);
        gbc.fill = GridBagConstraints.BOTH;
        
        // Main buttons (0-9, A-F, Basic Operations)
        String[] numbers = {"D", "E", "F",
							"A", "B", "C",
							"7", "8", "9",
							"4", "5", "6",
						    "1", "2", "3",};

		// Operator buttons - divide and multipy symbols in unicode
		String[] operators = {"CLR", "\u00F7", "\u00D7", "-", "+"}; 
		String[] lastRow = {"0", "="};
        int row = 0, col = 0;
		gbc.weightx = 1;
		gbc.weighty = 1;
		gbc.ipadx = 5;
        
		for (int i = 0; i < 20; i++) {
			gbc.gridx = col;
            gbc.gridy = row;
			// Col 3 is the operators
			if (col == 3) {
				String op = operators[row];
				JButton btn = new JButton(op);
				btn.addActionListener(e -> performOperation(op));
				btn.setMargin(new Insets(6, 6, 6, 6));
				btn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
				basicPanel.add(btn, gbc);
			} else {
				String num = numbers[col + (row * 3)];
				JButton btn = new JButton(num);
				btn.addActionListener(e -> appendDigit(num));
				basicPanel.add(btn, gbc);
			}

			col++;
            if (col > 3) {
                col = 0;
                row++;
            }
		}
		// Add the last two buttons (0 and =)
		gbc.gridx = 1;
		gbc.gridy = row;
		String num = lastRow[0]; // 0
		JButton btn = new JButton(num);
		btn.addActionListener(e -> appendDigit(num));
		basicPanel.add(btn, gbc);

		gbc.gridx = 2;
		gbc.gridwidth = 2;
		String eq = lastRow[1]; // =
		btn = new JButton(eq);
		btn.addActionListener(e -> performOperation(eq));
		basicPanel.add(btn, gbc);

		return basicPanel;
	}

	private JPanel createOperationsPanel() {
		JPanel operationsPanel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 2, 2, 2);
        gbc.fill = GridBagConstraints.BOTH;
		gbc.weightx = 1;
		gbc.weighty = 1;
		int row = 0, col = 0;


		String[] operators = {"AND", "OR", 
							  "XOR", "NOT", 
							  "NOR", "MOD", 
							  "RoR", "RoL",
							  "<<", ">>", 
							  "+/-" };

		for (String op : operators) {
			JButton btn = new JButton(op);
			btn.setMargin(new Insets(8, 6, 8, 6));
			btn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
            btn.addActionListener(e -> performOperation(op));
			gbc.gridx = col;
			gbc.gridy = row;
			operationsPanel.add(btn, gbc);

			col++;
            if (col > 1) {
                col = 0;
                row++;
            }
		}

		return operationsPanel;
	}

	/**
	 * Create the increment/decrement and bitwise operations panel
	 */
	private JPanel createIncrementPanel() {
		JPanel panel = new JPanel(new GridLayout(2, 4, 2, 2));
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
	 * Append a digit to the current number
	 */
	private void appendDigit(String digit) {
		if (calculatorLogic.isNewNumber()) {
			calculatorLogic.setCurrentValue(BigInteger.ZERO);
			calculatorLogic.setNewNumber(false);
		}
		
		// Validate digit for current input mode
		int digitValue;
		try {
			switch (calculatorLogic.getInputMode()) {
				case "HEX":
					digitValue = Integer.parseInt(digit, 16);
					calculatorLogic.setCurrentValue(calculatorLogic.getCurrentValue().multiply(BigInteger.valueOf(16)).add(BigInteger.valueOf(digitValue)));
					break;
				case "DEC":
					if (digit.matches("[0-9]")) {
						digitValue = Integer.parseInt(digit, 10);
						calculatorLogic.setCurrentValue(calculatorLogic.getCurrentValue().multiply(BigInteger.valueOf(10)).add(BigInteger.valueOf(digitValue)));
					}
					break;
				case "BIN":
					if (digit.matches("[01]")) {
						digitValue = Integer.parseInt(digit, 2);
						calculatorLogic.setCurrentValue(calculatorLogic.getCurrentValue().multiply(BigInteger.valueOf(2)).add(BigInteger.valueOf(digitValue)));
					}
					break;
				case "OCT":
					if (digit.matches("[0-7]")) {
						digitValue = Integer.parseInt(digit, 8);
						calculatorLogic.setCurrentValue(calculatorLogic.getCurrentValue().multiply(BigInteger.valueOf(8)).add(BigInteger.valueOf(digitValue)));
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
	 * Perform operation for specified operator
	 */
	private void performOperation(String op) {
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
	 * Calculate distance from current address to marked address
	 */
	public void calculateDistanceToMarked(long currentAddress) {
		calculatorLogic.calculateDistanceToMarked(currentAddress);
		updateDisplay();
		
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

		markedValueLabel.setText("Marked Value: " + sign + "0x" + markedValue.abs().toString(16).toUpperCase());
	}

	/**
	 * Recall the marked value
	 */
	public void recallMarkedValue() {
		calculatorLogic.recallMarkedValue();
		updateDisplay();
	}

	/**
	 * Add a value to the calculator (used by context menu actions)
	 */
	public void addValue(BigInteger value) {
		calculatorLogic.setCurrentValue(value);
		calculatorLogic.setNewNumber(true);
		updateDisplay();
	}

	/**
	 * Mark an address for distance calculation
	 */
	public void markAddress(long address) {
		calculatorLogic.setMarkedAddress(address);
		markedAddressLabel.setText("Marked Address: 0x" + Long.toHexString(address).toUpperCase());
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

		markedValueLabel.setText("Marked Value: " + sign + "0x" + markedValue.abs().toString(16).toUpperCase());
	}

	/**
	 * Perform operation between current value and marked value
	 */
	public void performMarkedValueOperation(BigInteger currentMemValue, String operation) {
		calculatorLogic.performMarkedValueOperation(currentMemValue, operation);
		updateDisplay();
		
		// Show detailed operation information
		BigInteger markedValue = calculatorLogic.getMarkedValue();
		if (markedValue != null) {
			BigInteger result = calculatorLogic.getCurrentValue();
			String operationSymbol = "";
			
			switch (operation) {
				case "add":
					operationSymbol = "+";
					break;
				case "subtract":
					operationSymbol = "-";
					break;
				case "xor":
					operationSymbol = "XOR";
					break;
			}
			
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
		}
	}

	/**
	 * Clear marked values and addresses
	 */
	private void clearMark() {
		calculatorLogic.clearMark();
		// Update UI
		markedValueLabel.setText("Marked Value: None");
		markedAddressLabel.setText("Marked Address: None");
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
	 * Perform the equals operation
	 */
	public void performEquals() {
		calculatorLogic.performEquals();
		updateDisplay();
	}

	/**
	 * Flip sign of current value
	 */
	private void flipSign() {
		calculatorLogic.flipSign();
		updateDisplay();
	}

	/**
	 * Clear the calculator
	 */
	public void clearCalculator() {
		calculatorLogic.clearCalculator();
		updateDisplay();
	}

	/**
	 * Increment the current value by the specified amount
	 */
	private void increment(BigInteger amount) {
		calculatorLogic.increment(amount);
		updateDisplay();
	}

	/**
	 * Perform bitwise NOT operation
	 */
	public void bitwiseNot() {
		calculatorLogic.bitwiseNot();
		updateDisplay();
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
	 * Set the current operation
	 */
	public void setOperation(String operation) {
		calculatorLogic.setOperation(operation);
	}

	/**
	 * Update the display with current value in all number bases
	 */
	public void updateDisplay() {
		displayManager.updateDisplay();
	}

	/**
	 * Navigate to an address if the value represents a valid address
	 */
	public void navigateToAddress(BigInteger value) {
		addressNavigator.navigateToAddress(value);
	}

	/**
	 * Add a value to the history
	 */
	public void addToHistory(BigInteger value, String operation) {
		plugin.getHistoryProvider().addToHistory(value, operation);
	}
}
