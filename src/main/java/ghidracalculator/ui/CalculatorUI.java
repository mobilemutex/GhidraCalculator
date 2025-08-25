package ghidracalculator.ui;

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.KeyListener;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import javax.swing.*;

import generic.theme.GThemeDefaults;
import ghidracalculator.CalculatorLogic;
import ghidracalculator.CalculatorProvider;
import ghidracalculator.CalculatorModel;
import ghidracalculator.CalculatorPlugin;

/**
 * Calculator UI
 *
 * This class handles all UI building for the calculator.
 */
public class CalculatorUI extends JPanel implements CalculatorModel.CalculatorModelListener{
	
    private CalculatorPlugin plugin;
	private CalculatorProvider provider;
	private CalculatorLogic calculatorLogic;
	
	// GUI Components
	private JTextField displayField;
	private JLabel hexModeLabel, decModeLabel, octModeLabel, binModeLabel;
	public JLabel hexValueLabel, decValueLabel, octValueLabel, binValueLabel;
	public JLabel markedValueLabel, markedAddressLabel;
	private Map<String, JLabel> modeLabels, valueLabels;
	
	/**
	 * Constructor
	 * @param provider The calculator provider instance
	 */
	public CalculatorUI(CalculatorPlugin calculatorPlugin, CalculatorProvider provider, CalculatorLogic calculatorLogic) {
        super(new BorderLayout());
        this.plugin = calculatorPlugin;
		this.provider = provider;
		this.calculatorLogic = calculatorLogic;
		
		// Initialize maps
		modeLabels = new HashMap<>();
		valueLabels = new HashMap<>();
		
		// Register as listener to the model
		calculatorLogic.getModel().addCalculatorModelListener(this);

		initializeUI();
	}

	public Map<String, JLabel> getModeLabels() {
		return modeLabels;
	}

	public JComponent getComponent() {
		return this;
	}
	
	/**
	 * Gets the display field
	 * @return the display field
	 */
	public JTextField getDisplayField() {
		return displayField;
	}
	
	/**
	 * Build the main calculator panel
	 */
	private void initializeUI() {
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

        add(mainPanel, BorderLayout.CENTER);
        
        // Initialize display with default values
        updateDisplay();
        
        // Set initial mode highlighting to HEX
        modeLabels.get("HEX").setBorder(BorderFactory.createMatteBorder(0, 3, 0, 0, GThemeDefaults.Colors.Palette.BLUE));
 }
	
	/**
	 * Create the display panel with multi-base output
	 */
	private JPanel createDisplayPanel() {
		hexModeLabel = createModeLabel("HEX:   ");
		decModeLabel = createModeLabel("DEC:   ");
		octModeLabel = createModeLabel("OCT:   ");
		binModeLabel = createModeLabel("BIN:   ");

		hexValueLabel = createValueLabel();
		decValueLabel = createValueLabel();
		octValueLabel = createValueLabel();
		binValueLabel = createValueLabel();

		modeLabels.put("HEX", hexModeLabel);
		modeLabels.put("DEC", decModeLabel);
		modeLabels.put("OCT", octModeLabel);
		modeLabels.put("BIN", binModeLabel);

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
				btn.addActionListener(e -> calculatorLogic.performOperation(op));
				btn.setMargin(new Insets(6, 6, 6, 6));
				btn.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
				basicPanel.add(btn, gbc);
			} else {
				String num = numbers[col + (row * 3)];
				JButton btn = new JButton(num);
				btn.addActionListener(e -> calculatorLogic.appendDigit(num));
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
		btn.addActionListener(e -> calculatorLogic.appendDigit(num));
		basicPanel.add(btn, gbc);

		gbc.gridx = 2;
		gbc.gridwidth = 2;
		String eq = lastRow[1]; // =
		btn = new JButton(eq);
		btn.addActionListener(e -> calculatorLogic.performOperation(eq));
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
            btn.addActionListener(e -> calculatorLogic.performOperation(op));
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
		panel.add(createButton("+1", e -> calculatorLogic.increment(BigInteger.ONE)));
		panel.add(createButton("+0x10", e -> calculatorLogic.increment(BigInteger.valueOf(0x10))));
		panel.add(createButton("+0x100", e -> calculatorLogic.increment(BigInteger.valueOf(0x100))));
		panel.add(createButton("+0x1000", e -> calculatorLogic.increment(BigInteger.valueOf(0x1000))));
		
		// Row 2: Decrement operations
		panel.add(createButton("-1", e -> calculatorLogic.increment(BigInteger.ONE.negate())));
		panel.add(createButton("-0x10", e -> calculatorLogic.increment(BigInteger.valueOf(-0x10))));
		panel.add(createButton("-0x100", e -> calculatorLogic.increment(BigInteger.valueOf(-0x100))));
		panel.add(createButton("-0x1000", e -> calculatorLogic.increment(BigInteger.valueOf(-0x1000))));
		
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

	/**
	    * Show context menu for the display field
	    */
	   public void showDisplayContextMenu(MouseEvent e) {
	       JPopupMenu popup = new JPopupMenu();
	       BigInteger currentValue = calculatorLogic.getCurrentValue();
	       
	       // Jump to Address option (only if valid address)
	       if (isValidAddress(currentValue)) {
	           JMenuItem jumpItem = new JMenuItem("Jump to Address");
	           jumpItem.setToolTipText("Navigate to 0x" + currentValue.toString(16).toUpperCase() + " in the listing");
	           jumpItem.addActionListener(evt -> provider.navigateToAddress(currentValue));
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
	       
	       // Mark Value option
	       JMenuItem markValueItem = new JMenuItem("Mark Value");
	       markValueItem.addActionListener(evt -> provider.markCurrentValue());
	       popup.add(markValueItem);
	       
	       // Recall Value option
	       if (provider.hasMarkedValue()) {
	           JMenuItem recallValueItem = new JMenuItem("Recall Value");
	           recallValueItem.addActionListener(evt -> provider.recallMarkedValue());
	           popup.add(recallValueItem);
	       }
	       
	       // Only show popup if it has items
	       if (popup.getComponentCount() > 0) {
	           popup.show(displayField, e.getX(), e.getY());
	       }
	   }

	/**
     * Parse the input from the display field and update the calculator value
     */
    public void parseDisplayInput() {
        String input = displayField.getText().trim();
        if (input.isEmpty()) {
            return;
        }

        try {
            BigInteger value = provider.parseInputValue(input);
            calculatorLogic.setCurrentValue(value);
            calculatorLogic.setNewNumber(true);
            updateDisplay();
        } catch (NumberFormatException e) {
            // Invalid input, show error briefly
            String originalText = displayField.getText();
            displayField.setText("ERROR");
            displayField.setBackground(GThemeDefaults.Colors.Palette.PINK);
            
            // Reset after 1 second
            Timer timer = new Timer(1000, evt -> {
                displayField.setText(originalText);
                displayField.setBackground(GThemeDefaults.Colors.BACKGROUND);
            });
            timer.setRepeats(false);
            timer.start();
        }
    }

	public void setCurrentMode(String mode) {
		Map<String, JLabel> modeLabels = getModeLabels();

        // Update highlighting
        modeLabels.get(calculatorLogic.getInputMode()).setBorder(BorderFactory.createMatteBorder(0, 3, 0, 0, GThemeDefaults.Colors.Viewport.UNEDITABLE_BACKGROUND));
		modeLabels.get(mode).setBorder(BorderFactory.createMatteBorder(0,3,0,0,GThemeDefaults.Colors.Palette.BLUE));
        
        calculatorLogic.setInputMode(mode);
    }

	public void setValueLabels(BigInteger currentValue, String sign) {
		 // Update multi-base labels
        hexValueLabel.setText(sign + "0x" + currentValue.abs().toString(16).toUpperCase());
        decValueLabel.setText(currentValue.toString(10));
        octValueLabel.setText(sign + "0" + currentValue.abs().toString(8));

		// Binary Display: Pad to 4-bit alignment and add spaces
        String binaryStr = currentValue.abs().toString(2);
        int padLen = (4 - (binaryStr.length() % 4)) % 4;
        String paddedBinary = "0".repeat(padLen) + binaryStr;
        String binFormatted = paddedBinary.replaceAll("(.{4})", "$1 ").trim();
        binValueLabel.setText(sign + binFormatted);
	}

	/**
     * Update the display with current value in all number bases
     */
    public void updateDisplay() {
        // Update main display field based on input mode
        String displayText;
        String sign;
        BigInteger currentValue = calculatorLogic.getCurrentValue();

        if (currentValue.signum() == -1) {
            sign = "-";
        } else {
            sign = "";
        }

        switch (calculatorLogic.getInputMode()) {
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
        displayField.setText(displayText);
        
        // Update multi-base labels
        setValueLabels(currentValue, sign);
        
        // Update address validation info in tooltip
        String addressInfo = getAddressInfo(currentValue);
        displayField.setToolTipText(addressInfo);
    }
    
    /**
	* Get address information for the current value
	*/
	private String getAddressInfo(BigInteger value) {
		try {
			if (plugin.getCurrentProgram() == null) {
				return "No program loaded";
			}
			
			var addressFactory = plugin.getCurrentProgram().getAddressFactory();
			var address = addressFactory.getDefaultAddressSpace().getAddress(value.longValue());
			
			if (plugin.getCurrentProgram().getMemory().contains(address)) {
				return String.format("Valid address: %s", address.toString());
			} else {
				return "Address not in program memory";
			}
		} catch (Exception e) {
			return "Invalid address format";
		}
       }
       
       /**
        * Check if a value represents a valid address in the current program
        */
       private boolean isValidAddress(BigInteger value) {
           try {
               if (plugin.getCurrentProgram() == null) {
                   return false;
               }
               
               var addressFactory = plugin.getCurrentProgram().getAddressFactory();
               var address = addressFactory.getDefaultAddressSpace().getAddress(value.longValue());
               
               return plugin.getCurrentProgram().getMemory().contains(address);
           } catch (Exception e) {
               return false;
           }
       }

	/**
     * Copy current value to clipboard
     */
    public void copyValueToClipboard() {
        try {
            String value = displayField.getText();
            StringSelection selection = new StringSelection(value);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            
            // Show brief feedback
            displayField.setToolTipText("Value copied to clipboard: " + value);
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
                displayField.setText(clipboardText.trim());
                provider.parseInputValue(clipboardText.trim());
                parseDisplayInput();
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                "Error pasting from clipboard: " + ex.getMessage(),
                "Paste Error",
                JOptionPane.ERROR_MESSAGE);
        }
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
     * Handle model changes and update the UI accordingly
     */
    @Override
    public void modelChanged(CalculatorModel.CalculatorModelEvent event) {
        // Update the display when the model changes
        updateDisplay();
    }
    
    @Override
    public void modelError(CalculatorModel.CalculatorModelErrorEvent event) {
        JOptionPane.showMessageDialog(this, event.getErrorMessage(), "Error", JOptionPane.ERROR_MESSAGE);
    }
}
