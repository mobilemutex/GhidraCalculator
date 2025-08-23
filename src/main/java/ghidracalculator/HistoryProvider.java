package ghidracalculator;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;

import docking.ComponentProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidracalculator.resources.GhidraCalcIcons;

public class HistoryProvider extends ComponentProvider{
    private CalculatorPlugin plugin;

    // History window components
    private JComponent historyPanel;
	private JList<String> historyList;
	private DefaultListModel<String> historyModel;
	private List<BigInteger> historyValues;
    
    /**
	 * Constructor
	 * 
	 */
	public HistoryProvider(CalculatorPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
        this.plugin = plugin;

		// Initialize history components
		historyModel = new DefaultListModel<>();
		historyValues = new ArrayList<>();

		
		setTitle("Calculator History");
		setWindowMenuGroup("Calculator");
		setIcon(GhidraCalcIcons.GHIDRACALC_ICON);

		// Create history window
		historyPanel = createHistoryComponent();
        setDefaultWindowPosition(docking.WindowPosition.BOTTOM);
		
		// Set the component
		setVisible(true);
	}

    @Override
    public JComponent getComponent() {
        return historyPanel;
    }

    /**
	 * Create the history window component
	 */
	private JComponent createHistoryComponent() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder("Calculator History"));
		
		// Create history list
		historyList = new JList<>(historyModel);
		historyList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		historyList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		
		// Add double-click listener for address navigation
		historyList.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					int index = historyList.locationToIndex(e.getPoint());
					if (index >= 0 && index < historyValues.size()) {
						BigInteger value = historyValues.get(index);

						// Only attempt to navigate to address if it's a valid address
						AddressFactory addressFactory = plugin.getCurrentProgram().getAddressFactory();
						Address address = addressFactory.getDefaultAddressSpace().getAddress(value.longValue());

						if (plugin.getCurrentProgram().getMemory().contains(address)) {
							plugin.getProvider().navigateToAddress(value);
						}
					}
				}
			}
		});
		
		// Add scroll pane
		JScrollPane scrollPane = new JScrollPane(historyList);
		scrollPane.setPreferredSize(new Dimension(300, 200));
		panel.add(scrollPane, BorderLayout.CENTER);
		
		// Add control buttons
		JPanel buttonPanel = new JPanel(new FlowLayout());
		
		JButton clearHistoryButton = new JButton("Clear History");
		clearHistoryButton.addActionListener(e -> clearHistory());
		buttonPanel.add(clearHistoryButton);
		
		JButton loadValueButton = new JButton("Load Selected");
		loadValueButton.addActionListener(e -> loadSelectedHistoryValue());
		buttonPanel.add(loadValueButton);
		
		panel.add(buttonPanel, BorderLayout.SOUTH);
		
		return panel;
	}   

	/**
	 * Toggle the history window visibility
	 */
	protected void toggleHistoryWindow() {
		if (this.isVisible()) {
			plugin.getTool().removeComponentProvider(this);
		} else {
			plugin.getTool().addComponentProvider(this, false);
		}
	}

    /**
	 * Add a value to the history
	 */
	protected void addToHistory(BigInteger value, String operation) {
		String historyEntry = String.format("%s = 0x%s (%s)", 
			operation, 
			value.toString(16).toUpperCase(), 
			value.toString(10));
		
		historyModel.addElement(historyEntry);
		historyValues.add(value);
		
		// Limit history size to 100 entries
		if (historyModel.size() > 100) {
			historyModel.removeElementAt(0);
			historyValues.remove(0);
		}
		
		// Auto-scroll to bottom
		if (historyList != null) {
			historyList.ensureIndexIsVisible(historyModel.size() - 1);
		}
	}

    /**
	 * Clear the history
	 */
	private void clearHistory() {
		historyModel.clear();
		historyValues.clear();
	}

	/**
	 * Load the selected history value into the calculator
	 */
	public void loadSelectedHistoryValue() {
		int selectedIndex = historyList.getSelectedIndex();
		if (selectedIndex >= 0 && selectedIndex < historyValues.size()) {
			BigInteger value = historyValues.get(selectedIndex);
			plugin.getProvider().getCalculatorLogic().setCurrentValue(value);
            plugin.getProvider().getCalculatorLogic().setNewNumber(true);
			plugin.getProvider().getUI().updateDisplay();
		}
	}


}