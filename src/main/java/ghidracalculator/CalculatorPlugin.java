package ghidracalculator;

import docking.action.DockingAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidracalculator.actions.AddAddressAction;
import ghidracalculator.actions.AddMemoryAction;
import ghidracalculator.actions.CalculateDistanceAction;
import ghidracalculator.actions.MarkAddressAction;
import ghidracalculator.actions.MarkScalarAction;
import ghidracalculator.actions.AddScalarAction;
import ghidracalculator.actions.PerformMarkedScalarOperationAction;

@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = "GhidraCalculator",
	category = PluginCategoryNames.COMMON,
	shortDescription = "Calculator for Ghidra",
	description = "A calculator with multi-base display, bitwise operations, " +
				  "and integration with Ghidra's disassembler view. " +
				  "Supports context menu operations for adding values and addresses, marking for " +
				  "comparison, and calculating distances between addresses."
)
public class CalculatorPlugin extends ProgramPlugin {

	private CalculatorProvider provider;
	protected HistoryProvider historyProvider;
	final static String GROUP_NAME = "Calculator";

	private DockingAction addAddressAction;
	private DockingAction addMemoryValueAction;
	private DockingAction markAddressAction;
	private DockingAction calculateDistanceAction;
	private DockingAction addScalarAction1;
	private DockingAction addScalarAction2;
	private DockingAction addScalarAction3;
	private DockingAction markScalarAction1;
	private DockingAction markScalarAction2;
	private DockingAction markScalarAction3;
	private DockingAction addToMarkedScalarAction1;
	private DockingAction addToMarkedScalarAction2;
	private DockingAction addToMarkedScalarAction3;
	private DockingAction subtractFromMarkedScalarAction1;
	private DockingAction subtractFromMarkedScalarAction2;
	private DockingAction subtractFromMarkedScalarAction3;
	private DockingAction xorWithMarkedScalarAction1;
	private DockingAction xorWithMarkedScalarAction2;
	private DockingAction xorWithMarkedScalarAction3;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public CalculatorPlugin(PluginTool tool) {
		super(tool);
		String pluginName = getName();
		
		// Create the calculator provider (dockable window)
		provider = new CalculatorProvider(this, pluginName);
		historyProvider = new HistoryProvider(this, pluginName);
	}

	@Override
	public void init() {
		super.init();
		
		// Create context menu actions for disassembler integration
		createContextMenuActions();
	}

	public HistoryProvider getHistoryProvider() {
		return historyProvider;
	}

	/**
	 * Create context menu actions for integration with Ghidra's listing windows
	 */
	private void createContextMenuActions() {
		
		addAddressAction = new AddAddressAction(this, "CalculatorAdd");
		addMemoryValueAction = new AddMemoryAction(this, "CalculatorAdd");
		markAddressAction = new MarkAddressAction(this, "CalculatorMark");
		calculateDistanceAction = new CalculateDistanceAction(this, "CalculatorAddress");

		// Hard-coding actions for up to 3 operands until I figure out a way to do this dynamically
		addScalarAction1 = new AddScalarAction(this, "Add scalar operand 0 to Calculator", 0, "CalculatorAdd");
		addScalarAction2 = new AddScalarAction(this, "Add scalar operand 1 to Calculator", 1, "CalculatorAdd");
		addScalarAction3 = new AddScalarAction(this, "Add scalar operand 2 to Calculator", 2, "CalculatorAdd");
		markScalarAction1 = new MarkScalarAction(this, "Mark scalar operand 0", 0, "CalculatorMark");
		markScalarAction2 = new MarkScalarAction(this, "Mark scalar operand 1", 1, "CalculatorMark");
		markScalarAction3 = new MarkScalarAction(this, "Mark scalar operand 2", 2, "CalculatorMark");
		addToMarkedScalarAction1 = new PerformMarkedScalarOperationAction(this, "Add to marked scalar operand 0", "add", 0, "CalculatorScalar");
		addToMarkedScalarAction2 = new PerformMarkedScalarOperationAction(this, "Add to marked scalar operand 1", "add", 1, "CalculatorScalar");
		addToMarkedScalarAction3 = new PerformMarkedScalarOperationAction(this, "Add to marked scalar operand 2", "add", 2, "CalculatorScalar");
		subtractFromMarkedScalarAction1 = new PerformMarkedScalarOperationAction(this, "Subtract from marked scalar operand 0", "subtract", 0, "CalculatorScalar");
		subtractFromMarkedScalarAction2 = new PerformMarkedScalarOperationAction(this, "Subtract from marked scalar operand 1", "subtract", 1, "CalculatorScalar");
		subtractFromMarkedScalarAction3 = new PerformMarkedScalarOperationAction(this, "Subtract from marked scalar operand 2", "subtract", 2, "CalculatorScalar");
		xorWithMarkedScalarAction1 = new PerformMarkedScalarOperationAction(this, "XOR with marked scalar operand 0", "xor", 0, "CalculatorScalar");
		xorWithMarkedScalarAction2 = new PerformMarkedScalarOperationAction(this, "XOR with marked scalar operand 1", "xor", 1, "CalculatorScalar");
		xorWithMarkedScalarAction3 = new PerformMarkedScalarOperationAction(this, "XOR with marked scalar operand 2", "xor", 2, "CalculatorScalar");

		tool.addAction(addAddressAction);
		tool.addAction(addMemoryValueAction);
		tool.addAction(markAddressAction);
		tool.addAction(calculateDistanceAction);
		tool.addAction(addScalarAction1);
		tool.addAction(addScalarAction2);
		tool.addAction(addScalarAction3);
		tool.addAction(markScalarAction1);
		tool.addAction(markScalarAction2);
		tool.addAction(markScalarAction3);
		tool.addAction(addToMarkedScalarAction1);
		tool.addAction(addToMarkedScalarAction2);
		tool.addAction(addToMarkedScalarAction3);
		tool.addAction(subtractFromMarkedScalarAction1);
		tool.addAction(subtractFromMarkedScalarAction2);
		tool.addAction(subtractFromMarkedScalarAction3);
		tool.addAction(xorWithMarkedScalarAction1);
		tool.addAction(xorWithMarkedScalarAction2);
		tool.addAction(xorWithMarkedScalarAction3);
	}

	/**
	 * Get the calculator provider for this plugin
	 * @return the calculator provider
	 */
	public CalculatorProvider getProvider() {
		return provider;
	}
}