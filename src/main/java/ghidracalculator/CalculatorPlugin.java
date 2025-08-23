package ghidracalculator;

import docking.action.DockingAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidracalculator.actions.AddAddressAction;
import ghidracalculator.actions.AddDecompilerConstantAction;
import ghidracalculator.actions.AddMemoryAction;
import ghidracalculator.actions.CalculateDistanceAction;
import ghidracalculator.actions.MarkAddressAction;
import ghidracalculator.actions.MarkDecompilerConstantAction;
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
	final static String CALC_ADD = "CalculatorAdd";
	final static String CALC_MARK = "CalculatorMark";
	final static String CALC_ADDRESS = "CalculatorAddress";
	final static String CALC_SCALAR = "CalculatorScalar";

	private DockingAction addAddressAction;
	private DockingAction addMemoryValueAction;
	private DockingAction markAddressAction;
	private DockingAction calculateDistanceAction;
	private DockingAction addScalarAction;
	private DockingAction markScalarAction;
	private DockingAction addToMarkedScalarAction;
	private DockingAction subtractFromMarkedScalarAction;
	private DockingAction xorWithMarkedScalarAction;
	private DockingAction addDecompilerConstant;
	private DockingAction markDecompilerConstant;

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
		addAddressAction = new AddAddressAction(this, CALC_ADD);
		addMemoryValueAction = new AddMemoryAction(this, CALC_ADD);
		markAddressAction = new MarkAddressAction(this, CALC_MARK);
		calculateDistanceAction = new CalculateDistanceAction(this, CALC_ADDRESS);
		addScalarAction = new AddScalarAction(this, "Add scalar operand to Calculator", CALC_ADD);
		markScalarAction = new MarkScalarAction(this, "Mark scalar operand", CALC_MARK);
		addToMarkedScalarAction = new PerformMarkedScalarOperationAction(this, provider.getCalculatorLogic(), "Add to marked scalar operand", "add", CALC_SCALAR);
		subtractFromMarkedScalarAction = new PerformMarkedScalarOperationAction(this, provider.getCalculatorLogic(), "Subtract from marked scalar operand", "subtract", CALC_SCALAR);
		xorWithMarkedScalarAction = new PerformMarkedScalarOperationAction(this, provider.getCalculatorLogic(), "XOR with marked scalar operand", "xor", CALC_SCALAR);
		addDecompilerConstant = new AddDecompilerConstantAction(this);
		markDecompilerConstant = new MarkDecompilerConstantAction(this);

		tool.addAction(addAddressAction);
		tool.addAction(addMemoryValueAction);
		tool.addAction(markAddressAction);
		tool.addAction(calculateDistanceAction);
		tool.addAction(addScalarAction);
		tool.addAction(markScalarAction);
		tool.addAction(addToMarkedScalarAction);
		tool.addAction(subtractFromMarkedScalarAction);
		tool.addAction(xorWithMarkedScalarAction);
		tool.addAction(addDecompilerConstant);
		tool.addAction(markDecompilerConstant);
	}

	/**
	 * Get the calculator provider for this plugin
	 * @return the calculator provider
	 */
	public CalculatorProvider getProvider() {
		return provider;
	}
}