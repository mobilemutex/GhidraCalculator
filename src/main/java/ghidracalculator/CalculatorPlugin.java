package ghidracalculator;

import java.math.BigInteger;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.HelpLocation;

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
		// Action to add address value to calculator
		DockingAction addAddressAction = new DockingAction("Add Address to Calculator", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				addAddressToCalculator(context);
			}
			
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context instanceof ListingActionContext && 
					   ((ListingActionContext) context).getAddress() != null;
			}
		};
		addAddressAction.setPopupMenuData(new MenuData(new String[] { "Calculator", "Add Address to Calculator" }));
		addAddressAction.setHelpLocation(new HelpLocation("Calculator", "AddAddress"));
		tool.addAction(addAddressAction);

		// Action to add memory value to calculator
		DockingAction addMemoryValueAction = new DockingAction("Add Memory Value to Calculator", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				addMemoryValueToCalculator(context);
			}
			
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context instanceof ListingActionContext && 
					   ((ListingActionContext) context).getAddress() != null &&
					   getCurrentProgram() != null;
			}
		};
		addMemoryValueAction.setPopupMenuData(new MenuData(new String[] { "Calculator", "Add Memory Value to Calculator" }));
		addMemoryValueAction.setHelpLocation(new HelpLocation("Calculator", "AddMemoryValue"));
		tool.addAction(addMemoryValueAction);

		// Action to add constant value to calculator
		DockingAction addConstantValueAction = new DockingAction("Add Constant Value to Calculator", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				addConstantValueToCalculator(context);
			}
			
			// TODO: Update this to allow for choosing between multiple constants in an instruction
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (context instanceof ListingActionContext) {
					Instruction instruction = getCurrentProgram().getListing().getInstructionAt(((ListingActionContext) context).getAddress());
					if (instruction != null) {
						int numOperands = instruction.getNumOperands();
						for (int i = 0; i < numOperands; i++) {
							Object[] opObjects = instruction.getOpObjects(i);
							for (Object obj : opObjects) {
								if (obj instanceof Scalar) {
									return true;
								}
							}
						}
					}
				}
				return false;
			}
		};
		addConstantValueAction.setPopupMenuData(new MenuData(new String[] { "Calculator", "Add Constant Value to Calculator" }));
		addConstantValueAction.setHelpLocation(new HelpLocation("Calculator", "AddConstantValue"));
		tool.addAction(addConstantValueAction);

		// Action to mark address for distance calculation
		DockingAction markAddressAction = new DockingAction("Mark Address for Distance", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				markAddressForDistance(context);
			}
			
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context instanceof ListingActionContext && 
					   ((ListingActionContext) context).getAddress() != null;
			}
		};
		markAddressAction.setPopupMenuData(new MenuData(new String[] { "Calculator", "Mark Address for Distance" }));
		markAddressAction.setHelpLocation(new HelpLocation("Calculator", "MarkAddress"));
		tool.addAction(markAddressAction);

		// Action to calculate distance to marked address
		DockingAction distanceAction = new DockingAction("Calculate Distance to Marked", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				calculateDistanceToMarked(context);
			}
			
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context instanceof ListingActionContext && 
					   ((ListingActionContext) context).getAddress() != null &&
					   provider.hasMarkedAddress();
			}
		};
		distanceAction.setPopupMenuData(new MenuData(new String[] { "Calculator", "Calculate Distance to Marked" }));
		distanceAction.setHelpLocation(new HelpLocation("Calculator", "CalculateDistance"));
		tool.addAction(distanceAction);

		// Mark value for comparison
		DockingAction markValueAction = new DockingAction("Mark Value for Comparison", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				markValueForComparison(context);
			}
			
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context instanceof ListingActionContext && 
					   ((ListingActionContext) context).getAddress() != null &&
					   getCurrentProgram() != null;
			}
		};
		markValueAction.setPopupMenuData(new MenuData(new String[] { "Calculator", "Mark Value for Comparison" }));
		markValueAction.setHelpLocation(new HelpLocation("Calculator", "MarkValue"));
		tool.addAction(markValueAction);

		// Add to marked value
		DockingAction addToMarkedAction = new DockingAction("Add to Marked Value", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				performMarkedValueOperation(context, "add");
			}
			
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context instanceof ListingActionContext && 
					   ((ListingActionContext) context).getAddress() != null &&
					   getCurrentProgram() != null && provider.hasMarkedValue();
			}
		};
		addToMarkedAction.setPopupMenuData(new MenuData(new String[] { "Calculator", "Add to Marked Value" }));
		addToMarkedAction.setHelpLocation(new HelpLocation("Calculator", "AddToMarked"));
		tool.addAction(addToMarkedAction);

		// Subtract from marked value
		DockingAction subtractFromMarkedAction = new DockingAction("Subtract from Marked Value", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				performMarkedValueOperation(context, "subtract");
			}
			
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context instanceof ListingActionContext && 
					   ((ListingActionContext) context).getAddress() != null &&
					   getCurrentProgram() != null && provider.hasMarkedValue();
			}
		};
		subtractFromMarkedAction.setPopupMenuData(new MenuData(new String[] { "Calculator", "Subtract from Marked Value" }));
		subtractFromMarkedAction.setHelpLocation(new HelpLocation("Calculator", "SubtractFromMarked"));
		tool.addAction(subtractFromMarkedAction);

		// XOR with marked value
		DockingAction xorWithMarkedAction = new DockingAction("XOR with Marked Value", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				performMarkedValueOperation(context, "xor");
			}
			
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context instanceof ListingActionContext && 
					   ((ListingActionContext) context).getAddress() != null &&
					   getCurrentProgram() != null && provider.hasMarkedValue();
			}
		};
		xorWithMarkedAction.setPopupMenuData(new MenuData(new String[] { "Calculator", "XOR with Marked Value" }));
		xorWithMarkedAction.setHelpLocation(new HelpLocation("Calculator", "XorWithMarked"));
		tool.addAction(xorWithMarkedAction);
	}

	/**
	 * Action method: Add the selected address value to the calculator
	 */
	private void addAddressToCalculator(ActionContext context) {
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			Address address = listingContext.getAddress();
			if (address != null) {
				BigInteger addressValue = new BigInteger(address.toString(false), 16);
				provider.addValue(addressValue);
			}
		}
	}

	/**
	 * Action method: Add the memory value at the selected address to the calculator
	 */
	private void addMemoryValueToCalculator(ActionContext context) {
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			Address address = listingContext.getAddress();
			Program program = getCurrentProgram();
			
			if (address != null && program != null) {
				try {
					Memory memory = program.getMemory();
					// Try to read different sizes and let user choose or use a reasonable default
					byte[] bytes = new byte[8]; // Read up to 8 bytes
					int bytesRead = memory.getBytes(address, bytes);
					
					if (bytesRead > 0) {
						// Convert bytes to BigInteger (little-endian interpretation)
						BigInteger value = BigInteger.ZERO;
						for (int i = Math.min(bytesRead, 4) - 1; i >= 0; i--) {
							value = value.shiftLeft(8).or(BigInteger.valueOf(bytes[i] & 0xFF));
						}
						provider.addValue(value);
					}
				} catch (MemoryAccessException e) {
					// If we can't read memory, just use the address value
					BigInteger addressValue = new BigInteger(address.toString(false), 16);
					provider.addValue(addressValue);
				}
			}
		}
	}

	/**
	 * Action method: Add the constant value at the selected address to the calculator
	 */
	private void addConstantValueToCalculator(ActionContext context) {
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			Address address = listingContext.getAddress();
			Program program = getCurrentProgram();
			
			if (address != null && program != null) {
				try {
					Listing listing = program.getListing();
					Instruction instruction = listing.getInstructionAt(address);
					if (instruction != null) {
						int numOperands = instruction.getNumOperands();
						for (int i = 0; i< numOperands; i++) {
							Object[] opObjects = instruction.getOpObjects(i);
							for (Object obj : opObjects) {
								if (obj instanceof Scalar) {
									Scalar scalar = (Scalar) obj;
									BigInteger value = BigInteger.valueOf(scalar.getValue());
									provider.addValue(value);
									return;
								}
							}
						}
					}

					Memory memory = program.getMemory();
					// Try to read different sizes and let user choose or use a reasonable default
					byte[] bytes = new byte[8]; // Read up to 8 bytes
					int bytesRead = memory.getBytes(address, bytes);
					
					if (bytesRead > 0) {
						// Convert bytes to BigInteger (little-endian interpretation)
						BigInteger value = BigInteger.ZERO;
						for (int i = Math.min(bytesRead, 4) - 1; i >= 0; i--) {
							value = value.shiftLeft(8).or(BigInteger.valueOf(bytes[i] & 0xFF));
						}
						provider.addValue(value);
					}
				} catch (MemoryAccessException e) {
					// If we can't read memory, just use the address value
					BigInteger addressValue = new BigInteger(address.toString(false), 16);
					provider.addValue(addressValue);
				}
			}
		}
	}

	/**
	 * Action method: Mark the selected address for distance calculation
	 */
	private void markAddressForDistance(ActionContext context) {
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			Address address = listingContext.getAddress();
			if (address != null) {
				long addressOffset = address.getOffset();
				provider.markAddress(addressOffset);
			}
		}
	}

	/**
	 * Action method: Calculate distance from current address to marked address
	 */
	private void calculateDistanceToMarked(ActionContext context) {
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			Address address = listingContext.getAddress();
			if (address != null) {
				long currentOffset = address.getOffset();
				provider.calculateDistanceToMarked(currentOffset);
			}
		}
	}

	/**
	 * Bonus Feature: Mark a memory value for comparison operations
	 */
	private void markValueForComparison(ActionContext context) {
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			Address address = listingContext.getAddress();
			Program program = getCurrentProgram();
			
			if (address != null && program != null) {
				try {
					Memory memory = program.getMemory();
					byte[] bytes = new byte[8];
					int bytesRead = memory.getBytes(address, bytes);
					
					if (bytesRead > 0) {
						BigInteger value = BigInteger.ZERO;
						for (int i = Math.min(bytesRead, 4) - 1; i >= 0; i--) {
							value = value.shiftLeft(8).or(BigInteger.valueOf(bytes[i] & 0xFF));
						}
						provider.markValueForComparison(value);
					}
				} catch (MemoryAccessException e) {
					// If we can't read memory, use address value
					BigInteger addressValue = new BigInteger(address.toString(false), 16);
					provider.markValueForComparison(addressValue);
				}
			}
		}
	}

	/**
	 * Perform operation between current memory value and marked value
	 */
	private void performMarkedValueOperation(ActionContext context, String operation) {
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			Address address = listingContext.getAddress();
			Program program = getCurrentProgram();
			
			if (address != null && program != null) {
				try {
					Memory memory = program.getMemory();
					byte[] bytes = new byte[8];
					int bytesRead = memory.getBytes(address, bytes);
					
					if (bytesRead > 0) {
						BigInteger currentValue = BigInteger.ZERO;
						for (int i = Math.min(bytesRead, 4) - 1; i >= 0; i--) {
							currentValue = currentValue.shiftLeft(8).or(BigInteger.valueOf(bytes[i] & 0xFF));
						}
						provider.performMarkedValueOperation(currentValue, operation);
					}
				} catch (MemoryAccessException e) {
					// If we can't read memory, use address value
					BigInteger addressValue = new BigInteger(address.toString(false), 16);
					provider.performMarkedValueOperation(addressValue, operation);
				}
			}
		}
	}

	/**
	 * Get the calculator provider for this plugin
	 * @return the calculator provider
	 */
	public CalculatorProvider getProvider() {
		return provider;
	}
}