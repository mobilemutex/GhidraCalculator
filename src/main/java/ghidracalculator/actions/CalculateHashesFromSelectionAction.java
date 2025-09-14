package ghidracalculator.actions;

import java.math.BigInteger;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramSelection;
import ghidracalculator.CalculatorPlugin;
import ghidracalculator.utils.HashUtils;

public class CalculateHashesFromSelectionAction extends ListingContextAction {
    protected final CalculatorPlugin plugin;
    
    public CalculateHashesFromSelectionAction(CalculatorPlugin plugin, String groupName) {
        super("Calculate Hashes from Selection", plugin.getName());
        this.plugin = plugin;
        setPopupMenuData(new MenuData(new String[] { "Calculator", ""}, groupName));
    }

    @Override
    public void actionPerformed(ActionContext context) {
        if (context instanceof ListingActionContext) {
            ListingActionContext lac = (ListingActionContext) context;
            calculateHashes(lac.getSelection());
        }
    }

    @Override
    public boolean isEnabledForContext(ListingActionContext context) {
        if (context instanceof ListingActionContext) {
            ProgramSelection selection =
                ((ListingActionContext) context).getNavigatable().getSelection();

            if (selection != null && selection.getNumAddressRanges() == 1) {
                String menuName = "Calculate Hashes from selection";
                getPopupMenuData().setMenuItemNamePlain(menuName);

                return true;
            }
        }
        return false;
    }

    public void calculateHashes(ProgramSelection selection) {
        // Get start address and length from selection
        BigInteger startAddress = selection.getMinAddress().getOffsetAsBigInteger();
        int length = (int) selection.getMaxAddress().subtract(selection.getMinAddress());

        // Get current program
        var program = this.plugin.getCurrentProgram();
        
        // Calculate hashes for all supported algorithms
        StringBuilder result = new StringBuilder();
        result.append("\n=== Hash Calculations ===\n");
        result.append("Start Address: 0x").append(startAddress.toString(16).toUpperCase()).append("\n");
        result.append("Length: ").append(length).append(" bytes\n\n");
        
        // Calculate memory hash for each algorithm
        HashUtils.HashAlgorithm[] algorithms = HashUtils.HashAlgorithm.values();
        for (HashUtils.HashAlgorithm algorithm : algorithms) {
            try {
                HashUtils.HashResult hashResult = HashUtils.calculateMemoryHash(program, startAddress, length, algorithm);
                result.append(algorithm.getAlgorithmName()).append(": ").append(hashResult.toHexString().toUpperCase()).append("\n");
            } catch (MemoryAccessException ex) {
                result.append(algorithm.getAlgorithmName()).append(": MEMORY ACCESS ERROR - ").append(ex.getMessage()).append("\n");
            } catch (Exception ex) {
                result.append(algorithm.getAlgorithmName()).append(": ERROR - ").append(ex.getMessage()).append("\n");
            }
        }
        
        // Output to console
        var consoleService = this.plugin.getTool().getService(ghidra.app.services.ConsoleService.class);
        if (consoleService != null) {
            consoleService.println(result.toString());
        }
    }
}