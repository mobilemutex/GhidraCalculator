package ghidracalculator.actions;

import java.math.BigInteger;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidracalculator.CalculatorLogic;
import ghidracalculator.CalculatorPlugin;

public class AddMemoryAction extends ListingContextAction {
    protected final CalculatorPlugin plugin;
    protected CalculatorLogic logic;

    public AddMemoryAction(CalculatorPlugin plugin, CalculatorLogic calculatorLogic, String groupName) {
        super("Add Memory Value to Calculator", plugin.getName());
        this.plugin = plugin;
        this.logic = calculatorLogic;
        setPopupMenuData(new MenuData(new String[] { "Calculator", ""}, groupName));
    }

    // TODO: provide options in the context menu for big/little endian representations
    @Override
    public void actionPerformed(ListingActionContext context) {
        Address address = context.getAddress();
        Program program = plugin.getCurrentProgram();
        
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
                    logic.addValue(value);
                }
            } catch (MemoryAccessException e) {
                // If we can't read memory, just use the address value?
                BigInteger addressValue = new BigInteger(address.toString(false), 16);
                logic.addValue(addressValue);
            }
        }
        return;
    }

    @Override
    public boolean isEnabledForContext(ListingActionContext context) {
        if (context.getAddress() == null) {
            return false;
        }

        int value;

        try {
            Memory memory = plugin.getCurrentProgram().getMemory();
            value = memory.getInt(context.getAddress());
        } catch (MemoryAccessException e) {
            return false;
        }

        String menuName = "Add Memory to Calculator: 0x" + Long.toHexString(value & 0xFFFFFFFFL).toUpperCase();
        getPopupMenuData().setMenuItemNamePlain(menuName);
        return true;
    }
}
