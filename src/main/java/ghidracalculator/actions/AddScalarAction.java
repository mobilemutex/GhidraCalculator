package ghidracalculator.actions;

import java.math.BigInteger;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidracalculator.CalculatorPlugin;

public class AddScalarAction extends ListingContextAction {
    protected final CalculatorPlugin plugin;
    private final int operandIndex;

    public AddScalarAction(CalculatorPlugin plugin, String actionName, int operandIndex, String groupName) {
        super(actionName, plugin.getName());
        this.plugin = plugin;
        this.operandIndex = operandIndex;
        setPopupMenuData(new MenuData(new String[] { "Calculator", ""}, groupName));
    }

    @Override
    public void actionPerformed(ListingActionContext context) {
        Address address = context.getAddress();
        if (address == null) {
            return;
        }

        CodeUnit codeUnit = context.getCodeUnit();
        if (!(codeUnit instanceof Instruction)) {
            return;
        }
        
        Instruction instruction = (Instruction) codeUnit;

        Object[] operandObjects = instruction.getOpObjects(operandIndex);
        for (Object operandObject : operandObjects) {
            if (operandObject instanceof Scalar) {
                Scalar scalar = (Scalar) operandObject;
                BigInteger value = BigInteger.valueOf(scalar.getValue());
				plugin.getProvider().addValue(value);
            }
        }
    }

    @Override
    public boolean isEnabledForContext(ListingActionContext context) {
        if (context.getAddress() == null) {
            return false;
        }

        Instruction instruction = context.getProgram().getListing().getInstructionAt(context.getAddress());

        if (instruction == null) {
            return false;
        }

        if (instruction.getNumOperands() < operandIndex) {
            return false;
        }

        Object[] opObjects = instruction.getOpObjects(operandIndex);
        for (Object obj : opObjects) {
            if (obj instanceof Scalar) {
                String menuName = "Add Scalar to Calculator: " + 
                    //Long.toHexString(((Scalar) obj).getValue() & 0xFFFFFFFFL).toUpperCase();
                    ((Scalar) obj).toString();
                getPopupMenuData().setMenuItemNamePlain(menuName);
                return true;
            }
        }
        
        return false;
    }
    
}
