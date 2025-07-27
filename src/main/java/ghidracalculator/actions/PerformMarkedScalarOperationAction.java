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

public class PerformMarkedScalarOperationAction extends ListingContextAction {
    protected final CalculatorPlugin plugin;
    private final int operandIndex;
    private final String operation;

    public PerformMarkedScalarOperationAction(CalculatorPlugin plugin, String actionName, String operation, int operandIndex, String groupName) {
        super(actionName, plugin.getName());
        this.plugin = plugin;
        this.operandIndex = operandIndex;
        this.operation = operation;
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
				plugin.getProvider().performMarkedValueOperation(value, operation);
            }
        }
    }

    @Override
    public boolean isEnabledForContext(ListingActionContext context) {
        if (plugin.getProvider().hasMarkedValue() == false) {
            return false;
        }

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
                String operationString1 = "";
                String operationString2 = "";
                if (operation == "add") {
                    operationString1 = "Add ";
                    operationString2 = " to 0x";
                } else if (operation == "subtract") {
                    operationString1 = "Subtract ";
                    operationString2 = " from 0x";
                } else if (operation == "xor") {
                    operationString1 = "XOR ";
                    operationString2 = " with 0x";
                }
                String menuName = operationString1 + 
                    ((Scalar) obj).toString() +
                    operationString2 + 
                    plugin.getProvider().getMarkedValue().toString(16);
                getPopupMenuData().setMenuItemNamePlain(menuName);
                return true;
            }
        }
        
        return false;
    }
}
