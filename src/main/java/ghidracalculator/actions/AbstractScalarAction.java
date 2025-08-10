package ghidracalculator.actions;

import java.util.List;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.OperandFieldLocation;
import ghidracalculator.CalculatorPlugin;

public abstract class AbstractScalarAction extends ListingContextAction {
    protected final CalculatorPlugin plugin;
    protected Scalar scalarOp = null;
    protected Boolean isMarkedOperation;

    public AbstractScalarAction(CalculatorPlugin plugin, String actionName, String groupName, Boolean isMarkedOperation) {
        super(actionName, plugin.getName());
        this.plugin = plugin;
        this.isMarkedOperation = isMarkedOperation;
        setPopupMenuData(new MenuData(new String[] { "Calculator", ""}, groupName));
    }

    @Override
    public boolean isEnabledForContext(ListingActionContext context) {
        if (isMarkedOperation && plugin.getProvider().hasMarkedValue() == false) {
            return false;
        }

        CodeUnit codeUnit = null;
        if (context.getAddress() != null) {
            codeUnit = context.getProgram().getListing().getCodeUnitContaining(context.getAddress());
        }

        if (codeUnit == null) {
            return false;
        }

        // Check if we're on an operand field
        if (!(context.getLocation() instanceof OperandFieldLocation)) {
            return false;
        }

        OperandFieldLocation operandLoc = (OperandFieldLocation) context.getLocation();
        int operandIndex = operandLoc.getOperandIndex();
        int subOperandIndex = operandLoc.getSubOperandIndex();

        if (codeUnit instanceof Data) {
            scalarOp = codeUnit.getScalar(operandIndex);

            String menuName = getMenuName(context.getProgram(), scalarOp);
            getPopupMenuData().setMenuItemNamePlain(menuName);

            return true;
        }

        if (subOperandIndex < 0) {
            return false;
        }

        Instruction instruction = (Instruction) codeUnit;
        List<?> opList = instruction.getDefaultOperandRepresentationList(operandIndex);
        if (opList == null) {
            return false;
        }

        int numSubOps = opList.size();
        Scalar currentScalar = null;

		// Check from opIndex to End for scalar.
		for (int repIndex = subOperandIndex; repIndex < numSubOps; repIndex++) {
			Object object = opList.get(repIndex);
			if (object instanceof Scalar) {
				currentScalar = (Scalar) object;
				break;
			}
		}
		if (currentScalar == null) {
			for (int repIndex = subOperandIndex - 1; repIndex >= 0; repIndex--) {
				Object object = opList.get(repIndex);
				if (object instanceof Scalar) {
					currentScalar = (Scalar) object;
					break;
				}
			}
		}
		if (currentScalar == null) {
			return false;
		}

		// Only return scalar if we can find matching scalar in OpObjects
		Object[] opObjects = instruction.getOpObjects(operandIndex);
		for (Object object : opObjects) {
			if (object instanceof Scalar && currentScalar.equals(object)) {
                scalarOp = currentScalar;
                break;
			}
		}

        if (scalarOp == null) {
            return false;
        }

        String menuName = getMenuName(context.getProgram(), scalarOp);
        getPopupMenuData().setMenuItemNamePlain(menuName);

        return true;
    }

    /**
	 * Get the formatted menu item name.  Note that Data and Instructions may utilize different 
	 * numeric formatting conventions.
	 * @param program the program
	 * @param scalar the scalar value to be converted
	 * @return formatted menu item name
	 */
	protected abstract String getMenuName(Program program, Scalar scalar);
}
