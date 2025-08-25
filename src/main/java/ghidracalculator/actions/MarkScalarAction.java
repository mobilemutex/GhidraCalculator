package ghidracalculator.actions;

import java.math.BigInteger;

import ghidra.app.context.ListingActionContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidracalculator.CalculatorLogic;
import ghidracalculator.CalculatorPlugin;

public class MarkScalarAction extends AbstractScalarAction {

    public MarkScalarAction(CalculatorPlugin plugin, CalculatorLogic calculatorLogic, String actionName, String groupName) {
        super(plugin, calculatorLogic, actionName, groupName, false);
    }

    @Override
    public void actionPerformed(ListingActionContext context) {
        BigInteger value = BigInteger.valueOf(scalarOp.getValue());
        logic.markValueForComparison(value);
    }

    @Override
    protected String getMenuName(Program program, Scalar scalar) {
        return "Mark Scalar Value: " + scalar.toString();
    }
}
