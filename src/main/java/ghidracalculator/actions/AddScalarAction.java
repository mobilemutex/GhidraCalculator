package ghidracalculator.actions;

import java.math.BigInteger;

import ghidra.app.context.ListingActionContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidracalculator.CalculatorPlugin;

public class AddScalarAction extends AbstractScalarAction {

    public AddScalarAction(CalculatorPlugin plugin, String actionName, String groupName) {
        super(plugin, actionName, groupName, false);
    }
    
    @Override
    public void actionPerformed(ListingActionContext context) {
        BigInteger value = BigInteger.valueOf(scalarOp.getValue());
        plugin.getProvider().addValue(value);
    }

    @Override
    protected String getMenuName(Program program, Scalar scalar) {
        return "Add Scalar to Calculator: " + scalar.toString();
    }

}
