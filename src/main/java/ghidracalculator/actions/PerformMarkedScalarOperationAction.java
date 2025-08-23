package ghidracalculator.actions;

import java.math.BigInteger;

import ghidra.app.context.ListingActionContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidracalculator.CalculatorLogic;
import ghidracalculator.CalculatorPlugin;

public class PerformMarkedScalarOperationAction extends AbstractScalarAction {
    private final String operation;
    private CalculatorLogic calculatorLogic;

    public PerformMarkedScalarOperationAction(CalculatorPlugin plugin, CalculatorLogic calculatorLogic, String actionName, String operation, String groupName) {
        super(plugin, actionName, groupName, true);
        this.operation = operation;
        this.calculatorLogic = calculatorLogic;
    }

    @Override
    public void actionPerformed(ListingActionContext context) {
        BigInteger value = BigInteger.valueOf(scalarOp.getValue());
        calculatorLogic.performMarkedValueOperation(value, operation);
    }

    @Override
    protected String getMenuName(Program program, Scalar scalar) {
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
            scalar.toString() +
            operationString2 + 
            plugin.getProvider().getCalculatorLogic().getMarkedValue().toString(16);

        return menuName;
    }
}
