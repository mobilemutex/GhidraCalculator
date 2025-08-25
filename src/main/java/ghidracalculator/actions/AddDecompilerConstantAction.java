package ghidracalculator.actions;

import java.math.BigInteger;

import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidracalculator.CalculatorLogic;
import ghidracalculator.CalculatorPlugin;

public class AddDecompilerConstantAction extends AbstractDecompilerConstantAction {

    public AddDecompilerConstantAction(CalculatorPlugin plugin, CalculatorLogic calculatorLogic) {
        super(plugin, calculatorLogic, "Add Constant to Calculator");
    }

    @Override
    protected void decompilerActionPerformed(DecompilerActionContext context) {
        BigInteger value = BigInteger.valueOf(constant.getValue());
        logic.addValue(value);
    }
    
    @Override
    protected String getMenuName(Program program, Scalar constant) {
        return "Add Constant to Calculator: " + constant.toString();
    }
}
