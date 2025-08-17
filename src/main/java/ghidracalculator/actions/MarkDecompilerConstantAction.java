package ghidracalculator.actions;

import java.math.BigInteger;

import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidracalculator.CalculatorPlugin;

public class MarkDecompilerConstantAction extends AbstractDecompilerConstantAction {

    public MarkDecompilerConstantAction(CalculatorPlugin plugin) {
        super(plugin, "Mark Decompiler Constant Value");
    }
    
    @Override
    protected void decompilerActionPerformed(DecompilerActionContext context) {
        BigInteger value = BigInteger.valueOf(constant.getValue());
        plugin.getProvider().markValueForComparison(value);
    }
    
    @Override
    protected String getMenuName(Program program, Scalar constant) {
        return "Mark Constant Value: " + constant.toString();
    }
}
