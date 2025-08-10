package ghidracalculator.actions;

import java.math.BigInteger;

import docking.action.MenuData;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.actions.AbstractDecompilerAction;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidracalculator.CalculatorPlugin;

public class AddDecompilerConstantAction extends AbstractDecompilerAction {

    protected static final int MAX_SCALAR_SIZE = 8;
    protected CalculatorPlugin plugin;
    protected Scalar constant;

    public AddDecompilerConstantAction(CalculatorPlugin plugin, String groupName) {
        super("Add Constant to Calculator");
        this.plugin = plugin;
        setPopupMenuData(new MenuData(new String[] {"Calculator", ""}, groupName));
    }

    protected boolean evaluateContext(DecompilerActionContext context) {
        ClangToken tokenAtCursor = context.getTokenAtCursor();
        if (!(tokenAtCursor instanceof ClangVariableToken)) {
            return false;
        }

        Varnode constantVn = tokenAtCursor.getVarnode();
        if (constantVn == null || !constantVn.isConstant() || constantVn.getSize() > MAX_SCALAR_SIZE) {
            return false;
        }

        constant = tokenAtCursor.getScalar();

        if (constant == null) {
            return false;
        }

        return true;
    }

    @Override
    protected void decompilerActionPerformed(DecompilerActionContext context) {
        BigInteger value = BigInteger.valueOf(constant.getValue());
        plugin.getProvider().addValue(value);
    }

    @Override
    protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
        if (evaluateContext(context) == false) {
            return false;
        } 

        String menuName = "Add Constant to Calculator: " + constant.toString();
        getPopupMenuData().setMenuItemNamePlain(menuName);

        return true;
    }
    
    
}
