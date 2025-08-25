package ghidracalculator.actions;

import docking.action.MenuData;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.actions.AbstractDecompilerAction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidracalculator.CalculatorLogic;
import ghidracalculator.CalculatorPlugin;

public abstract class AbstractDecompilerConstantAction extends AbstractDecompilerAction {
    protected static final int MAX_SCALAR_SIZE = 8;
    protected CalculatorPlugin plugin;
    protected CalculatorLogic logic;
    protected Scalar constant;
    
    public AbstractDecompilerConstantAction(CalculatorPlugin plugin, CalculatorLogic calculatorLogic, String name) {
        super(name);
        this.plugin = plugin;
        this.logic = calculatorLogic;
        setPopupMenuData(new MenuData(new String[] {""}, "Calculator"));
    }

    @Override
    protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
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

        String menuName = getMenuName(context.getProgram(), constant);
        getPopupMenuData().setMenuItemNamePlain(menuName);

        return true;
    }

     /**
	 * Get the formatted menu item name.  Note that Data and Instructions may utilize different 
	 * numeric formatting conventions.
	 * @param program the program
	 * @param constant the scalar value to be converted
	 * @return formatted menu item name
	 */
	protected abstract String getMenuName(Program program, Scalar constant);
}
