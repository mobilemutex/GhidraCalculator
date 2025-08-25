package ghidracalculator.actions;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidracalculator.CalculatorLogic;
import ghidracalculator.CalculatorPlugin;

public class CalculateDistanceAction extends ListingContextAction {
    protected final CalculatorPlugin plugin;
    protected CalculatorLogic logic;

    public CalculateDistanceAction(CalculatorPlugin plugin, CalculatorLogic calculatorLogic, String groupName) {
        super("Calculate Distance", plugin.getName());
        this.plugin = plugin;
        this.logic = calculatorLogic;
        setPopupMenuData(new MenuData(new String[] { "Calculator", ""}, groupName));
    }

    @Override
    public void actionPerformed(ListingActionContext context) {
			Address address = context.getAddress();
			if (address != null) {
				long currentOffset = address.getOffset();
				logic.calculateDistanceToMarked(currentOffset);
			}
    }

    @Override
    public boolean isEnabledForContext(ListingActionContext context) {
        if (context.getAddress() == null) {
            return false;
        }

        if (logic.hasMarkedAddress() == false) {
            return false;
        }
        
        long markedAddress = logic.getMarkedAddress();
        String menuName = "Calculate Distance from 0x" + Long.toHexString(markedAddress) + " to 0x" + context.getAddress().toString();
        getPopupMenuData().setMenuItemNamePlain(menuName);
        return true;
    }
    
}
