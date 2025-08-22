package ghidracalculator.actions;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidracalculator.CalculatorPlugin;

public class CalculateDistanceAction extends ListingContextAction {
    protected final CalculatorPlugin plugin;

    public CalculateDistanceAction(CalculatorPlugin plugin, String groupName) {
        super("Calculate Distance", plugin.getName());
        this.plugin = plugin;
        setPopupMenuData(new MenuData(new String[] { "Calculator", ""}, groupName));
    }

    @Override
    public void actionPerformed(ListingActionContext context) {
			Address address = context.getAddress();
			if (address != null) {
				long currentOffset = address.getOffset();
				plugin.getProvider().calculateDistanceToMarked(currentOffset);
			}
    }

    @Override
    public boolean isEnabledForContext(ListingActionContext context) {
        if (context.getAddress() == null) {
            return false;
        }

        if (plugin.getProvider().hasMarkedAddress() == false) {
            return false;
        }
        
        long markedAddress = plugin.getProvider().getCalculatorLogic().getMarkedAddress();
        String menuName = "Calculate Distance from 0x" + Long.toHexString(markedAddress) + " to 0x" + context.getAddress().toString();
        getPopupMenuData().setMenuItemNamePlain(menuName);
        return true;
    }
    
}
