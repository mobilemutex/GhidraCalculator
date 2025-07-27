package ghidracalculator.actions;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidracalculator.CalculatorPlugin;

public class MarkAddressAction extends ListingContextAction {
    protected final CalculatorPlugin plugin;

    public MarkAddressAction(CalculatorPlugin plugin, String groupName) {
        super("Mark Address for Distance", plugin.getName());
        this.plugin = plugin;
        setPopupMenuData(new MenuData(new String[] { "Calculator", ""}, groupName));
    }

    @Override
    public void actionPerformed(ListingActionContext context) {
			Address address = context.getAddress();
			if (address != null) {
				long addressOffset = address.getOffset();
				plugin.getProvider().markAddress(addressOffset);
			}
    }

    @Override
    public boolean isEnabledForContext(ListingActionContext context) {
        if (context.getAddress() == null) {
            return false;
        }
        
        String menuName = "Mark Address: 0x" + context.getAddress().toString();
        getPopupMenuData().setMenuItemNamePlain(menuName);
        return true;
    }
}
