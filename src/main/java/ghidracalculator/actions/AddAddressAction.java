package ghidracalculator.actions;

import java.math.BigInteger;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidracalculator.CalculatorPlugin;

public class AddAddressAction extends ListingContextAction {
    protected final CalculatorPlugin plugin;

    public AddAddressAction(CalculatorPlugin plugin, String groupName) {
        super("Add Address to Calculator", plugin.getName());
        this.plugin = plugin;
        setPopupMenuData(new MenuData(new String[] { "Calculator", ""}, groupName));
    }

    @Override
    public void actionPerformed(ListingActionContext context) {
        Address address = context.getAddress();
        if (address == null) {
            return;
        }

        BigInteger addressValue = new BigInteger(address.toString(false), 16);
        plugin.getProvider().addValue(addressValue);
    }

    @Override
    public boolean isEnabledForContext(ListingActionContext context) {
        if (context.getAddress() == null) {
            return false;
        }
        
        String menuName = "Add Address to Calculator: 0x" + context.getAddress().toString();
        getPopupMenuData().setMenuItemNamePlain(menuName);
        return true;
    }
}
