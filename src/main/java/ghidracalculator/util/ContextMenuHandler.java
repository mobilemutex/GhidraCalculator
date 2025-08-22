package ghidracalculator.util;

import java.awt.event.MouseEvent;
import java.math.BigInteger;

import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

import ghidracalculator.CalculatorProvider;

/**
 * Context Menu Handler class to handle all context menu functionality
 */
public class ContextMenuHandler {
    private CalculatorProvider provider;
    private AddressNavigator addressNavigator;
    
    public ContextMenuHandler(CalculatorProvider provider) {
        this.provider = provider;
        this.addressNavigator = new AddressNavigator(provider);
    }
    
    /**
     * Show context menu for the display field
     */
    public void showDisplayContextMenu(MouseEvent e) {
        JPopupMenu popup = new JPopupMenu();
        BigInteger currentValue = provider.getCalculatorLogic().getCurrentValue();
        
        // Jump to Address option (only if valid address)
        if (addressNavigator.isValidAddress(currentValue)) {
            JMenuItem jumpItem = new JMenuItem("Jump to Address");
            jumpItem.setToolTipText("Navigate to 0x" + currentValue.toString(16).toUpperCase() + " in the listing");
            jumpItem.addActionListener(evt -> addressNavigator.jumpToCurrentAddress());
            popup.add(jumpItem);
        }
        
        // Copy Value option
        JMenuItem copyItem = new JMenuItem("Copy Value");
        copyItem.setToolTipText("Copy current value to clipboard");
        copyItem.addActionListener(evt -> new InputHandler(provider).copyValueToClipboard());
        popup.add(copyItem);
        
        // Paste Value option
        JMenuItem pasteItem = new JMenuItem("Paste Value");
        pasteItem.setToolTipText("Paste value from clipboard");
        pasteItem.addActionListener(evt -> new InputHandler(provider).pasteValueFromClipboard());
        popup.add(pasteItem);
        
        // Mark Value option
        JMenuItem markValueItem = new JMenuItem("Mark Value");
        markValueItem.addActionListener(evt -> provider.markCurrentValue());
        popup.add(markValueItem);
        
        // Recall Value option
        if (provider.hasMarkedValue()) {
            JMenuItem recallValueItem = new JMenuItem("Recall Value");
            recallValueItem.addActionListener(evt -> provider.recallMarkedValue());
            popup.add(recallValueItem);
        }
        
        // Only show popup if it has items
        if (popup.getComponentCount() > 0) {
            popup.show(provider.getDisplayField(), e.getX(), e.getY());
        }
    }
}