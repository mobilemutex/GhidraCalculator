# Ghidra Calculator Plugin User Guide

## Overview

The Ghidra Calculator Plugin is a powerful calculator extension for Ghidra that enhances reverse engineering workflows by providing a multi-base calculator with deep integration into Ghidra's disassembler and decompiler views. This guide will walk you through all the features and capabilities of the calculator.

## Installation

1. **Install in Ghidra**
   - Open Ghidra
   - Go to **File → Install Extensions...**
   - Click the **"+"** button (Add Extension)
   - Select the release zip file
   - Click **OK** to install
   - **Restart Ghidra** when prompted

2. **Enable the Plugin**
   - After Ghidra restarts, go to **File → Configure → Plugins**
   - Search for **"Calculator"**
   - Check the box next to **"CalculatorPlugin"**
   - Click **OK**

3. **Access the Calculator**
   - Go to **Window → Calculator** and click on **Calculator**
   - Go to **Window → Calculator** and click on **Calculator History**
   - The calculator and history windows will appear and can be docked anywhere

## Calculator Interface

### Main Display

The calculator features a comprehensive display system with multiple components:

1. **Primary Input Field**: Large editable field showing the current value in the selected input mode
2. **Multi-Base Display**: Simultaneous display of the current value in all number bases:
   - HEX (Hexadecimal)
   - DEC (Decimal)
   - OCT (Octal)
   - BIN (Binary) - Clickable for direct bit manipulation
3. **Marked Value Display**: Shows any currently marked value
4. **Marked Address Display**: Shows any currently marked address

### Input Modes

The calculator supports four input modes that can be selected by clicking on the mode labels:

- **HEX (Hexadecimal)**: Default mode, supports digits 0-9 and letters A-F
- **DEC (Decimal)**: Supports digits 0-9
- **BIN (Binary)**: Supports digits 0-1
- **OCT (Octal)**: Supports digits 0-7

### Basic Operations

The calculator provides standard arithmetic operations:
- Addition (+)
- Subtraction (-)
- Multiplication (×)
- Division (÷)
- Modulo (MOD)

### Bitwise Operations

Advanced bitwise operations are available:
- AND: Bitwise AND operation
- OR: Bitwise OR operation
- XOR: Bitwise XOR operation
- NOT: Bitwise NOT operation
- NOR: Bitwise NOR operation
- RoR: Rotate Right (32-bit)
- RoL: Rotate Left (32-bit)
- <<: Left Shift
- >>: Right Shift

### Special Functions

- **Flip Sign (+/-)**: Change the sign of the current value
- **Clear (CLR)**: Reset the calculator to zero
- **2's Complement**: Calculate the 2's complement of the current value
- **Endian Swap**: Swap the byte order of the current value (big-endian to little-endian or vice versa)

### Quick Operations Panel

The bottom panel provides quick increment/decrement operations and is part of the collapsible extras panel:
- +1, +0x10, +0x100, +0x1000
- +2. +4, +8, +32
- -1, -0x10, -0x100, -0x1000
- -2, -4, -8, -32

### Collapsible Extras Panel

The calculator features a collapsible extras panel that can be toggled to show or hide additional functionality:

1. **Increment Panel**: Contains the quick increment/decrement operations mentioned above
2. **Hash Panel**: Provides hash calculation functionality for the current value

The Hash Panel allows you to calculate various hash values (MD5, SHA-1, SHA-256) for a specified region of memory.

## Context Menu Integration

The calculator integrates deeply with Ghidra's interface through context menus:

### In Disassembler View

Right-clicking in the disassembler view provides these calculator options:

1. **Add Address to Calculator**: Adds the selected address to the calculator
2. **Add Memory Value to Calculator**: Adds the value at the selected memory location to the calculator
3. **Add Scalar Operand to Calculator**: Adds a scalar operand to the calculator
4. **Mark Address for Distance**: Marks an address for distance calculation
5. **Mark Scalar Operand**: Marks a scalar operand for comparison operations
6. **Calculate Distance**: Calculates the distance between the marked address and the current address
7. **Add to Marked Scalar**: Performs addition between the marked value and the current scalar
8. **Subtract from Marked Scalar**: Performs subtraction between the marked value and the current scalar
9. **XOR with Marked Scalar**: Performs XOR between the marked value and the current scalar

### In Decompiler View

Right-clicking in the decompiler view provides these calculator options:

1. **Add Constant to Calculator**: Adds a constant value to the calculator
2. **Mark Constant**: Marks a constant value for comparison operations

### Hash Calculations Context Menu

Right-clicking on a selection in the Listing or Decompiler view provides hash calculation options:

1. **Calculate Hashes from Selection**: Calculates various hash values (MD5, SHA-1, SHA-256) for the selected data

### Display Field Context Menu

Right-clicking in the calculator's display field provides:

1. **Jump to Address**: Navigate to the current value as an address (if valid)
2. **Copy Value**: Copy the current value to clipboard
3. **Paste Value**: Paste a value from clipboard
4. **Mark Value**: Mark the current value for later recall
5. **Recall Value**: Recall a previously marked value

## History Functionality

The calculator maintains a history of all operations:

### History Window Features

- **Double-click**: Jump to resulting address if it's a valid address
- **Load Selected**: Load the selected history result into the calculator
- **Clear History**: Remove all entries from the history

### History Entries

Each history entry shows:
- The operation performed
- The result in hexadecimal format
- The result in decimal format

The history is limited to 100 entries to maintain performance.

## Keyboard Shortcuts

The calculator supports keyboard input for efficient operation:

- **Enter**: Evaluate the current expression
- **Escape**: Clear the calculator
- **Backspace/Delete**: Edit the current input
- **+**: Addition
- **-**: Subtraction
- **\***: Multiplication
- **/**: Division
- **&**: AND operation
- **|**: OR operation
- **^**: XOR operation
- **~**: NOT operation
- **=**: Equals

## Value Marking

The calculator supports marking values and addresses for later use:

1. **Mark Value**: Store the current value for later recall
2. **Recall Value**: Load a previously marked value
3. **Mark Address**: Store an address for distance calculations
4. **Calculate Distance**: Compute the distance between two marked addresses

## Input Formats

The calculator accepts values in multiple formats:

- **Hexadecimal**: 0x1234 or 1234 (in HEX mode)
- **Binary**: 0b1010 or 1010 (in BIN mode)
- **Octal**: 0123 or 123 (in OCT mode)
- **Decimal**: 1234 (in DEC mode or without prefix)

## Address Navigation

When the calculator value represents a valid address in the current program:

- The display field tooltip shows address validation information
- Right-click context menu provides "Jump to Address" option
- History entries with valid addresses can be double-clicked for navigation

## Toolbar Actions

The calculator window includes toolbar buttons for quick access:

- **Clear**: Reset the calculator and clear all marks
- **History Toggle**: Show/hide the calculator history window (Note: This feature may not work in all Ghidra versions)

## Usage Tips

1. **Efficient Input**: Use keyboard shortcuts for faster calculations
2. **Multi-base Verification**: Use the multi-base display to verify values in different number systems
3. **Context Integration**: Take advantage of right-click options to quickly add addresses and values from your disassembly
4. **History Utilization**: Use the history window to review previous calculations and navigate to addresses
5. **Value Marking**: Mark values for complex multi-step calculations
6. **Address Operations**: Use address marking and distance calculation for memory analysis
7. **Clipboard Operations**: Copy and paste values between the calculator and other applications
8. **Clickable Binary Display**: Click on individual bits in the binary display to toggle them for quick bit manipulation
9. **Collapsible Extras Panel**: Use the collapsible extras panel to access increment operations and hash calculations
10. **Hash Calculations**: Calculate hashes for the current value using the hash panel or context menu options
11. **2's Complement and Endian Swapping**: Use the special functions to quickly perform 2's complement and endian swapping operations. The bitwidth for these operations is specified in the input field, and can be toggled between 8, 16, 32, and 64 by clicking the current bitwidth.

## Troubleshooting

### Common Issues

1. **Calculator not appearing**: Ensure the plugin is properly enabled in the plugin configuration
2. **Context menu options missing**: Make sure you're right-clicking in a valid location (disassembler or decompiler view)
3. **Address navigation not working**: Verify that a program is loaded and the address is valid within that program
4. **History window not showing**: Try manually opening it through the Window menu

### Error Messages

- **"No program loaded"**: Load a program before attempting address operations
- **"Address not in program memory"**: The calculated value is outside the valid address range
- **"GoTo service not available"**: This is an internal error; try restarting Ghidra
- **"Invalid address format"**: The value cannot be interpreted as a valid address

## Feature Requests

Have ideas for new features? Submit them as GitHub issues and they may be implemented in future versions!