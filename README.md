# Ghidra Calculator Plugin


<img width="413" height="932" alt="GhidraCalcHistory" src="https://github.com/user-attachments/assets/8ff3c478-7b21-48ab-bc99-30d5f7c4f921" />
<img width="651" height="571" alt="GhidraCalcContext" src="https://github.com/user-attachments/assets/f89b86bb-091e-43fc-a023-7c5ca1019e3b" />


## Features

### Core Calculator Features
- **Multi-base Display**: Simultaneous hex, decimal, binary, and octal display
- **Input Mode Switching**: Switch between hex/dec/bin/oct input modes
- **Standard Operations**: Addition, subtraction, multiplication, division
- **Bitwise Operations**: AND, OR, XOR, NOT
- **Quick Increment/Decrement**: ±1, ±0x10, ±0x100, ±0x1000 buttons
- **Value Marking**: Mark and recall values
- **Real-time Conversion**: See values in all number bases simultaneously
- **History Window**: See previous calculations
  - Double-click to jump to resultijg address, if its valid
  - Load result into calculator

### Ghidra Integration Features
- **Context Menu Integration**: Right-click in disassembler to:
  - Add addresses to calculator
  - Add memory values to calculator
  - Add operand constants to calculator
  - Mark addresses for distance calculation
  - Mark values for comparison operations
