"""
analyze_memory_check.py - Analyze memory check at 0x1C4 and related code
"""

def analyze_memory_check():
    """Analyze the memory check at 0x1C4 and its context"""
    print("\n=== Analyzing Memory Check at 0x1C4 ===\n")
    
    # Get the function containing 0x1C4
    func_ea = idaapi.get_func(0x1C4)
    if not func_ea:
        print("Error: Function not found at 0x1C4")
        return
    
    func_name = idc.get_func_name(func_ea.start_ea) or f"sub_{func_ea.start_ea:X}"
    print(f"Function: {func_name} (0x{func_ea.start_ea:X}-0x{func_ea.end_ea:X})\n")
    
    # Disassemble the function
    print("Disassembly:")
    for ea in idautils.Heads(func_ea.start_ea, func_ea.end_ea):
        disasm = idc.GetDisasm(ea)
        print(f"  {ea:04X}: {disasm}")
    
    # Find cross-references to this function
    print("\nCross-references to this function:")
    for xref in idautils.XrefsTo(func_ea.start_ea):
        print(f"  Called from: 0x{xref.frm:X}")
        print(f"  Type: {xref.type}")
        print(f"  Code: {idc.GetDisasm(xref.frm)}\n")
    
    # Check for any data references in the function
    print("\nMemory accesses in function:")
    for ea in idautils.Heads(func_ea.start_ea, func_ea.end_ea):
        if idc.print_insn_mnem(ea) == 'movx':
            op = idc.print_operand(ea, 1)
            if '@' in op:  # If it's a memory access
                print(f"  {ea:04X}: {idc.GetDisasm(ea)}")
    
    # Look for potential checksum or validation patterns
    print("\nPotential validation patterns:")
    for ea in idautils.Heads(func_ea.start_ea, func_ea.end_ea):
        mnem = idc.print_insn_mnem(ea)
        if mnem in ('cjne', 'jnz', 'jz', 'jc', 'jnc'):
            print(f"  {ea:04X}: {idc.GetDisasm(ea)}")

if __name__ == "__main__":
    analyze_memory_check()
