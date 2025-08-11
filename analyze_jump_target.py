"""
analyze_jump_target.py - Analyze the jump target at code_A4BC+1
"""

def analyze_jump_target():
    """Analyze the code at code_A4BC+1"""
    target_ea = 0xA4BC + 1  # code_A4BC+1
    print(f"\n=== Analyzing Jump Target at 0x{target_ea:X} ===\n")
    
    # Get the function containing this address
    func_ea = idaapi.get_func(target_ea)
    if not func_ea:
        print(f"Error: No function found at 0x{target_ea:X}")
        return
    
    func_name = idc.get_func_name(func_ea.start_ea) or f"sub_{func_ea.start_ea:X}"
    print(f"Function: {func_name} (0x{func_ea.start_ea:X}-0x{func_ea.end_ea:X})\n")
    
    # Disassemble the function
    print("Disassembly:")
    for ea in idautils.Heads(func_ea.start_ea, func_ea.end_ea):
        disasm = idc.GetDisasm(ea)
        print(f"  {ea:04X}: {disasm}")
        
        # Stop after 20 instructions to keep output manageable
        if ea > (target_ea + 0x40):
            print("  ... (truncated)")
            break
    
    # Find cross-references to this function
    print("\nCross-references to this function:")
    xref_count = 0
    for xref in idautils.XrefsTo(func_ea.start_ea):
        xref_count += 1
        print(f"  Called from: 0x{xref.frm:X}")
        print(f"  Type: {xref.type}")
        print(f"  Code: {idc.GetDisasm(xref.frm)}\n")
    
    if xref_count == 0:
        print("  No cross-references found")
    
    # Check for any interesting data references
    print("\nMemory accesses in function:")
    for ea in idautils.Heads(func_ea.start_ea, func_ea.end_ea):
        mnem = idc.print_insn_mnem(ea)
        if mnem in ('movx', 'movc', 'mov'):
            op = idc.print_operand(ea, 1)
            if '@' in op or '#' in op:  # If it's a memory access or immediate
                print(f"  {ea:04X}: {idc.GetDisasm(ea)}")
    
    # Look for potential return values or status codes
    print("\nReturn value analysis:")
    for ea in idautils.Heads(func_ea.end_ea - 0x10, func_ea.end_ea):
        mnem = idc.print_insn_mnem(ea)
        if mnem == 'ret':
            print(f"  {ea:04X}: {idc.GetDisasm(ea)}")
            # Check if a value is being returned in A or R7
            prev_ea = idc.prev_head(ea, func_ea.start_ea)
            if 'mov' in idc.print_insn_mnem(prev_ea):
                print(f"    Possible return value in: {idc.GetDisasm(prev_ea)}")

if __name__ == "__main__":
    analyze_jump_target()
