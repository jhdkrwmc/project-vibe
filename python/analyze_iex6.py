"""
analyze_iex6.py - Analyze the IEX6 interrupt handler and its context
"""
import json
import os

def get_interrupt_info(ea):
    """Get information about an interrupt handler"""
    # Check if this is a known interrupt vector
    vectors = {
        0x03: 'External Interrupt 0',
        0x0B: 'Timer 0',
        0x13: 'External Interrupt 1',
        0x1B: 'Timer 1',
        0x23: 'UART',
        0x2B: 'Timer 2',
        0x33: 'External Interrupt 2',
        0x3B: 'External Interrupt 3',
        0x43: 'External Interrupt 4',
        0x4B: 'External Interrupt 5',
        0x53: 'External Interrupt 6',
        0x5B: 'External Interrupt 7',
        0x63: 'I2C',
        0x6B: 'IEX6'  # Our target
    }
    
    return vectors.get(ea, f'Unknown Interrupt {ea:X}h')

def analyze_iex6():
    """Analyze the IEX6 interrupt handler and related code"""
    iex6_ea = 0x6B
    
    # Get the function info for IEX6
    func = idaapi.get_func(iex6_ea)
    if not func:
        print(f"Error: Could not find function at 0x{iex6_ea:X}")
        return None
    
    # Get basic function info
    func_info = {
        'start_ea': f"0x{func.start_ea:X}",
        'end_ea': f"0x{func.end_ea:X}",
        'size': func.size(),
        'name': 'IEX6',
        'interrupt_info': get_interrupt_info(iex6_ea),
        'calls': [],
        'basic_blocks': []
    }
    
    # Disassemble the function
    for head in idautils.Heads(func.start_ea, func.end_ea):
        mnem = idc.print_insn_mnem(head).lower()
        disasm = idc.GetDisasm(head)
        
        # Track function calls
        if mnem in ['acall', 'lcall']:
            called_ea = idc.get_operand_value(head, 0)
            called_name = idc.get_func_name(called_ea) or f"sub_{called_ea:X}"
            func_info['calls'].append({
                'ea': f"0x{head:X}",
                'called_ea': f"0x{called_ea:X}",
                'called_name': called_name,
                'disasm': disasm
            })
    
    # Analyze basic blocks
    f = idaapi.FlowChart(func)
    for block in f:
        block_info = {
            'start_ea': f"0x{block.start_ea:X}",
            'end_ea': f"0x{block.end_ea:X}",
            'instructions': []
        }
        
        # Get instructions in this block
        for head in idautils.Heads(block.start_ea, block.end_ea):
            block_info['instructions'].append({
                'ea': f"0x{head:X}",
                'disasm': idc.GetDisasm(head)
            })
        
        func_info['basic_blocks'].append(block_info)
    
    # Find any code that enables this interrupt
    iex6_enable = find_interrupt_enable(iex6_ea)
    if iex6_enable:
        func_info['interrupt_enable'] = iex6_enable
    
    # Save results
    output_file = os.path.join(os.path.dirname(idaapi.get_input_file_path()), 'iex6_analysis.json')
    with open(output_file, 'w') as f:
        json.dump(func_info, f, indent=2)
    
    print(f"Analysis complete. Results saved to: {output_file}")
    
    # Print summary
    print(f"\n=== IEX6 Interrupt Analysis ===")
    print(f"Address: {func_info['start_ea']}-{func_info['end_ea']}")
    print(f"Type: {func_info['interrupt_info']}")
    print(f"Size: {func_info['size']} bytes")
    
    print("\nFunction Calls:")
    for call in func_info['calls']:
        print(f"  {call['ea']}: {call['disasm']}")
    
    if 'interrupt_enable' in func_info:
        print("\nInterrupt Enable:")
        for enable in func_info['interrupt_enable']:
            print(f"  {enable['ea']}: {enable['disasm']}")
    
    return func_info

def find_interrupt_enable(iex6_ea):
    """Find where this interrupt is enabled"""
    # Look for instructions that might enable this interrupt
    # This is 8051-specific and depends on the interrupt controller
    
    # Common interrupt enable registers in 8051:
    # - IE (Interrupt Enable) at 0xA8
    # - EIE (Extended Interrupt Enable) at 0xE8 (if available)
    
    # We'll look for writes to these registers with the appropriate bit set
    enable_ops = []
    
    # Check IE (0xA8) writes
    for head in idautils.Heads(0, idc.get_segm_end(0)):
        if idc.print_insn_mnem(head).lower() == 'mov':
            if 'IE' in idc.print_operand(head, 0):
                enable_ops.append({
                    'ea': f"0x{head:X}",
                    'disasm': idc.GetDisasm(head)
                })
    
    return enable_ops if enable_ops else None

if __name__ == "__main__":
    analyze_iex6()
