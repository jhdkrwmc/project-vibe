"""
find_memory_writes.py - Find all writes to specific memory locations
"""
import json
import os
from collections import defaultdict

def find_memory_writes(target_addrs):
    """Find all writes to the specified memory addresses"""
    results = {f"0x{addr:04X}": [] for addr in target_addrs}
    
    # Convert addresses to strings for easy comparison
    target_strs = {f"0x{addr:04X}" for addr in target_addrs}
    
    # Scan all code segments
    for seg_ea in idautils.Segments():
        seg_name = idc.get_segm_name(seg_ea)
        seg_start = idc.get_segm_start(seg_ea)
        seg_end = idc.get_segm_end(seg_ea)
        
        # Only scan code segments
        if not idaapi.is_code(idaapi.get_flags(seg_start)):
            continue
            
        print(f"Scanning segment: {seg_name} (0x{seg_start:X}-0x{seg_end:X})")
        
        # Scan each instruction in the segment
        for head in idautils.Heads(seg_start, seg_end):
            # Skip if not a code item
            if not idaapi.is_code(idaapi.get_flags(head)):
                continue
                
            mnem = idc.print_insn_mnem(head).lower()
            
            # Check for memory write operations
            if mnem in ['movx', 'mov'] and '@dptr' in idc.print_operand(head, 1).lower():
                # Get the immediate value being moved to DPTR
                prev_ea = idc.prev_head(head, seg_start)
                if prev_ea != idaapi.BADADDR:
                    prev_mnem = idc.print_insn_mnem(prev_ea).lower()
                    if prev_mnem == 'mov' and 'dptr' in idc.print_operand(prev_ea, 0).lower():
                        # Get the immediate value
                        op = idc.print_operand(prev_ea, 1)
                        if op.startswith('#'):
                            try:
                                addr = int(op[1:].strip(), 16)
                                addr_str = f"0x{addr:04X}"
                                if addr_str in target_strs:
                                    # Get the function containing this instruction
                                    func_ea = idc.get_func_attr(head, idc.FUNCATTR_START)
                                    func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
                                    
                                    # Get some context around the instruction
                                    context = []
                                    for i in range(-3, 3):
                                        ea = head + (i * idc.get_item_size(head + i))
                                        if idaapi.is_code(idaapi.get_flags(ea)):
                                            context.append({
                                                'ea': f"0x{ea:X}",
                                                'disasm': idc.GetDisasm(ea)
                                            })
                                    
                                    # Add to results
                                    results[addr_str].append({
                                        'write_ea': f"0x{head:X}",
                                        'write_instruction': idc.GetDisasm(head),
                                        'dptr_set_ea': f"0x{prev_ea:X}",
                                        'dptr_set_instruction': idc.GetDisasm(prev_ea),
                                        'function': func_name,
                                        'function_ea': f"0x{func_ea:X}",
                                        'context': context
                                    })
                            except (ValueError, TypeError):
                                pass
    
    return results

def analyze_writes_to_memory():
    """Main function to analyze writes to target memory locations"""
    # Target memory addresses to analyze
    target_addrs = [0xF09, 0xBA5]
    
    print(f"Searching for writes to: {[f'0x{addr:04X}' for addr in target_addrs]}")
    
    # Find all writes to these addresses
    write_analysis = find_memory_writes(target_addrs)
    
    # Save results to JSON
    output_file = os.path.join(os.path.dirname(idaapi.get_input_file_path()), 'memory_writes_analysis.json')
    with open(output_file, 'w') as f:
        json.dump(write_analysis, f, indent=2)
    
    print(f"\nAnalysis complete. Results saved to: {output_file}")
    
    # Print summary
    print("\n=== Write Analysis Summary ===")
    for addr, writes in write_analysis.items():
        print(f"\nWrites to {addr}:")
        if writes:
            for i, write in enumerate(writes, 1):
                print(f"  {i}. In {write['function']} at {write['write_ea']}")
                print(f"     Instruction: {write['write_instruction']}")
                print(f"     DPTR set at: {write['dptr_set_instruction']}")
        else:
            print("  No direct writes found")
    
    return write_analysis

if __name__ == "__main__":
    analyze_writes_to_memory()
