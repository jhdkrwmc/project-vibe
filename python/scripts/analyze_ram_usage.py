"""
analyze_ram_usage.py - Analyze usage of RAM_23 and RAM_24 in the firmware
"""
import json
import os
from collections import defaultdict

def get_ram_references(ram_address):
    """Find all references to a specific RAM address"""
    refs = []
    
    # Search for direct references to the RAM address
    for head in idautils.Heads(0, idc.get_segm_end(0)):
        # Check if this instruction references our RAM location
        if idc.get_operand_type(head, 0) == idc.o_mem and idc.get_operand_value(head, 0) == ram_address:
            refs.append({
                'ea': f"0x{head:X}",
                'disasm': idc.GetDisasm(head),
                'op_type': 'direct',
                'operand': 0
            })
        if idc.get_operand_type(head, 1) == idc.o_mem and idc.get_operand_value(head, 1) == ram_address:
            refs.append({
                'ea': f"0x{head:X}",
                'disasm': idc.GetDisasm(head),
                'op_type': 'direct',
                'operand': 1
            })
    
    # Also check for bit-level access (for RAM_24.3)
    if ram_address == 0x24:
        for head in idautils.Heads(0, idc.get_segm_end(0)):
            disasm = idc.GetDisasm(head).lower()
            if 'ram_24.' in disasm or '24.' in disasm:
                # Get the actual bit number if possible
                bit = None
                if 'ram_24.' in disasm:
                    try:
                        bit = int(disasm.split('ram_24.')[1].split(';')[0].strip())
                    except (ValueError, IndexError):
                        pass
                
                refs.append({
                    'ea': f"0x{head:X}",
                    'disasm': idc.GetDisasm(head),
                    'op_type': 'bit',
                    'bit': bit,
                    'operand': 0 if 'ram_24.' in idc.print_operand(head, 0).lower() else 1
                })
    
    return refs

def analyze_ram_usage():
    """Analyze usage of RAM_23 and RAM_24"""
    ram_23 = 0x23
    ram_24 = 0x24
    
    # Get references to both RAM locations
    ram23_refs = get_ram_references(ram_23)
    ram24_refs = get_ram_references(ram_24)
    
    # Group references by function
    def group_by_function(refs):
        func_groups = defaultdict(list)
        for ref in refs:
            func = idaapi.get_func(int(ref['ea'], 16))
            if func:
                func_name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
                func_groups[func_name].append(ref)
            else:
                func_groups['unknown'].append(ref)
        return func_groups
    
    ram23_groups = group_by_function(ram23_refs)
    ram24_groups = group_by_function(ram24_refs)
    
    # Get bit usage for RAM_24
    bit_usage = defaultdict(list)
    for ref in ram24_refs:
        if 'bit' in ref:
            bit_usage[ref['bit']].append(ref)
    
    # Prepare results
    results = {
        'ram_23': {
            'address': '0x23',
            'total_references': len(ram23_refs),
            'references_by_function': {
                func: [
                    {'ea': ref['ea'], 'disasm': ref['disasm'], 'op_type': ref['op_type']}
                    for ref in refs
                ]
                for func, refs in ram23_groups.items()
            }
        },
        'ram_24': {
            'address': '0x24',
            'total_references': len(ram24_refs),
            'bit_usage': {
                bit: [
                    {'ea': ref['ea'], 'disasm': ref['disasm']}
                    for ref in refs
                ]
                for bit, refs in bit_usage.items()
            },
            'references_by_function': {
                func: [
                    {'ea': ref['ea'], 'disasm': ref['disasm'], 'op_type': ref['op_type']}
                    for ref in refs
                ]
                for func, refs in ram24_groups.items()
            }
        }
    }
    
    # Save results
    output_file = os.path.join(os.path.dirname(idaapi.get_input_file_path()), 'ram_usage_analysis.json')
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Analysis complete. Results saved to: {output_file}")
    
    # Print summary
    print("\n=== RAM Usage Analysis ===")
    print(f"RAM_23 (0x23) - {len(ram23_refs)} total references")
    print(f"  Used in {len(ram23_groups)} functions")
    
    print(f"\nRAM_24 (0x24) - {len(ram24_refs)} total references")
    print(f"  Used in {len(ram24_groups)} functions")
    print("  Bit-level usage:")
    for bit, refs in sorted(bit_usage.items()):
        print(f"    Bit {bit}: {len(refs)} references")
    
    return results

if __name__ == "__main__":
    analyze_ram_usage()
