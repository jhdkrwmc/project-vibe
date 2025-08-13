"""
analyze_integrity_flow.py - Comprehensive analysis of the integrity check flow
"""
import json
import os
from collections import defaultdict

def get_function_at(ea):
    """Get function containing the given address"""
    func = idaapi.get_func(ea)
    if not func:
        return None
    return func

def disassemble_function(func_ea):
    """Disassemble a function and return the instructions"""
    func = idaapi.get_func(func_ea)
    if not func:
        return []
    
    instructions = []
    for ea in idautils.Heads(func.start_ea, func.end_ea):
        instructions.append({
            'ea': f"0x{ea:X}",
            'disasm': idc.GetDisasm(ea)
        })
    return instructions

def get_xrefs_to(ea):
    """Get cross-references to the given address"""
    xrefs = []
    for xref in idautils.XrefsTo(ea):
        xrefs.append({
            'from_ea': f"0x{xref.frm:X}",
            'type': str(xref.type),
            'disasm': idc.GetDisasm(xref.frm)
        })
    return xrefs

def analyze_memory_location(addr):
    """Analyze a memory location for reads and writes"""
    result = {
        'address': f"0x{addr:X}",
        'reads': [],
        'writes': []
    }
    
    # Find all code references to this address
    for ref in idautils.XrefsTo(addr):
        mnem = idc.print_insn_mnem(ref.frm).lower()
        if 'movx' in mnem:
            if idc.print_operand(ref.frm, 0) == '@DPTR':
                result['writes'].append({
                    'ea': f"0x{ref.frm:X}",
                    'disasm': idc.GetDisasm(ref.frm)
                })
            elif idc.print_operand(ref.frm, 1) == '@DPTR':
                result['reads'].append({
                    'ea': f"0x{ref.frm:X}",
                    'disasm': idc.GetDisasm(ref.frm)
                })
    
    return result

def analyze_integrity_flow():
    """Main analysis function"""
    print("Starting integrity flow analysis...")
    
    # Main data structure
    analysis = {
        'memory_checks': {},
        'called_functions': {},
        'memory_locations': {},
        'analysis_summary': {}
    }
    
    # 1. Analyze the memory check at 0x1C4
    check_ea = 0x1C4
    func = get_function_at(check_ea)
    
    if func:
        func_name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
        analysis['memory_checks'][f"0x{check_ea:X}"] = {
            'function': func_name,
            'start_ea': f"0x{func.start_ea:X}",
            'end_ea': f"0x{func.end_ea:X}",
            'instructions': disassemble_function(func.start_ea)
        }
        
        # Find all cross-references to this function
        analysis['memory_checks'][f"0x{check_ea:X}"]['callers'] = get_xrefs_to(func.start_ea)
    
    # 2. Analyze jump target at 0xA4BD
    jump_target = 0xA4BD
    jt_func = get_function_at(jump_target)
    
    if jt_func:
        jt_func_name = idc.get_func_name(jt_func.start_ea) or f"sub_{jt_func.start_ea:X}"
        analysis['jump_target'] = {
            'address': f"0x{jump_target:X}",
            'function': jt_func_name,
            'start_ea': f"0x{jt_func.start_ea:X}",
            'end_ea': f"0x{jt_func.end_ea:X}",
            'instructions': disassemble_function(jt_func.start_ea)
        }
    
    # 3. Analyze key memory locations
    key_addresses = [0xF09, 0xBA5, 0xB77, 0xB76]
    for addr in key_addresses:
        analysis['memory_locations'][f"0x{addr:X}"] = analyze_memory_location(addr)
    
    # 4. Find and analyze called functions
    if 'jump_target' in analysis:
        called_funcs = set()
        for inst in analysis['jump_target']['instructions']:
            if 'lcall' in inst['disasm'] or 'acall' in inst['disasm']:
                try:
                    # Try to extract the called address
                    parts = inst['disasm'].split()
                    if len(parts) > 1:
                        called_addr = int(parts[1].replace('code_', '').replace('+', ' ').split()[0], 16)
                        called_funcs.add(called_addr)
                except:
                    continue
        
        for func_ea in called_funcs:
            func = get_function_at(func_ea)
            if func:
                func_name = idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
                analysis['called_functions'][f"0x{func_ea:X}"] = {
                    'name': func_name,
                    'start_ea': f"0x{func.start_ea:X}",
                    'end_ea': f"0x{func.end_ea:X}",
                    'instruction_count': len(list(idautils.FuncItems(func.start_ea)))
                }
    
    # 5. Generate analysis summary
    analysis['analysis_summary'] = {
        'memory_check_found': len(analysis['memory_checks']) > 0,
        'jump_target_analyzed': 'jump_target' in analysis,
        'memory_locations_analyzed': len(analysis['memory_locations']),
        'called_functions_analyzed': len(analysis['called_functions'])
    }
    
    # Save results to JSON file
    output_file = os.path.join(os.path.dirname(idaapi.get_input_file_path()), 'integrity_analysis.json')
    with open(output_file, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    print(f"Analysis complete. Results saved to: {output_file}")
    return analysis

if __name__ == "__main__":
    analysis = analyze_integrity_flow()
    # Print a quick summary
    print("\n=== Analysis Summary ===")
    print(f"Memory checks found: {len(analysis['memory_checks'])}")
    print(f"Jump target analyzed: {'Yes' if 'jump_target' in analysis else 'No'}")
    print(f"Memory locations analyzed: {len(analysis['memory_locations'])}")
    print(f"Called functions analyzed: {len(analysis['called_functions'])}")
