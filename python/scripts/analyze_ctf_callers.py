"""
analyze_ctf_callers.py - Analyze callers of the CTF function (0x9B)
"""
import json
import os
from collections import defaultdict

def get_function_info(ea):
    """Get information about a function"""
    func = idaapi.get_func(ea)
    if not func:
        return None
    
    return {
        'start_ea': f"0x{func.start_ea:X}",
        'end_ea': f"0x{func.end_ea:X}",
        'name': idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}",
        'size': func.end_ea - func.start_ea
    }

def analyze_caller(caller_ea, target_func_ea):
    """Analyze a single caller of the target function"""
    # Get the function containing this call
    func = idaapi.get_func(caller_ea)
    if not func:
        return None
    
    func_info = get_function_info(func.start_ea)
    if not func_info:
        return None
    
    # Get the call instruction and its context
    call_instr = idc.GetDisasm(caller_ea)
    
    # Get basic blocks around the call
    blocks = []
    f = idaapi.FlowChart(idaapi.get_func(func.start_ea))
    for block in f:
        if block.start_ea <= caller_ea < block.end_ea:
            # Found the block containing our call
            blocks.append({
                'start_ea': f"0x{block.start_ea:X}",
                'end_ea': f"0x{block.end_ea:X}",
                'instructions': []
            })
            
            # Get instructions in this block
            for head in idautils.Heads(block.start_ea, block.end_ea):
                blocks[-1]['instructions'].append({
                    'ea': f"0x{head:X}",
                    'disasm': idc.GetDisasm(head),
                    'is_call': head == caller_ea
                })
            
            # Also get previous and next blocks for context
            for pred in block.preds():
                blocks.append({
                    'start_ea': f"0x{pred.start_ea:X}",
                    'end_ea': f"0x{pred.end_ea:X}",
                    'type': 'predecessor',
                    'instructions': []
                })
                for head in idautils.Heads(pred.start_ea, pred.end_ea):
                    blocks[-1]['instructions'].append({
                        'ea': f"0x{head:X}",
                        'disasm': idc.GetDisasm(head)
                    })
            
            break
    
    return {
        'caller_ea': f"0x{caller_ea:X}",
        'caller_func': func_info,
        'call_instruction': call_instr,
        'context_blocks': blocks
    }

def analyze_ctf_callers():
    """Analyze all callers of the CTF function"""
    # The CTF function is at 0x9B
    ctf_ea = 0x9B
    
    # Get the function info for CTF
    ctf_info = get_function_info(ctf_ea)
    if not ctf_info:
        print(f"Error: Could not find function at 0x{ctf_ea:X}")
        return None
    
    print(f"Analyzing callers of {ctf_info['name']} (0x{ctf_ea:X})...")
    
    # Find all callers (cross-references to)
    callers = []
    for xref in idautils.XrefsTo(ctf_ea):
        if xref.iscode:
            caller_info = analyze_caller(xref.frm, ctf_ea)
            if caller_info:
                callers.append(caller_info)
    
    # Analyze the call hierarchy
    call_hierarchy = {
        'target_function': {
            'ea': f"0x{ctf_ea:X}",
            'name': ctf_info['name'],
            'size': ctf_info['size'],
            'callers': callers
        },
        'caller_analysis': []
    }
    
    # For each caller, check if it's called by other functions
    for caller in callers:
        caller_ea = int(caller['caller_ea'], 16)
        caller_func_ea = int(caller['caller_func']['start_ea'], 16)
        
        # Find callers of this caller
        caller_callers = []
        for xref in idautils.XrefsTo(caller_func_ea):
            if xref.iscode:
                caller_func = idaapi.get_func(xref.frm)
                if caller_func:
                    caller_callers.append({
                        'ea': f"0x{xref.frm:X}",
                        'disasm': idc.GetDisasm(xref.frm),
                        'func_name': idc.get_func_name(caller_func.start_ea) or f"sub_{caller_func.start_ea:X}",
                        'func_ea': f"0x{caller_func.start_ea:X}"
                    })
        
        call_hierarchy['caller_analysis'].append({
            'caller_ea': caller['caller_ea'],
            'caller_func': caller['caller_func'],
            'callers': caller_callers
        })
    
    # Save results to JSON
    output_file = os.path.join(os.path.dirname(idaapi.get_input_file_path()), 'ctf_callers_analysis.json')
    with open(output_file, 'w') as f:
        json.dump(call_hierarchy, f, indent=2)
    
    print(f"Analysis complete. Results saved to: {output_file}")
    
    # Print summary
    print("\n=== Caller Analysis Summary ===")
    print(f"Function: {ctf_info['name']} (0x{ctf_ea:X})")
    print(f"Number of direct callers: {len(callers)}")
    
    for i, caller in enumerate(callers, 1):
        print(f"\nCaller {i}:")
        print(f"  Address: {caller['caller_ea']}")
        print(f"  Function: {caller['caller_func']['name']} ({caller['caller_func']['start_ea']}-{caller['caller_func']['end_ea']})")
        print(f"  Call instruction: {caller['call_instruction']}")
    
    return call_hierarchy

if __name__ == "__main__":
    analyze_ctf_callers()
