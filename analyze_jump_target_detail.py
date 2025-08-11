"""
analyze_jump_target_detail.py - Detailed analysis of the jump target at 0xA4BD
"""
import json
import os

def get_function_info(ea):
    """Get information about the function containing the given address"""
    func = idaapi.get_func(ea)
    if not func:
        return None
    
    # Get basic function info
    func_info = {
        'start_ea': f"0x{func.start_ea:X}",
        'end_ea': f"0x{func.end_ea:X}",
        'name': idc.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}",
        'calls': [],
        'xrefs': [],
        'basic_blocks': []
    }
    
    # Get cross-references to this function
    for xref in idautils.XrefsTo(func.start_ea):
        func_info['xrefs'].append({
            'from_ea': f"0x{xref.frm:X}",
            'type': str(xref.type),
            'disasm': idc.GetDisasm(xref.frm)
        })
    
    # Analyze basic blocks and calls
    for block in idaapi.FlowChart(func):
        block_info = {
            'start_ea': f"0x{block.start_ea:X}",
            'end_ea': f"0x{block.end_ea:X}",
            'instructions': []
        }
        
        # Get instructions in this block
        for head in idautils.Heads(block.start_ea, block.end_ea):
            mnem = idc.print_insn_mnem(head).lower()
            disasm = idc.GetDisasm(head)
            
            # Add instruction to block
            block_info['instructions'].append({
                'ea': f"0x{head:X}",
                'mnem': mnem,
                'disasm': disasm
            })
            
            # Track function calls
            if mnem in ['acall', 'lcall']:
                called_ea = idc.get_operand_value(head, 0)
                called_name = idc.get_func_name(called_ea) or f"sub_{called_ea:X}"
                func_info['calls'].append({
                    'call_ea': f"0x{head:X}",
                    'called_ea': f"0x{called_ea:X}",
                    'called_name': called_name,
                    'disasm': disasm
                })
        
        func_info['basic_blocks'].append(block_info)
    
    return func_info

def analyze_jump_target(target_ea):
    """Analyze the jump target in detail"""
    print(f"Analyzing jump target at 0x{target_ea:X}")
    
    # Get the function containing the jump target
    func = idaapi.get_func(target_ea)
    if not func:
        print(f"Error: No function found at 0x{target_ea:X}")
        return None
    
    # Get detailed function info
    func_info = get_function_info(func.start_ea)
    
    # Find the specific basic block containing our target
    target_block = None
    for block in func_info['basic_blocks']:
        start_ea = int(block['start_ea'], 16)
        end_ea = int(block['end_ea'], 16)
        if start_ea <= target_ea < end_ea:
            target_block = block
            break
    
    # Save results
    analysis = {
        'target_address': f"0x{target_ea:X}",
        'function': func_info,
        'target_block': target_block
    }
    
    # Save to JSON
    output_file = os.path.join(os.path.dirname(idaapi.get_input_file_path()), 'jump_target_analysis.json')
    with open(output_file, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    print(f"Analysis complete. Results saved to: {output_file}")
    return analysis

def print_summary(analysis):
    """Print a summary of the analysis"""
    if not analysis:
        return
    
    print("\n=== Jump Target Analysis Summary ===")
    print(f"Target Address: {analysis['target_address']}")
    print(f"Function: {analysis['function']['name']} ({analysis['function']['start_ea']}-{analysis['function']['end_ea']})")
    
    print("\nFunction Calls:")
    for call in analysis['function']['calls']:
        print(f"  {call['call_ea']}: {call['disasm']}")
    
    if analysis['target_block']:
        print("\nTarget Basic Block:")
        for inst in analysis['target_block']['instructions']:
            print(f"  {inst['ea']}: {inst['disasm']}")
    
    print("\nCross-references to this function:")
    for xref in analysis['function']['xrefs']:
        print(f"  From {xref['from_ea']}: {xref['disasm']}")

if __name__ == "__main__":
    target_ea = 0xA4BD  # The jump target we're analyzing
    analysis = analyze_jump_target(target_ea)
    print_summary(analysis)
