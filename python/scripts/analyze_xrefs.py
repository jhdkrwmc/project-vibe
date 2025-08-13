"""
analyze_xrefs.py - Analyze cross-references to a specific function

This script analyzes cross-references to a given function and checks
if it's reachable from the RESET vector (0x0000).
"""

import idaapi
import idautils
import idc

def get_function_name(ea):
    """Get function name at given address"""
    func_name = idc.get_func_name(ea)
    return func_name if func_name else f"sub_{ea:X}"

def get_xrefs_to(func_ea):
    """Get all code references to the given function"""
    xrefs = []
    for xref in idautils.XrefsTo(func_ea):
        xrefs.append({
            'from': xref.frm,
            'type': xref.type,
            'from_func': get_function_name(xref.frm),
            'disasm': idc.GetDisasm(xref.frm)
        })
    return xrefs

def trace_to_reset(func_ea, max_depth=10):
    """Trace call graph to see if function is reachable from RESET"""
    visited = set()
    queue = [(func_ea, 0, [func_ea])]
    
    while queue:
        current_ea, depth, path = queue.pop(0)
        
        # Skip if we've already visited this function
        if current_ea in visited:
            continue
            
        visited.add(current_ea)
        
        # If we've reached the reset vector, return the path
        if current_ea == 0x0000:
            return True, path
            
        # Stop if we've reached maximum depth
        if depth >= max_depth:
            continue
            
        # Get callers of the current function
        for xref in idautils.XrefsTo(current_ea):
            # Only follow code references
            if xref.type in (idc.fl_CN, idc.fl_CF):
                caller_ea = xref.frm
                caller_func = idaapi.get_func(caller_ea)
                
                if caller_func:
                    queue.append((caller_func.start_ea, depth + 1, path + [caller_func.start_ea]))
    
    return False, []

def main():
    """Main function to analyze cross-references"""
    target_ea = 0x236D  # The function we're interested in
    
    print(f"\n=== Analyzing Cross-References to 0x{target_ea:X} ===")
    
    # Get cross-references to the target function
    xrefs = get_xrefs_to(target_ea)
    
    print(f"\nFound {len(xrefs)} cross-references to 0x{target_ea:X}:")
    for i, xref in enumerate(xrefs, 1):
        print(f"{i}. From 0x{xref['from']:X} ({xref['from_func']}): {xref['disasm']}")
    
    # Check if reachable from RESET
    print("\nChecking if function is reachable from RESET (0x0000)...")
    reachable, path = trace_to_reset(target_ea)
    
    if reachable:
        print("\nPath to RESET:")
        for i, ea in enumerate(reversed(path)):
            print(f"{'  ' * i}└─ 0x{ea:X} ({get_function_name(ea)})")
    else:
        print("\nNo path to RESET found within maximum depth.")
    
    # Save results to a file
    output_file = idaapi.ask_file(True, "*.json", "Save cross-reference analysis to")
    if output_file:
        import json
        with open(output_file, 'w') as f:
            json.dump({
                'target_ea': target_ea,
                'target_name': get_function_name(target_ea),
                'xrefs': xrefs,
                'reachable_from_reset': reachable,
                'path_to_reset': [{
                    'ea': ea,
                    'name': get_function_name(ea)
                } for ea in path] if reachable else []
            }, f, indent=2)
        print(f"\nAnalysis saved to {output_file}")

if __name__ == "__main__":
    main()
