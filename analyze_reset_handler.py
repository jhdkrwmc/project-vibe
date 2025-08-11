"""
analyze_reset_handler.py - Analyze the reset handler and boot process

This script traces the execution flow from the reset vector (0x0000)
to identify the boot-time integrity check.
"""

import idaapi
import idautils
import idc

def get_disasm(ea):
    """Get disassembly at given address"""
    return idc.GetDisasm(ea)

def get_function_name(ea):
    """Get function name at given address"""
    func_name = idc.get_func_name(ea)
    return func_name if func_name else f"sub_{ea:X}"

def trace_boot_flow(start_ea, max_instructions=100):
    """Trace the boot flow starting from the given address"""
    visited = set()
    flow = []
    current_ea = start_ea
    
    print(f"Tracing boot flow from 0x{start_ea:X}...")
    
    for _ in range(max_instructions):
        if current_ea in visited:
            print(f"Loop detected at 0x{current_ea:X}")
            break
            
        visited.add(current_ea)
        
        # Get current instruction
        disasm = get_disasm(current_ea)
        mnem = idc.print_insn_mnem(current_ea).lower()
        
        # Add to flow
        func_name = get_function_name(current_ea)
        flow.append({
            'ea': current_ea,
            'disasm': disasm,
            'func': func_name
        })
        
        # Check for control flow instructions
        if mnem in ('ljmp', 'lcall', 'acall', 'ajmp', 'sjmp', 'jmp'):
            # Get the target address
            target = idc.get_operand_value(current_ea, 0)
            if target != idc.BADADDR and target != 0:
                print(f"0x{current_ea:04X}: {disasm}")
                if mnem in ('lcall', 'acall'):
                    # For calls, we'll continue after the call
                    next_ea = idc.next_head(current_ea, idc.BADADDR)
                    if next_ea != idc.BADADDR:
                        print(f"  -> Calling 0x{target:04X}, will return to 0x{next_ea:04X}")
                    else:
                        print(f"  -> Calling 0x{target:04X}")
                else:
                    print(f"  -> Jumping to 0x{target:04X}")
                
                # If this is a call, we might want to trace into it
                if mnem in ('lcall', 'acall') and target not in visited:
                    # Trace into the function
                    sub_flow = trace_boot_flow(target, max_instructions//2)
                    flow.extend(sub_flow)
                    
                    # Continue after the call
                    current_ea = next_ea
                    continue
                else:
                    current_ea = target
                    continue
        
        # Check for return
        elif mnem in ('ret', 'reti'):
            print(f"0x{current_ea:04X}: {disasm} (returning)")
            break
            
        # Move to next instruction
        next_ea = idc.next_head(current_ea, idc.BADADDR)
        if next_ea == idc.BADADDR:
            break
            
        current_ea = next_ea
    
    return flow

def main():
    """Main function to analyze the reset handler"""
    print("=== Analyzing Reset Handler ===")
    
    # Start tracing from the reset vector
    reset_vector = 0x0000
    boot_flow = trace_boot_flow(reset_vector)
    
    # Save results to a file
    output_file = idaapi.ask_file(True, "*.json", "Save boot flow analysis to")
    if output_file:
        import json
        with open(output_file, 'w') as f:
            json.dump(boot_flow, f, indent=2)
        print(f"\nBoot flow analysis saved to {output_file}")
    
    # Print summary
    print("\n=== Boot Flow Summary ===")
    for i, inst in enumerate(boot_flow[:20]):  # Print first 20 instructions
        print(f"0x{inst['ea']:04X}: {inst['disasm']}")
    
    if len(boot_flow) > 20:
        print(f"... and {len(boot_flow) - 20} more instructions")

if __name__ == "__main__":
    main()
