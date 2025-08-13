"""
test_integrity_bypass.py - Test bypass for the integrity check in CTF function

This script tests patching the jump at 0x1D0 to bypass the integrity check.
The original instruction is "jnz code_1D5" (70 03).
The patch changes it to "sjmp code_1D2" (80 01).
"""
import json
import os
from collections import namedtuple

# Configuration
PATCH_ADDR = 0x1D0
ORIG_BYTES = b"\x70\x03"  # jnz code_1D5
PATCH_BYTES = b"\x80\x01"  # sjmp code_1D2

# Data structure to hold patch information
PatchInfo = namedtuple('PatchInfo', ['ea', 'original', 'patched', 'description'])

def apply_patch():
    """Apply the patch to bypass the integrity check"""
    # Save original bytes
    original = ida_bytes.get_bytes(PATCH_ADDR, len(ORIG_BYTES))
    
    # Create patch info
    patch = PatchInfo(
        ea=f"0x{PATCH_ADDR:X}",
        original=original.hex(),
        patched=PATCH_BYTES.hex(),
        description="Bypass integrity check by forcing success path"
    )
    
    # Apply the patch
    ida_bytes.patch_bytes(PATCH_ADDR, PATCH_BYTES)
    
    # Update disassembly
    ida_bytes.create_insn(PATCH_ADDR)
    
    print(f"[+] Patch applied at {patch.ea}")
    print(f"    Original: {patch.original} ({disassemble(ORIG_BYTES, PATCH_ADDR)})")
    print(f"    Patched:  {patch.patched} ({disassemble(PATCH_BYTES, PATCH_ADDR)})")
    
    return patch

def restore_patch(patch):
    """Restore the original bytes"""
    ida_bytes.patch_bytes(int(patch.ea, 16), bytes.fromhex(patch.original))
    ida_bytes.create_insn(int(patch.ea, 16))
    print(f"[+] Restored original bytes at {patch.ea}")

def disassemble(code, ea):
    """Disassemble bytes at the given address"""
    # Save current address
    saved_ea = idc.get_screen_ea()
    
    # Temporarily write the bytes
    orig_bytes = ida_bytes.get_bytes(ea, len(code))
    ida_bytes.patch_bytes(ea, code)
    
    # Get disassembly
    disasm = idc.generate_disasm_line(ea, 0)
    
    # Restore original bytes
    ida_bytes.patch_bytes(ea, orig_bytes)
    
    # Restore screen position
    idc.jumpto(saved_ea)
    
    return disasm

def analyze_patch_impact():
    """Analyze the impact of the patch"""
    print("\n=== Patch Impact Analysis ===")
    
    # Get the function containing the patch
    fn = idaapi.get_func(PATCH_ADDR)
    if not fn:
        print("[-] Could not find function containing patch address")
        return
    
    # Get function name and bounds
    fn_name = idaapi.get_func_name(fn.start_ea)
    print(f"Function: {fn_name} (0x{fn.start_ea:X}-0x{fn.end_ea:X})")
    
    # Show context around the patch
    print("\nCode context around patch:")
    start = max(fn.start_ea, PATCH_ADDR - 16)
    end = min(fn.end_ea, PATCH_ADDR + 32)
    
    for ea in range(start, end, 1):
        if not idaapi.is_code(idaapi.get_flags(ea)):
            continue
            
        disasm = idc.generate_disasm_line(ea, 0)
        prefix = "--> " if ea == PATCH_ADDR else "    "
        print(f"{prefix}0x{ea:04X}: {disasm}")
        
        # Stop if we hit another function
        if ea > PATCH_ADDR and idaapi.get_func(ea) != fn:
            break

def save_patch_info(patch):
    """Save patch information to a JSON file"""
    patch_info = {
        'ea': patch.ea,
        'original_bytes': patch.original,
        'patched_bytes': patch.patched,
        'description': patch.description,
        'function': idaapi.get_func_name(int(patch.ea, 16)),
        'disassembly': {
            'original': disassemble(bytes.fromhex(patch.original), int(patch.ea, 16)),
            'patched': disassemble(bytes.fromhex(patch.patched), int(patch.ea, 16))
        }
    }
    
    output_file = os.path.join(os.path.dirname(idaapi.get_input_file_path()), 'integrity_bypass_patch.json')
    with open(output_file, 'w') as f:
        json.dump(patch_info, f, indent=2)
    
    print(f"\n[+] Patch information saved to: {output_file}")

def test_integrity_bypass():
    """Test the integrity check bypass"""
    print("=== Testing Integrity Check Bypass ===\n")
    
    # Check if the original bytes match what we expect
    current_bytes = ida_bytes.get_bytes(PATCH_ADDR, len(ORIG_BYTES))
    if current_bytes != ORIG_BYTES and current_bytes != PATCH_BYTES:
        print(f"[-] Unexpected bytes at 0x{PATCH_ADDR:X}: {current_bytes.hex()}")
        print("    Expected either:")
        print(f"    - Original: {ORIG_BYTES.hex()} (jnz code_1D5)")
        print(f"    - Patched:  {PATCH_BYTES.hex()} (sjmp code_1D2)")
        return False
    
    # Check if already patched
    if current_bytes == PATCH_BYTES:
        print("[*] Patch already applied")
        return True
    
    # Apply the patch
    print("[*] Applying patch...")
    patch = apply_patch()
    
    # Save patch information
    save_patch_info(patch)
    
    # Analyze impact
    analyze_patch_impact()
    
    print("\n[+] Patch applied successfully!")
    print("    The integrity check at 0x1D0 will now always take the success path.")
    
    return True

if __name__ == "__main__":
    test_integrity_bypass()
