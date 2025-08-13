"""
patch_a4d5.py - Patch the branch at 0xA4D5 to force execution to 0xA4DF

This script patches the conditional jump at 0xA4D5 to make it unconditional.
Original: jc 0xA4DF (0x40 0x08)
Patched:  sjmp 0xA4DF (0x80 0x08)
"""
import os
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

@dataclass
class FirmwarePatch:
    """Represents a patch to be applied to the firmware"""
    offset: int
    original: bytes
    patched: bytes
    description: str

# Patch configuration
PATCH_OFFSET = 0xA4D5
ORIGINAL_BYTES = b"\x40"  # jc opcode
PATCHED_BYTES = b"\x80"   # sjmp opcode
PATCH_DESCRIPTION = "Change jc to sjmp to force execution to 0xA4DF"

def apply_patch(input_file: str, output_file: str) -> bool:
    """Apply the patch to the input file and save to output file"""
    try:
        # Read the input file
        with open(input_file, 'rb') as f:
            data = bytearray(f.read())
        
        # Check if the original bytes match
        if data[PATCH_OFFSET:PATCH_OFFSET + 1] != ORIGINAL_BYTES:
            print(f"[!] Warning: Original bytes at 0x{PATCH_OFFSET:X} do not match expected pattern")
            print(f"    Expected: {ORIGINAL_BYTES.hex()}")
            print(f"    Found:    {data[PATCH_OFFSET:PATCH_OFFSET + len(ORIGINAL_BYTES)].hex()}")
            if input("    Continue anyway? (y/N): ").lower() != 'y':
                return False
        
        # Apply the patch
        data[PATCH_OFFSET:PATCH_OFFSET + len(PATCHED_BYTES)] = PATCHED_BYTES
        
        # Write the patched file
        with open(output_file, 'wb') as f:
            f.write(data)
        
        print(f"[+] Patch applied successfully to {output_file}")
        return True
        
    except Exception as e:
        print(f"[!] Error applying patch: {e}")
        return False

def main():
    """Main function"""
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_file> <output_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    print(f"[+] Patching {input_file}")
    print(f"    Offset: 0x{PATCH_OFFSET:X}")
    print(f"    Original: {ORIGINAL_BYTES.hex()} (jc 0xA4DF)")
    print(f"    Patched:  {PATCHED_BYTES.hex()} (sjmp 0xA4DF)")
    
    if not os.path.exists(input_file):
        print(f"[!] Input file not found: {input_file}")
        sys.exit(1)
    
    if os.path.exists(output_file):
        print(f"[!] Output file already exists: {output_file}")
        if input("    Overwrite? (y/N): ").lower() != 'y':
            sys.exit(1)
    
    if apply_patch(input_file, output_file):
        print(f"[+] Successfully created patched firmware: {output_file}")
        print("\nNext steps:")
        print(f"1. Test the patched firmware: {output_file}")
        print("2. If successful, the firmware should bypass the integrity check")
        print("3. If not, we may need to analyze other potential check locations")
    else:
        print("[!] Failed to apply patch")
        sys.exit(1)

if __name__ == "__main__":
    main()
