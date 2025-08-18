#!/usr/bin/env python3
"""
SN9C292B Firmware - Post-Boot OSD Disable Patch

This script patches the three post-boot OSD enable sites in the firmware:
1. 0x04D0: Disable OSD control register 0x0B77
2. 0x0AC4: Disable OSD control register 0x0B76
3. 0x0AFE: Disable OSD control register 0x0B77

Leaves the initialization OSD enable at 0x4522 untouched.
"""

import sys
import os
import binascii
from typing import Tuple, List

# Patch locations: (file_offset, original_byte, patched_byte)
PATCHES = [
    (0x04D3, 0x01, 0x00),  # 0x04D0 + 3 (MOV A,#0x01)
    (0x0AC7, 0x01, 0x00),  # 0x0AC4 + 3 (MOV A,#0x01)
    (0x0B01, 0x01, 0x00),  # 0x0AFE + 3 (MOV A,#0x01)
]

def read_file(filename: str) -> bytes:
    """Read the entire file into a bytearray."""
    with open(filename, 'rb') as f:
        return bytearray(f.read())

def write_file(filename: str, data: bytes) -> None:
    """Write data to a file."""
    with open(filename, 'wb') as f:
        f.write(data)

def apply_patches(data: bytearray, patches: List[Tuple[int, int, int]]) -> List[Tuple[int, int, int]]:
    """Apply patches to the data and return a list of changes."""
    changes = []
    for offset, orig, new in patches:
        if offset >= len(data):
            print(f"Error: Offset 0x{offset:04X} is beyond file size (0x{len(data):X})")
            sys.exit(1)
            
        if data[offset] != orig:
            print(f"Warning: Expected 0x{orig:02X} at offset 0x{offset:04X}, found 0x{data[offset]:02X}")
        else:
            data[offset] = new
            changes.append((offset, orig, new))
    return changes

def format_hex_dump(data: bytes, address: int = 0, width: int = 16) -> str:
    """Format data as a hex dump."""
    result = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        result.append(f'0x{address + i:04X}: {hex_str.ljust(width*3)}  {ascii_str}')
    return '\n'.join(result)

def generate_diff_table(original: bytes, patched: bytes, patch_offsets: List[int], context: int = 8) -> str:
    """Generate a diff table showing changes with context."""
    diff_ranges = []
    
    # Create ranges around each patch location
    for offset in patch_offsets:
        start = max(0, offset - context)
        end = min(len(original), offset + 1 + context)
        diff_ranges.append((start, end))
    
    # Merge overlapping ranges
    if diff_ranges:
        diff_ranges.sort()
        merged = [list(diff_ranges[0])]
        for current in diff_ranges[1:]:
            last = merged[-1]
            if current[0] <= last[1]:
                last[1] = max(last[1], current[1])
            else:
                merged.append(list(current))
    else:
        merged = []
    
    # Generate diff output
    result = ["# Binary Diff Table\n"]
    result.append("| Offset (hex) | Original Bytes | Patched Bytes | Context |")
    result.append("|-------------|----------------|----------------|---------|")
    
    for start, end in merged:
        orig_chunk = original[start:end]
        patched_chunk = patched[start:end]
        
        # Find which bytes were changed in this range
        changed = [i for i in range(len(orig_chunk)) if orig_chunk[i] != patched_chunk[i]]
        
        # Format the bytes with changes highlighted
        orig_bytes = []
        patched_bytes = []
        
        for i, (o, p) in enumerate(zip(orig_chunk, patched_chunk)):
            addr = start + i
            if addr in patch_offsets:
                orig_bytes.append(f'**{o:02X}**')
                patched_bytes.append(f'**{p:02X}**')
            else:
                orig_bytes.append(f'{o:02X}')
                patched_bytes.append(f'{p:02X}')
        
        # Create context string
        context_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in orig_chunk)
        
        result.append(f"| 0x{start:04X} | {' '.join(orig_bytes)} | {' '.join(patched_bytes)} | `{context_str}` |")
    
    return '\n'.join(result)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <firmware.bin>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = "fw_postboot_only.bin"
    
    # Read the input file
    try:
        data = read_file(input_file)
    except Exception as e:
        print(f"Error reading {input_file}: {e}")
        sys.exit(1)
    
    # Check file size
    if len(data) != 0x20000:
        print(f"Error: Expected file size 0x20000, got 0x{len(data):X}")
        sys.exit(1)
    
    # Make a copy for patching
    patched_data = bytearray(data)
    
    # Apply patches
    changes = apply_patches(patched_data, PATCHES)
    
    if not changes:
        print("No changes were made (no matching bytes found).")
        sys.exit(0)
    
    # Write the patched file
    try:
        write_file(output_file, patched_data)
    except Exception as e:
        print(f"Error writing {output_file}: {e}")
        sys.exit(1)
    
    # Generate diff table
    patch_offsets = [offset for offset, _, _ in changes]
    diff_table = generate_diff_table(data, patched_data, patch_offsets)
    
    # Write diff table to file
    with open('bin_diff_table.md', 'w') as f:
        f.write(diff_table)
    
    # Print summary
    print("Patches applied successfully!")
    print(f"Original file: {input_file}")
    print(f"Patched file:  {output_file}")
    print("\nChanges made:")
    for offset, orig, new in changes:
        print(f"  Offset 0x{offset:04X}: 0x{orig:02X} -> 0x{new:02X}")
    
    print("\nDiff table written to bin_diff_table.md")

if __name__ == "__main__":
    main()
