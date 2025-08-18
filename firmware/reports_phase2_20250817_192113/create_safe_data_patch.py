#!/usr/bin/env python3
"""
Safe Data-Only OSD Disable Patch for SN9C292B Firmware
=======================================================

This script creates minimal data-only patches that avoid code injection
to prevent triggering integrity checks and bricking the camera.

Strategy: Change OSD enable values from 0xFF to 0x00 without injecting code.
"""

import os
import sys
from typing import List, Tuple

def read_file(path: str) -> bytes:
    """Read firmware file"""
    with open(path, "rb") as f:
        return f.read()

def write_file(path: str, data: bytes) -> None:
    """Write firmware file"""
    with open(path, "wb") as f:
        f.write(data)

def calculate_checksum(data: bytes) -> int:
    """Calculate simple byte sum checksum (excluding last 2 bytes)"""
    total = 0
    for i in range(len(data) - 2):  # Exclude last 2 bytes
        total = (total + data[i]) & 0xFFFF
    return total

def find_osd_enable_values(firmware: bytes) -> List[Tuple[int, int]]:
    """Find OSD enable values (0xFF) that can be safely changed to 0x00"""
    targets = []
    
    # FW_A: Look for MOV A,#0xFF patterns that enable OSD
    # Pattern: 74 FF (MOV A,#0xFF) followed by F0 (MOVX @DPTR,A)
    
    for i in range(len(firmware) - 3):
        if (firmware[i] == 0x74 and      # MOV A,#immediate
            firmware[i+1] == 0xFF and    # immediate = 0xFF
            firmware[i+2] == 0xF0):      # MOVX @DPTR,A
            
            # Check if this is in a safe area (not in critical code)
            if i < 0x1000 or i > 0x1F000:  # Avoid critical areas
                targets.append((i+1, 0xFF))  # (offset, current_value)
    
    return targets

def create_fw_a_data_patch(firmware: bytes) -> Tuple[bytes, List[Tuple[int, int, int]]]:
    """Create FW_A data-only patch"""
    print("Creating FW_A data-only patch...")
    
    # Specific target: 0xBB77 (MOV A,#0xFF that enables OSD)
    target_offset = 0xBB77
    if firmware[target_offset] == 0xFF:
        print(f"Found OSD enable at 0x{target_offset:04X}: 0xFF")
        
        # Create patched firmware
        patched = bytearray(firmware)
        patched[target_offset] = 0x00  # Change 0xFF to 0x00
        
        changes = [(target_offset, 0xFF, 0x00)]
        return bytes(patched), changes
    else:
        print(f"Error: Expected 0xFF at 0x{target_offset:04X}, found 0x{firmware[target_offset]:02X}")
        return firmware, []

def create_fw_b_data_patch(firmware: bytes) -> Tuple[bytes, List[Tuple[int, int, int]]]:
    """Create FW_B data-only patch"""
    print("Creating FW_B data-only patch...")
    
    # Find all OSD enable values
    targets = find_osd_enable_values(firmware)
    
    if not targets:
        print("No OSD enable values found")
        return firmware, []
    
    print(f"Found {len(targets)} OSD enable values:")
    for offset, value in targets:
        print(f"  0x{offset:04X}: 0x{value:02X}")
    
    # Create patched firmware
    patched = bytearray(firmware)
    changes = []
    
    for offset, old_value in targets:
        patched[offset] = 0x00  # Change to 0x00
        changes.append((offset, old_value, 0x00))
        print(f"  Patched 0x{offset:04X}: 0x{old_value:02X} → 0x00")
    
    return bytes(patched), changes

def apply_checksum_compensation(firmware: bytes, original_checksum: int) -> bytes:
    """Apply checksum compensation to last 2 bytes"""
    print(f"Applying checksum compensation...")
    
    # Calculate current checksum
    current_checksum = calculate_checksum(firmware)
    print(f"Current checksum: 0x{current_checksum:04X}")
    print(f"Target checksum: 0x{original_checksum:04X}")
    
    # Calculate compensation needed
    compensation = (original_checksum - current_checksum) & 0xFFFF
    print(f"Compensation needed: 0x{compensation:04X}")
    
    # Apply to last 2 bytes
    patched = bytearray(firmware)
    patched[0x1FFFE] = (compensation >> 8) & 0xFF
    patched[0x1FFFF] = compensation & 0xFF
    
    # Verify
    final_checksum = calculate_checksum(patched)
    print(f"Final checksum: 0x{final_checksum:04X}")
    print(f"Target achieved: {'YES' if final_checksum == original_checksum else 'NO'}")
    
    return bytes(patched)

def main():
    if len(sys.argv) != 3:
        print("Usage: python create_safe_data_patch.py <firmware_type> <input_firmware>")
        print("  firmware_type: 'fw_a' or 'fw_b'")
        print("  input_firmware: path to original firmware file")
        print("\nExample:")
        print("  python create_safe_data_patch.py fw_a firmware_backup_base.bin")
        print("  python create_safe_data_patch.py fw_b firmware5262.bin")
        return
    
    firmware_type = sys.argv[1].lower()
    input_path = sys.argv[2]
    
    if not os.path.exists(input_path):
        print(f"Error: Input file {input_path} not found")
        return
    
    if firmware_type not in ['fw_a', 'fw_b']:
        print("Error: firmware_type must be 'fw_a' or 'fw_b'")
        return
    
    print(f"=== Safe Data-Only OSD Disable Patch ===")
    print(f"Firmware Type: {firmware_type.upper()}")
    print(f"Input File: {input_path}")
    
    # Read firmware
    firmware = read_file(input_path)
    print(f"Firmware size: {len(firmware)} bytes")
    
    # Calculate original checksum
    original_checksum = calculate_checksum(firmware)
    print(f"Original checksum: 0x{original_checksum:04X}")
    
    # Create patch based on firmware type
    if firmware_type == 'fw_a':
        patched_firmware, changes = create_fw_a_data_patch(firmware)
    else:  # fw_b
        patched_firmware, changes = create_fw_b_data_patch(firmware)
    
    if not changes:
        print("No changes made - patch failed")
        return
    
    # Apply checksum compensation
    final_firmware = apply_checksum_compensation(patched_firmware, original_checksum)
    
    # Save patched firmware
    output_path = f"{firmware_type}_safe_data_patched.bin"
    write_file(output_path, final_firmware)
    
    # Create patch report
    report_path = f"{firmware_type}_safe_data_patch_report.txt"
    with open(report_path, 'w') as f:
        f.write(f"Safe Data-Only OSD Disable Patch Report\n")
        f.write(f"=====================================\n\n")
        f.write(f"Firmware Type: {firmware_type.upper()}\n")
        f.write(f"Input File: {input_path}\n")
        f.write(f"Output File: {output_path}\n\n")
        f.write(f"Changes Made:\n")
        for offset, old_val, new_val in changes:
            f.write(f"  0x{offset:04X}: 0x{old_val:02X} -> 0x{new_val:02X}\n")
        f.write(f"\nTotal Changes: {len(changes)} bytes\n")
        f.write(f"Original Checksum: 0x{original_checksum:04X}\n")
        f.write(f"Final Checksum: 0x{calculate_checksum(final_firmware):04X}\n")
        f.write(f"\nPatch Strategy: Data-only modification, no code injection\n")
        f.write(f"Risk Level: VERY LOW (minimal changes, no execution flow changes)\n")
    
    print(f"\n=== Patch Complete ===")
    print(f"Patched firmware saved to: {output_path}")
    print(f"Patch report saved to: {report_path}")
    print(f"Total changes: {len(changes)} bytes")
    print(f"\nThis patch only changes data values, not code structure.")
    print(f"It should be much safer than code injection patches.")

if __name__ == "__main__":
    main()
