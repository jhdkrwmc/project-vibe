#!/usr/bin/env python3
"""
Create integrity-safe OSD-off patch for SN9C292B firmware
"""

import os
import sys
from typing import Tuple

def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def write_file(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)

def calculate_sum16(data: bytes) -> int:
    """Calculate 16-bit word sum of firmware"""
    total = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) | data[i+1]
        else:
            word = data[i] << 8
        total = (total + word) & 0xFFFF
    return total

def create_osd_off_patch(firmware_path: str, output_path: str) -> None:
    """Create OSD-off patch with integrity preservation"""
    
    print(f"Loading firmware: {firmware_path}")
    firmware = read_file(firmware_path)
    
    if len(firmware) != 0x20000:
        print(f"Error: Expected 128KB firmware, got {len(firmware)} bytes")
        return
    
    print(f"Original SUM16: 0x{calculate_sum16(firmware):04X}")
    
    # OSD-off stub: clear 0xE24-0xE27 to 0x00
    stub = bytes([
        0x90, 0x0E, 0x24,  # MOV DPTR,#0x0E24
        0x74, 0x00,         # MOV A,#0x00
        0xF0,               # MOVX @DPTR,A
        0xA3,               # INC DPTR
        0x74, 0x00,         # MOV A,#0x00
        0xF0,               # MOVX @DPTR,A
        0xA3,               # INC DPTR
        0x74, 0x00,         # MOV A,#0x00
        0xF0,               # MOVX @DPTR,A
        0xA3,               # INC DPTR
        0x74, 0x00,         # MOV A,#0x00
        0xF0,               # MOVX @DPTR,A
        0x22                # RET
    ])
    
    print(f"OSD-off stub ({len(stub)} bytes):")
    print(" ".join(f"{b:02X}" for b in stub))
    
    # Injection site: replace LCALL at 0xF0A6 with LCALL to our stub
    # Original: 12 14 D9 (LCALL 0x14D9)
    # New: 12 F0 C0 (LCALL 0xF0C0 where we place the stub)
    
    injection_site = 0xF0A6
    stub_location = 0xF0C0
    
    print(f"\nInjection site: 0x{injection_site:04X}")
    print(f"Stub location: 0x{stub_location:04X}")
    
    # Create patched firmware
    patched = bytearray(firmware)
    
    # Place stub at 0xF0C0
    patched[stub_location:stub_location+len(stub)] = stub
    
    # Replace LCALL at 0xF0A6: 12 14 D9 -> 12 F0 C0
    patched[injection_site] = 0x12      # LCALL
    patched[injection_site+1] = 0xF0   # High byte of stub address
    patched[injection_site+2] = 0xC0   # Low byte of stub address
    
    print(f"\nPatch details:")
    print(f"0x{injection_site:04X}: 12 14 D9 -> 12 F0 C0 (LCALL to stub)")
    print(f"0x{stub_location:04X}: Inserted {len(stub)}-byte OSD-off stub")
    
    # Calculate new checksum
    new_sum16 = calculate_sum16(patched)
    print(f"New SUM16: 0x{new_sum16:04X}")
    
    # Compensate checksum by adjusting the last two bytes
    # We want SUM16 to be 0x0000
    target_sum = 0x0000
    current_sum = new_sum16
    
    # Calculate compensation needed
    compensation = (target_sum - current_sum) & 0xFFFF
    print(f"Checksum compensation needed: 0x{compensation:04X}")
    
    # Apply compensation to last two bytes
    last_word = (patched[0x1FFFE] << 8) | patched[0x1FFFF]
    new_last_word = (last_word + compensation) & 0xFFFF
    
    patched[0x1FFFE] = (new_last_word >> 8) & 0xFF
    patched[0x1FFFF] = new_last_word & 0xFF
    
    # Verify final checksum
    final_sum16 = calculate_sum16(patched)
    print(f"Final SUM16: 0x{final_sum16:04X}")
    
    if final_sum16 == target_sum:
        print("✓ Checksum compensation successful!")
    else:
        print(f"✗ Checksum compensation failed! Expected 0x{target_sum:04X}, got 0x{final_sum16:04X}")
        return
    
    # Write patched firmware
    write_file(output_path, bytes(patched))
    print(f"\nPatched firmware written to: {output_path}")
    
    # Show patch summary
    print(f"\n=== Patch Summary ===")
    print(f"Original firmware: {firmware_path}")
    print(f"Patched firmware: {output_path}")
    print(f"Original SUM16: 0x{calculate_sum16(firmware):04X}")
    print(f"Final SUM16: 0x{final_sum16:04X}")
    print(f"OSD-off stub: 0x{stub_location:04X} ({len(stub)} bytes)")
    print(f"Injection site: 0x{injection_site:04X} (LCALL to stub)")
    print(f"Checksum compensation: 0x{compensation:04X}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python create_osd_off_patch.py <input_firmware> <output_firmware>")
        print("Example: python create_osd_off_patch.py firmware_backup_base.bin firmware_osd_off.bin")
        return
    
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    
    if not os.path.exists(input_path):
        print(f"Error: Input file {input_path} not found")
        return
    
    create_osd_off_patch(input_path, output_path)

if __name__ == "__main__":
    main()
