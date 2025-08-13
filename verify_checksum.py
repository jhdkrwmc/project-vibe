#!/usr/bin/env python3
"""
Verify checksum calculation for SN9C292B firmware
"""

from pathlib import Path

def verify_checksum(firmware_path: str):
    """Verify the checksum of a firmware file"""
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    if len(data) != 0x20000:
        print(f"ERROR: Expected 0x20000 bytes, got {len(data):#x}")
        return
    
    # Calculate sum of bytes 0x0000 to 0x1FFD
    partial_sum = sum(data[0:0x1FFE]) & 0xFFFF
    
    # Read checksum from 0x1FFE-0x1FFF (little-endian)
    stored_checksum = (data[0x1FFF] << 8) | data[0x1FFE]
    
    # Calculate total sum
    total_sum = (partial_sum + stored_checksum) & 0xFFFF
    
    # Calculate recommended checksum
    recommended_checksum = (-partial_sum) & 0xFFFF
    
    print(f"Firmware: {firmware_path}")
    print(f"Size: {len(data):#x} bytes")
    print(f"Partial sum [0x0000..0x1FFD]: {partial_sum:#06x}")
    print(f"Stored checksum @ 0x1FFE-0x1FFF: {stored_checksum:#06x} (LE: {data[0x1FFE]:02X} {data[0x1FFF]:02X})")
    print(f"Total sum: {total_sum:#06x}")
    print(f"Verification: {'PASS' if total_sum == 0 else 'FAIL'}")
    print(f"Recommended checksum: {recommended_checksum:#06x} (LE: {recommended_checksum & 0xFF:02X} {(recommended_checksum >> 8) & 0xFF:02X})")
    
    return partial_sum, stored_checksum, total_sum, recommended_checksum

if __name__ == "__main__":
    # Check original firmware
    print("=== ORIGINAL FIRMWARE ===")
    verify_checksum("firmware_backup - Copy (4).bin")
    
    print("\n=== INTEGRITY BYPASS FIRMWARE ===")
    verify_checksum("out/fw_integrity_bypass_crc_fixed.bin") 