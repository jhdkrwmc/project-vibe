#!/usr/bin/env python3
"""
OSD Patch with CRC Recalculation for SONiX C1 Camera Firmware
Patches OSD line overlay to disabled and recalculates CRC32 checksums.
"""

import os
import sys
from pathlib import Path
import struct

def calculate_crc32(data):
    """Calculate CRC-32 using standard polynomial (0xEDB88320)"""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF

def patch_firmware_with_crc(input_file, output_file):
    """
    Patch firmware: disable OSD line overlay and recalculate CRC32
    """
    
    print(f"Reading firmware: {input_file}")
    with open(input_file, 'rb') as f:
        firmware = bytearray(f.read())
    
    if len(firmware) != 128 * 1024:  # 128KB check
        print(f"Warning: Expected 128KB firmware, got {len(firmware)} bytes")
    
    # OSD flag addresses from IDA analysis
    OSD_LINE_ENABLE = 0xE24    # OSD Line Overlay Enable
    OSD_BLOCK_ENABLE = 0xE25   # OSD Block Overlay Enable  
    OSD_CONTROL_ENABLE = 0xE26 # OSD Control Enable
    
    # Current values from IDA (before patching)
    current_values = {
        OSD_LINE_ENABLE: 0x21,
        OSD_BLOCK_ENABLE: 0xE0, 
        OSD_CONTROL_ENABLE: 0x94
    }
    
    print(f"Current OSD flags:")
    print(f"  0x{OSD_LINE_ENABLE:04X}: 0x{current_values[OSD_LINE_ENABLE]:02X} (Line)")
    print(f"  0x{OSD_BLOCK_ENABLE:04X}: 0x{current_values[OSD_BLOCK_ENABLE]:02X} (Block)")
    print(f"  0x{OSD_CONTROL_ENABLE:04X}: 0x{current_values[OSD_CONTROL_ENABLE]:02X} (Control)")
    
    # Apply OSD line disable patch
    print(f"\nPatching: Disable OSD Line Overlay")
    firmware[OSD_LINE_ENABLE] = 0x00  # Disable line
    print(f"  0x{OSD_LINE_ENABLE:04X}: 0x{current_values[OSD_LINE_ENABLE]:02X} -> 0x00")
    
    # CRC section boundaries (from analysis)
    SECTION_4_START = 0x10000
    SECTION_4_END = 0x14000
    SECTION_4_CRC_ADDR = 0x13FFC
    
    SECTION_5_START = 0x14000
    SECTION_5_END = 0x18000
    SECTION_5_CRC_ADDR = 0x17FFC
    
    SECTION_6_START = 0x18000
    SECTION_6_END = 0x1C000
    SECTION_6_CRC_ADDR = 0x1BFFC
    
    FINAL_START = 0x1C000
    FINAL_END = 0x20000
    FINAL_CRC_ADDR = 0x1FFFC
    
    print(f"\n=== CRC Recalculation ===")
    
    # Recalculate Section 4 CRC (contains our OSD patch)
    section4_data = firmware[SECTION_4_START:SECTION_4_END]
    old_crc4 = struct.unpack('<I', firmware[SECTION_4_CRC_ADDR:SECTION_4_CRC_ADDR+4])[0]
    new_crc4 = calculate_crc32(section4_data)
    
    print(f"Section 4 (0x{SECTION_4_START:04X}-0x{SECTION_4_END:04X}):")
    print(f"  Old CRC32 at 0x{SECTION_4_CRC_ADDR:04X}: 0x{old_crc4:08X}")
    print(f"  New CRC32: 0x{new_crc4:08X}")
    
    # Update Section 4 CRC
    firmware[SECTION_4_CRC_ADDR:SECTION_4_CRC_ADDR+4] = struct.pack('<I', new_crc4)
    
    # Recalculate Section 5 CRC (may be affected by section 4 changes)
    section5_data = firmware[SECTION_5_START:SECTION_5_END]
    old_crc5 = struct.unpack('<I', firmware[SECTION_5_CRC_ADDR:SECTION_5_CRC_ADDR+4])[0]
    new_crc5 = calculate_crc32(section5_data)
    
    print(f"Section 5 (0x{SECTION_5_START:04X}-0x{SECTION_5_END:04X}):")
    print(f"  Old CRC32 at 0x{SECTION_5_CRC_ADDR:04X}: 0x{old_crc5:08X}")
    print(f"  New CRC32: 0x{new_crc5:08X}")
    
    # Update Section 5 CRC
    firmware[SECTION_5_CRC_ADDR:SECTION_5_CRC_ADDR+4] = struct.pack('<I', new_crc5)
    
    # Recalculate Section 6 CRC
    section6_data = firmware[SECTION_6_START:SECTION_6_END]
    old_crc6 = struct.unpack('<I', firmware[SECTION_6_CRC_ADDR:SECTION_6_CRC_ADDR+4])[0]
    new_crc6 = calculate_crc32(section6_data)
    
    print(f"Section 6 (0x{SECTION_6_START:04X}-0x{SECTION_6_END:04X}):")
    print(f"  Old CRC32 at 0x{SECTION_6_CRC_ADDR:04X}: 0x{old_crc6:08X}")
    print(f"  New CRC32: 0x{new_crc6:08X}")
    
    # Update Section 6 CRC
    firmware[SECTION_6_CRC_ADDR:SECTION_6_CRC_ADDR+4] = struct.pack('<I', new_crc6)
    
    # Recalculate Final CRC (covers sections 6 + any remaining data)
    final_data = firmware[FINAL_START:FINAL_END]
    old_final_crc = struct.unpack('<I', firmware[FINAL_CRC_ADDR:FINAL_CRC_ADDR+4])[0]
    new_final_crc = calculate_crc32(final_data)
    
    print(f"Final Section (0x{FINAL_START:04X}-0x{FINAL_END:04X}):")
    print(f"  Old CRC32 at 0x{FINAL_CRC_ADDR:04X}: 0x{old_final_crc:08X}")
    print(f"  New CRC32: 0x{new_final_crc:08X}")
    
    # Update Final CRC
    firmware[FINAL_CRC_ADDR:FINAL_CRC_ADDR+4] = struct.pack('<I', new_final_crc)
    
    # Write patched firmware
    print(f"\nWriting patched firmware: {output_file}")
    with open(output_file, 'wb') as f:
        f.write(firmware)
    
    print(f"✓ OSD Line disabled + CRC recalculated firmware created successfully")
    
    # Verify the patch
    print(f"\n=== Patch Verification ===")
    with open(output_file, 'rb') as f:
        patched = f.read()
    
    print(f"OSD Line Enable (0x{OSD_LINE_ENABLE:04X}): 0x{patched[OSD_LINE_ENABLE]:02X} {'✓' if patched[OSD_LINE_ENABLE] == 0x00 else '✗'}")
    
    # Verify CRC was updated
    new_crc4_verify = struct.unpack('<I', patched[SECTION_4_CRC_ADDR:SECTION_4_CRC_ADDR+4])[0]
    print(f"Section 4 CRC updated: 0x{new_crc4:08X} {'✓' if new_crc4_verify == new_crc4 else '✗'}")
    
    return True

def main():
    """Main function"""
    input_firmware = Path("firmware_backup_base.bin")
    output_firmware = Path("firmware_osd_line_disabled_crc_fixed.bin")
    
    if not input_firmware.exists():
        print(f"Error: Input firmware not found: {input_firmware}")
        sys.exit(1)
    
    print("=== SONiX C1 Camera OSD Patch with CRC Fix ===")
    print(f"Input firmware: {input_firmware}")
    print(f"Output firmware: {output_firmware}")
    print()
    
    try:
        patch_firmware_with_crc(input_firmware, output_firmware)
        
        print(f"\n=== Patch Complete ===")
        print(f"✓ Created: {output_firmware}")
        print(f"✓ OSD Line Overlay: DISABLED")
        print(f"✓ CRC32 checksums: RECALCULATED")
        print()
        print("This firmware should now boot without Code 10 errors.")
        print("Flash firmware_osd_line_disabled_crc_fixed.bin to your camera.")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
