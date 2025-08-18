#!/usr/bin/env python3
"""
OSD Patch Script for SONiX C1 Camera Firmware
Creates two patched firmware files with minimal OSD changes to avoid CRC issues.

Usage: python osd_patch_script.py
"""

import os
import sys
from pathlib import Path

def patch_firmware(input_file, output_file, patch_type):
    """
    Patch firmware file with OSD disable patches
    
    Args:
        input_file: Path to input firmware file
        output_file: Path to output patched firmware file  
        patch_type: Either 'line' or 'block' to disable specific OSD overlay
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
    
    # Apply patches based on type
    if patch_type == 'line':
        print(f"\nPatching: Disable OSD Line Overlay only")
        firmware[OSD_LINE_ENABLE] = 0x00  # Disable line
        print(f"  0x{OSD_LINE_ENABLE:04X}: 0x{current_values[OSD_LINE_ENABLE]:02X} -> 0x00")
        
    elif patch_type == 'block':
        print(f"\nPatching: Disable OSD Block Overlay only")  
        firmware[OSD_BLOCK_ENABLE] = 0x00  # Disable block
        print(f"  0x{OSD_BLOCK_ENABLE:04X}: 0x{current_values[OSD_BLOCK_ENABLE]:02X} -> 0x00")
        
    else:
        raise ValueError(f"Invalid patch_type: {patch_type}. Use 'line' or 'block'")
    
    # Write patched firmware
    print(f"Writing patched firmware: {output_file}")
    with open(output_file, 'wb') as f:
        f.write(firmware)
    
    print(f"✓ {patch_type.capitalize()} OSD disabled firmware created successfully")
    return True

def main():
    """Main function to create both patched firmware files"""
    
    # Get firmware directory
    script_dir = Path(__file__).parent
    firmware_dir = script_dir
    
    # Input firmware (use the first backup)
    input_firmware = firmware_dir / "firmware_backup_base.bin"
    
    if not input_firmware.exists():
        print(f"Error: Input firmware not found: {input_firmware}")
        sys.exit(1)
    
    print("=== SONiX C1 Camera OSD Patch Script ===")
    print(f"Input firmware: {input_firmware}")
    print(f"Firmware size: {input_firmware.stat().st_size} bytes")
    print()
    
    # Create OSD Line disabled firmware
    line_output = firmware_dir / "firmware_osd_line_disabled.bin"
    try:
        patch_firmware(input_firmware, line_output, 'line')
    except Exception as e:
        print(f"Error creating line-disabled firmware: {e}")
        sys.exit(1)
    
    print()
    
    # Create OSD Block disabled firmware  
    block_output = firmware_dir / "firmware_osd_block_disabled.bin"
    try:
        patch_firmware(input_firmware, block_output, 'block')
    except Exception as e:
        print(f"Error creating block-disabled firmware: {e}")
        sys.exit(1)
    
    print()
    print("=== Patch Summary ===")
    print(f"✓ Line overlay disabled: {line_output}")
    print(f"✓ Block overlay disabled: {block_output}")
    print()
    print("Flash these firmwares one at a time to test:")
    print("1. Try firmware_osd_line_disabled.bin first")
    print("2. If it boots, OSD line was the issue")
    print("3. If it doesn't boot, try firmware_osd_block_disabled.bin")
    print("4. If neither boots, there may be CRC checks or other issues")
    print()
    print("Note: These are minimal patches to avoid CRC problems.")
    print("Power cycle with SPI shorted to GND if firmware doesn't boot.")

if __name__ == "__main__":
    main()
