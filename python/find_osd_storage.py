#!/usr/bin/env python3
"""
Find OSD Storage Location in SONiX C1 Firmware
This script searches for where OSD settings are actually stored persistently.
"""

import os
import sys
import struct
from pathlib import Path

def search_for_osd_patterns(firmware_path):
    """Search for OSD-related patterns in firmware"""
    print(f"🔍 Searching for OSD patterns in {firmware_path}")
    
    if not os.path.exists(firmware_path):
        print(f"❌ File {firmware_path} not found")
        return
    
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    print(f"📏 Firmware size: {len(data)} bytes (0x{len(data):04X})")
    
    # Known OSD patterns to search for
    patterns = {
        "OSD_TAG_9A_04": b'\x9A\x04',           # OSD enable command
        "OSD_ENABLE_LINE": b'\xE2\x04',         # OSD line enable address
        "OSD_ENABLE_BLOCK": b'\xE2\x05',        # OSD block enable address
        "OSD_CONTROL": b'\xE2\x06',             # OSD control address
        "VID_0C45": b'\x0C\x45',                # Vendor ID
        "PID_6366": b'\x63\x66',                # Product ID
        "OSD_STRING": b'OSD',                   # OSD string
        "ENABLE_STRING": b'Enable',             # Enable string
        "LINE_STRING": b'Line',                 # Line string
        "BLOCK_STRING": b'Block',               # Block string
    }
    
    results = {}
    
    for pattern_name, pattern_bytes in patterns.items():
        positions = []
        start = 0
        
        while True:
            pos = data.find(pattern_bytes, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        
        if positions:
            results[pattern_name] = positions
            print(f"✅ {pattern_name}: {len(positions)} occurrences")
            
            # Show context around first few occurrences
            for i, pos in enumerate(positions[:3]):
                context_start = max(0, pos - 16)
                context_end = min(len(data), pos + 16)
                context = data[context_start:context_end]
                
                print(f"   {i+1}. 0x{pos:04X}: {context.hex(' ')}")
                
                # Try to decode as ASCII if it looks like text
                try:
                    ascii_context = context.decode('ascii', errors='ignore')
                    if any(c.isprint() for c in ascii_context):
                        print(f"      ASCII: {ascii_context}")
                except:
                    pass
        else:
            print(f"❌ {pattern_name}: Not found")
    
    return results

def search_for_configuration_areas(firmware_path):
    """Search for areas that might contain configuration data"""
    print(f"\n🔍 Searching for configuration areas in {firmware_path}")
    
    if not os.path.exists(firmware_path):
        return
    
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    # Look for potential configuration areas
    # These are areas with repeated 0x00, 0x01, 0xFF values
    config_candidates = []
    
    for i in range(0, len(data) - 64, 64):  # Check in 64-byte chunks
        chunk = data[i:i+64]
        
        # Count configuration-like bytes
        config_bytes = sum(1 for b in chunk if b in [0x00, 0x01, 0xFF])
        
        if config_bytes >= 32:  # At least half the chunk looks like config
            config_candidates.append((i, config_bytes, chunk))
    
    print(f"🔍 Found {len(config_candidates)} potential configuration areas:")
    
    for offset, config_count, chunk in config_candidates[:10]:  # Show first 10
        print(f"  0x{offset:04X}: {config_count}/64 config bytes")
        
        # Show first 16 bytes of the chunk
        hex_chunk = chunk[:16].hex(' ')
        print(f"    Data: {hex_chunk}")
        
        # Try to find OSD-related values in this area
        for i in range(len(chunk) - 2):
            if chunk[i] == 0xE2 and chunk[i+1] in [0x04, 0x05, 0x06]:
                print(f"    ⭐ OSD address 0x{chunk[i]:02X}{chunk[i+1]:02X} at offset +{i}")
    
    return config_candidates

def search_for_osd_default_values(firmware_path):
    """Search for where OSD default values might be stored"""
    print(f"\n🔍 Searching for OSD default values in {firmware_path}")
    
    if not os.path.exists(firmware_path):
        return
    
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    # Look for sequences that might be OSD defaults
    # Common patterns: 0x01 0x01 (both enabled) or 0x00 0x00 (both disabled)
    osd_default_patterns = [
        (b'\x01\x01', "OSD Line=1, Block=1 (both enabled)"),
        (b'\x00\x00', "OSD Line=0, Block=0 (both disabled)"),
        (b'\x01\x00', "OSD Line=1, Block=0 (line only)"),
        (b'\x00\x01', "OSD Line=0, Block=1 (block only)"),
    ]
    
    for pattern, description in osd_default_patterns:
        positions = []
        start = 0
        
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        
        if positions:
            print(f"✅ {description}: {len(positions)} occurrences")
            
            # Show context around first few
            for i, pos in enumerate(positions[:3]):
                context_start = max(0, pos - 8)
                context_end = min(len(data), pos + 8)
                context = data[context_start:context_end]
                
                print(f"   {i+1}. 0x{pos:04X}: {context.hex(' ')}")
                
                # Check if this is near known OSD addresses
                for osd_addr in [0xE24, 0xE25, 0xE26]:
                    if abs(pos - osd_addr) <= 16:
                        print(f"      ⭐ Near OSD address 0x{osd_addr:04X} (distance: {abs(pos - osd_addr)})")
        else:
            print(f"❌ {description}: Not found")

def analyze_firmware_structure(firmware_path):
    """Analyze the overall structure of the firmware"""
    print(f"\n🔍 Analyzing firmware structure: {firmware_path}")
    
    if not os.path.exists(firmware_path):
        return
    
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    size = len(data)
    
    # Look for common firmware structures
    print(f"📏 Total size: {size} bytes (0x{size:04X})")
    
    # Check if this looks like a typical 8051 firmware
    if size == 128 * 1024:  # 128KB
        print("✅ 128KB firmware (typical 8051 size)")
        
        # Look for common sections
        sections = [
            (0x0000, 0x7FFF, "Code section 1"),
            (0x8000, 0xBFFF, "Code section 2"),
            (0xC000, 0xFFFF, "Data/Config section"),
        ]
        
        for start, end, name in sections:
            if end <= size:
                section_data = data[start:end]
                non_zero = sum(1 for b in section_data if b != 0x00)
                print(f"  {name} (0x{start:04X}-0x{end:04X}): {non_zero}/{end-start} non-zero bytes")
    
    # Look for potential configuration areas at the end
    if size >= 0x1000:
        end_section = data[-0x1000:]  # Last 4KB
        non_zero_end = sum(1 for b in end_section if b != 0x00)
        print(f"📝 Last 4KB: {non_zero_end}/0x1000 non-zero bytes (potential config area)")

def main():
    """Main function"""
    print("🎥 SONiX C1 OSD Storage Finder")
    print("=" * 40)
    
    # Check for firmware files
    firmware_files = list(Path(".").glob("*.bin"))
    
    if not firmware_files:
        print("❌ No firmware files (.bin) found in current directory")
        print("Please place your firmware files here and run again")
        return
    
    print(f"📁 Found firmware files:")
    for f in firmware_files:
        size = f.stat().st_size
        print(f"  - {f.name}: {size} bytes")
    
    print(f"\n🎯 Analysis Options:")
    print("1. Search for OSD patterns in specific firmware")
    print("2. Search for configuration areas")
    print("3. Search for OSD default values")
    print("4. Analyze firmware structure")
    print("5. Full analysis of all firmware files")
    
    choice = input("\nEnter your choice (1-5): ").strip()
    
    if choice == "1":
        file_path = input("Enter firmware file path: ").strip()
        if file_path:
            search_for_osd_patterns(file_path)
    
    elif choice == "2":
        file_path = input("Enter firmware file path: ").strip()
        if file_path:
            search_for_configuration_areas(file_path)
    
    elif choice == "3":
        file_path = input("Enter firmware file path: ").strip()
        if file_path:
            search_for_osd_default_values(file_path)
    
    elif choice == "4":
        file_path = input("Enter firmware file path: ").strip()
        if file_path:
            analyze_firmware_structure(file_path)
    
    elif choice == "5":
        print("\n🚀 Running full analysis on all firmware files...")
        for firmware_file in firmware_files:
            print(f"\n{'='*60}")
            print(f"📁 Analyzing: {firmware_file.name}")
            print(f"{'='*60}")
            
            search_for_osd_patterns(str(firmware_file))
            search_for_configuration_areas(str(firmware_file))
            search_for_osd_default_values(str(firmware_file))
            analyze_firmware_structure(str(firmware_file))
    
    else:
        print("❌ Invalid choice")

if __name__ == "__main__":
    main()
