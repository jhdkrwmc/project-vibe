#!/usr/bin/env python3
"""
Simple Firmware Comparison Tool
Compares two firmware files and highlights OSD-related differences
"""

import sys
import os

def compare_firmware(file1, file2):
    """Compare two firmware files and find differences"""
    print(f"🔍 Comparing firmware files:")
    print(f"  File 1: {file1}")
    print(f"  File 2: {file2}")
    print()
    
    if not os.path.exists(file1) or not os.path.exists(file2):
        print("❌ One or both files not found")
        return
    
    # Read both files
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        data1 = f1.read()
        data2 = f2.read()
    
    size1, size2 = len(data1), len(data2)
    print(f"📏 File sizes: {size1} vs {size2} bytes")
    
    # Find differences
    differences = []
    min_size = min(size1, size2)
    
    for i in range(min_size):
        if data1[i] != data2[i]:
            differences.append((i, data1[i], data2[i]))
    
    print(f"🔍 Found {len(differences)} differences")
    
    if not differences:
        print("✅ No differences found")
        return
    
    # Focus on OSD-related areas
    osd_areas = [0xE24, 0xE25, 0xE26]  # Known OSD addresses
    osd_diffs = []
    
    for offset, byte1, byte2 in differences:
        # Check if this is near OSD addresses
        for osd_addr in osd_areas:
            if abs(offset - osd_addr) <= 16:  # Within 16 bytes
                osd_diffs.append((offset, byte1, byte2, osd_addr, abs(offset - osd_addr)))
                break
    
    if osd_diffs:
        print(f"\n🎯 {len(osd_diffs)} OSD-related differences found:")
        for offset, byte1, byte2, osd_addr, distance in osd_diffs:
            print(f"  0x{offset:04X}: 0x{byte1:02X} → 0x{byte2:02X} "
                  f"(near OSD 0x{osd_addr:04X}, distance: {distance})")
    else:
        print("\n⚠️ No OSD-related differences found")
    
    # Show first 20 differences
    print(f"\n📊 First 20 differences:")
    for i, (offset, byte1, byte2) in enumerate(differences[:20]):
        print(f"  {i+1:2d}. 0x{offset:04X}: 0x{byte1:02X} → 0x{byte2:02X}")
    
    if len(differences) > 20:
        print(f"  ... and {len(differences) - 20} more differences")
    
    # Look for configuration patterns
    config_patterns = []
    for offset, byte1, byte2 in differences:
        if byte1 in [0x00, 0x01, 0xFF] and byte2 in [0x00, 0x01, 0xFF]:
            config_patterns.append((offset, byte1, byte2))
    
    if config_patterns:
        print(f"\n⚙️ {len(config_patterns)} configuration-like differences:")
        for offset, byte1, byte2 in config_patterns[:10]:
            print(f"  0x{offset:04X}: 0x{byte1:02X} → 0x{byte2:02X}")

def main():
    """Main function"""
    print("🎥 SONiX C1 Firmware Comparison Tool")
    print("=" * 40)
    
    # Check for firmware files
    firmware_files = [f for f in os.listdir('.') if f.endswith('.bin')]
    
    if len(firmware_files) < 2:
        print("❌ Need at least 2 firmware files (.bin) for comparison")
        print(f"Found: {firmware_files}")
        return
    
    print(f"📁 Available firmware files:")
    for i, f in enumerate(firmware_files):
        size = os.path.getsize(f)
        print(f"  {i+1}. {f} ({size} bytes)")
    
    print()
    
    if len(firmware_files) == 2:
        # Auto-compare if only 2 files
        file1, file2 = firmware_files[0], firmware_files[1]
        print(f"🔄 Auto-comparing {file1} vs {file2}")
        compare_firmware(file1, file2)
    else:
        # Let user choose
        try:
            choice1 = int(input("Enter first file number: ")) - 1
            choice2 = int(input("Enter second file number: ")) - 1
            
            if 0 <= choice1 < len(firmware_files) and 0 <= choice2 < len(firmware_files):
                file1 = firmware_files[choice1]
                file2 = firmware_files[choice2]
                compare_firmware(file1, file2)
            else:
                print("❌ Invalid file numbers")
        except ValueError:
            print("❌ Please enter valid numbers")

if __name__ == "__main__":
    main()
