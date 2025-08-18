#!/usr/bin/env python3
"""
Recovery Mode Firmware Analysis for SONiX C1 Camera
This script analyzes differences between recovery mode and normal mode firmware
to find where OSD settings are stored persistently.
"""

import os
import sys
import hashlib
from pathlib import Path

def calculate_file_hash(filepath):
    """Calculate SHA256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def find_differences(file1_path, file2_path, chunk_size=1024):
    """Find differences between two binary files"""
    differences = []
    
    if not os.path.exists(file1_path) or not os.path.exists(file2_path):
        print(f"❌ One or both files not found")
        return differences
    
    file1_size = os.path.getsize(file1_path)
    file2_size = os.path.getsize(file2_path)
    
    print(f"📁 File 1: {file1_path} ({file1_size} bytes)")
    print(f"📁 File 2: {file2_path} ({file2_size} bytes)")
    
    # Find the smaller file size for comparison
    min_size = min(file1_size, file2_size)
    
    with open(file1_path, 'rb') as f1, open(file2_path, 'rb') as f2:
        offset = 0
        while offset < min_size:
            chunk1 = f1.read(chunk_size)
            chunk2 = f2.read(chunk_size)
            
            if chunk1 != chunk2:
                # Find exact difference within this chunk
                for i, (b1, b2) in enumerate(zip(chunk1, chunk2)):
                    if b1 != b2:
                        diff_offset = offset + i
                        differences.append({
                            'offset': diff_offset,
                            'file1_byte': b1,
                            'file2_byte': b2,
                            'file1_hex': f"0x{b1:02X}",
                            'file2_hex': f"0x{b2:02X}"
                        })
            
            offset += chunk_size
    
    return differences

def analyze_osd_related_differences(differences):
    """Analyze differences that might be OSD-related"""
    osd_candidates = []
    
    # Known OSD-related addresses from previous analysis
    osd_addresses = [
        0xE24,  # OSD Line Enable
        0xE25,  # OSD Block Enable
        0xE26,  # OSD Control Enable
    ]
    
    for diff in differences:
        offset = diff['offset']
        
        # Check if this offset is near known OSD addresses
        for osd_addr in osd_addresses:
            if abs(offset - osd_addr) <= 16:  # Within 16 bytes
                osd_candidates.append({
                    **diff,
                    'near_osd': osd_addr,
                    'distance': abs(offset - osd_addr)
                })
        
        # Check if this looks like a configuration value
        if diff['file1_byte'] in [0x00, 0x01, 0xFF] and diff['file2_byte'] in [0x00, 0x01, 0xFF]:
            osd_candidates.append({
                **diff,
                'near_osd': None,
                'distance': None,
                'likely_config': True
            })
    
    return osd_candidates

def search_for_patterns(file_path, patterns):
    """Search for specific byte patterns in firmware"""
    results = {}
    
    if not os.path.exists(file_path):
        return results
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    for pattern_name, pattern_bytes in patterns.items():
        if isinstance(pattern_bytes, str):
            pattern_bytes = bytes.fromhex(pattern_bytes.replace('0x', ''))
        
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
    
    return results

def main():
    """Main analysis function"""
    print("🔍 SONiX C1 Recovery Mode Firmware Analysis")
    print("=" * 50)
    
    # Check for firmware files
    firmware_dir = Path(".")
    firmware_files = list(firmware_dir.glob("*.bin"))
    
    if not firmware_files:
        print("❌ No firmware files (.bin) found in current directory")
        print("Please place your firmware files here:")
        print("  - Normal mode firmware (e.g., firmware_backup_base.bin)")
        print("  - Recovery mode firmware (e.g., recovery_firmware.bin)")
        return
    
    print(f"📁 Found firmware files:")
    for f in firmware_files:
        size = f.stat().st_size
        hash_val = calculate_file_hash(f)
        print(f"  - {f.name}: {size} bytes, SHA256: {hash_val[:16]}...")
    
    print("\n🎯 Analysis Options:")
    print("1. Compare two firmware files for differences")
    print("2. Search for OSD-related patterns")
    print("3. Analyze specific firmware file")
    
    choice = input("\nEnter your choice (1-3): ").strip()
    
    if choice == "1":
        print("\n🔍 File Comparison Mode")
        file1 = input("Enter first firmware file path: ").strip()
        file2 = input("Enter second firmware file path: ").strip()
        
        if not file1 or not file2:
            print("❌ Please provide both file paths")
            return
        
        print(f"\n🔍 Comparing {file1} vs {file2}...")
        differences = find_differences(file1, file2)
        
        if differences:
            print(f"\n✅ Found {len(differences)} differences!")
            
            # Analyze OSD-related differences
            osd_candidates = analyze_osd_related_differences(differences)
            
            if osd_candidates:
                print(f"\n🎯 {len(osd_candidates)} OSD-related candidates found:")
                for candidate in osd_candidates[:20]:  # Show first 20
                    print(f"  Offset 0x{candidate['offset']:04X}: "
                          f"{candidate['file1_hex']} → {candidate['file2_hex']}")
                    if candidate['near_osd']:
                        print(f"    Near OSD address 0x{candidate['near_osd']:04X} "
                              f"(distance: {candidate['distance']})")
                    if candidate.get('likely_config'):
                        print(f"    Likely configuration value")
            else:
                print("\n⚠️ No obvious OSD-related differences found")
            
            # Show all differences (first 50)
            print(f"\n📊 First 50 differences:")
            for i, diff in enumerate(differences[:50]):
                print(f"  {i+1:2d}. 0x{diff['offset']:04X}: "
                      f"{diff['file1_hex']} → {diff['file2_hex']}")
            
            if len(differences) > 50:
                print(f"  ... and {len(differences) - 50} more differences")
        else:
            print("✅ No differences found between files")
    
    elif choice == "2":
        print("\n🔍 Pattern Search Mode")
        file_path = input("Enter firmware file path: ").strip()
        
        if not file_path:
            print("❌ Please provide file path")
            return
        
        # Common patterns to search for
        patterns = {
            "OSD_TAG_9A": "9A04",  # OSD enable command
            "OSD_TAG_9A_04": "9A04",
            "VID_0C45": "0C45",    # Vendor ID
            "PID_6366": "6366",    # Product ID
            "OSD_ENABLE": "E24E25", # OSD enable addresses
            "CRC32_FFFF": "FFFFFFFF", # CRC32 pattern
        }
        
        print(f"\n🔍 Searching for patterns in {file_path}...")
        results = search_for_patterns(file_path, patterns)
        
        for pattern_name, positions in results.items():
            print(f"  {pattern_name}: {len(positions)} occurrences")
            for pos in positions[:5]:  # Show first 5 positions
                print(f"    - 0x{pos:04X}")
            if len(positions) > 5:
                print(f"    ... and {len(positions) - 5} more")
    
    elif choice == "3":
        print("\n🔍 Single File Analysis Mode")
        file_path = input("Enter firmware file path: ").strip()
        
        if not file_path:
            print("❌ Please provide file path")
            return
        
        if not os.path.exists(file_path):
            print(f"❌ File {file_path} not found")
            return
        
        size = os.path.getsize(file_path)
        print(f"\n📁 File: {file_path}")
        print(f"📏 Size: {size} bytes (0x{size:04X})")
        
        # Analyze file structure
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Look for potential OSD configuration areas
        potential_configs = []
        for i in range(0, min(size, 0x1000), 4):  # Check first 4KB in 4-byte chunks
            if i + 4 <= size:
                chunk = data[i:i+4]
                # Look for patterns that might be configuration
                if chunk[0] in [0x00, 0x01, 0xFF] and chunk[1] in [0x00, 0x01, 0xFF]:
                    potential_configs.append((i, chunk.hex()))
        
        print(f"\n🔍 Found {len(potential_configs)} potential configuration areas in first 4KB:")
        for offset, hex_val in potential_configs[:20]:
            print(f"  0x{offset:04X}: {hex_val}")
    
    else:
        print("❌ Invalid choice")

if __name__ == "__main__":
    main()
