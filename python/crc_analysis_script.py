#!/usr/bin/env python3
"""
CRC Analysis Script for SONiX C1 Camera Firmware
Analyzes firmware structure to find CRC checksums and their locations.
"""

import os
import sys
from pathlib import Path
import struct

def analyze_firmware_structure(firmware_path):
    """Analyze firmware structure for potential CRC locations"""
    
    print(f"Analyzing firmware: {firmware_path}")
    with open(firmware_path, 'rb') as f:
        firmware = bytearray(f.read())
    
    if len(firmware) != 128 * 1024:
        print(f"Warning: Expected 128KB firmware, got {len(firmware)} bytes")
        return
    
    print(f"Firmware size: {len(firmware)} bytes")
    print()
    
    # Common CRC patterns and locations to check
    crc_patterns = [
        # Look for common CRC-32 patterns (little-endian)
        (0x00, 0x1F, "Start of firmware - potential header"),
        (0x1F00, 0x2000, "Header area - potential CRC"),
        (0x1FF0, 0x2000, "End of header - potential CRC"),
        (0x1FFC, 0x2000, "Last 4 bytes of header - potential CRC32"),
        (0x1FF8, 0x2000, "Last 8 bytes of header - potential CRC64"),
        (0x7F00, 0x8000, "Mid-firmware - potential section CRC"),
        (0x7FFC, 0x8000, "Mid-section end - potential CRC32"),
        (0xBF00, 0xC000, "Mid-firmware - potential section CRC"),
        (0xBFFC, 0xC000, "Mid-section end - potential CRC32"),
        (0xFF00, 0x10000, "Mid-firmware - potential section CRC"),
        (0xFFFC, 0x10000, "Mid-section end - potential CRC32"),
        (0x13F00, 0x14000, "Mid-firmware - potential section CRC"),
        (0x13FFC, 0x14000, "Mid-section end - potential CRC32"),
        (0x17F00, 0x18000, "Mid-firmware - potential section CRC"),
        (0x17FFC, 0x18000, "Mid-section end - potential CRC32"),
        (0x1BF00, 0x1C000, "Mid-firmware - potential section CRC"),
        (0x1BFFC, 0x1C000, "Mid-section end - potential CRC32"),
        (0x1FF00, 0x20000, "End of firmware - potential final CRC"),
        (0x1FFFC, 0x20000, "Last 4 bytes - potential CRC32"),
        (0x1FFF8, 0x20000, "Last 8 bytes - potential CRC64"),
    ]
    
    # Check for potential CRC locations
    print("=== CRC Pattern Analysis ===")
    potential_crcs = []
    
    for start, end, desc in crc_patterns:
        if start < len(firmware) and end <= len(firmware):
            # Look for non-zero patterns that could be CRC
            section = firmware[start:end]
            
            # Check if section ends with non-zero values (potential CRC)
            last_4 = section[-4:] if len(section) >= 4 else section
            last_8 = section[-8:] if len(section) >= 8 else section
            
            # Look for CRC-like patterns (non-zero, non-sequential)
            if any(b != 0 for b in last_4):
                potential_crcs.append({
                    'start': start,
                    'end': end,
                    'description': desc,
                    'last_4_bytes': ' '.join([f'{b:02X}' for b in last_4]),
                    'last_8_bytes': ' '.join([f'{b:02X}' for b in last_8]) if len(section) >= 8 else 'N/A'
                })
    
    # Display potential CRC locations
    for crc in potential_crcs:
        print(f"0x{crc['start']:04X}-0x{crc['end']:04X}: {crc['description']}")
        print(f"  Last 4 bytes: {crc['last_4_bytes']}")
        if crc['last_8_bytes'] != 'N/A':
            print(f"  Last 8 bytes: {crc['last_8_bytes']}")
        print()
    
    # Look for common CRC algorithms
    print("=== CRC Algorithm Detection ===")
    
    # Check for CRC-32 (common in embedded systems)
    # Look for polynomial patterns or known CRC values
    crc32_polynomials = [0x04C11DB7, 0xEDB88320, 0x82F63B78, 0x8F6E37A0]
    
    # Check for potential CRC tables or constants
    for i in range(0, len(firmware) - 4, 4):
        value = struct.unpack('<I', firmware[i:i+4])[0]
        if value in crc32_polynomials:
            print(f"Potential CRC-32 polynomial at 0x{i:04X}: 0x{value:08X}")
    
    # Check for potential checksum locations
    print("\n=== Checksum Location Analysis ===")
    
    # Common embedded checksum locations
    checksum_locations = [
        (0x1FFC, "Header CRC32"),
        (0x1FF8, "Header CRC64"),
        (0x7FFC, "Section 1 CRC32"),
        (0xBFFC, "Section 2 CRC32"),
        (0xFFFC, "Section 3 CRC32"),
        (0x13FFC, "Section 4 CRC32"),
        (0x17FFC, "Section 5 CRC32"),
        (0x1BFFC, "Section 6 CRC32"),
        (0x1FFFC, "Final CRC32"),
    ]
    
    for addr, desc in checksum_locations:
        if addr < len(firmware):
            value = struct.unpack('<I', firmware[addr:addr+4])[0]
            print(f"0x{addr:04X}: {desc} = 0x{value:08X}")
    
    return potential_crcs

def main():
    """Main function"""
    firmware_path = Path("firmware_backup_base.bin")
    
    if not firmware_path.exists():
        print(f"Error: Firmware not found: {firmware_path}")
        sys.exit(1)
    
    print("=== SONiX C1 Camera CRC Analysis ===")
    print()
    
    crc_locations = analyze_firmware_structure(firmware_path)
    
    print("=== Analysis Complete ===")
    print("Use this information to identify CRC locations for patching.")

if __name__ == "__main__":
    main()
