#!/usr/bin/env python3
"""
SN9C292B Missing Validation Mechanism Finder
Based on deep analysis showing our 4-layer bypass is incomplete

This script searches for the missing validation logic that's still causing Code 10
after our comprehensive bypass patches.
"""

import os
import struct
from pathlib import Path

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Outputs
OUT_ANALYSIS = OUT_DIR / "missing_validation_analysis.txt"
OUT_PATTERNS = OUT_DIR / "validation_patterns.txt"

# Known validation patterns we've already bypassed
KNOWN_PATTERNS = [
    "90 0B 77 74 01 F0",  # OSD enable pattern 1
    "90 0B 76 74 01 F0",  # OSD enable pattern 2
    "90 0B 77 74 01 F0",  # OSD enable pattern 3
    "90 0B 75 74 01 F0",  # OSD enable pattern 4
    "90 0B 77 74 86 F0",  # Extended OSD configuration
    "B4 84 03",            # Validation logic pattern 1
    "B4 84 03",            # Validation logic pattern 2
    "B4 01 08",            # Additional validation check
]

# Search areas (active code sections)
SEARCH_AREAS = [
    (0x0000, 0x2000, "Main Code"),
    (0x6000, 0x8000, "Data Section 1"),
    (0x8000, 0xA000, "Data Section 2"),
    (0xA000, 0xC000, "Data Section 3"),
    (0xC000, 0xE000, "Data Section 4"),
    (0xE000, 0x10000, "Data Section 5"),
    (0x10000, 0x14000, "Extended Data"),
]

SIZE_EXPECTED = 0x20000


def read_firmware(path: Path) -> bytearray:
    if not path.exists():
        raise FileNotFoundError(f"Input firmware not found: {path}")
    data = bytearray(path.read_bytes())
    if len(data) != SIZE_EXPECTED:
        raise ValueError(f"Unexpected firmware size: {len(data):#x} (expected {SIZE_EXPECTED:#x})")
    return data


def search_for_patterns(data: bytearray) -> dict:
    """Search for potential validation patterns in the firmware"""
    patterns_found = {}
    
    # Search for common validation patterns
    for start, end, name in SEARCH_AREAS:
        print(f"Searching {name} (0x{start:04X}-0x{end-1:04X})...")
        section_patterns = []
        
        # Search for potential validation logic
        for i in range(start, min(end, len(data) - 16)):
            # Look for potential validation patterns
            chunk = data[i:i+16]
            
            # Pattern 1: OSD register access patterns
            if (i + 6 <= len(data) and 
                data[i] == 0x90 and 
                data[i+1] == 0x0B and
                data[i+2] in [0x75, 0x76, 0x77] and
                data[i+3] == 0x74):
                section_patterns.append({
                    "offset": f"0x{i:04X}",
                    "pattern": "OSD Register Access",
                    "bytes": " ".join(f"{b:02X}" for b in data[i:i+6]),
                    "context": " ".join(f"{b:02X}" for b in data[i:i+16])
                })
            
            # Pattern 2: Validation comparison patterns
            if (i + 3 <= len(data) and 
                data[i] == 0xB4 and
                data[i+2] in [0x03, 0x08, 0x0C]):
                section_patterns.append({
                    "offset": f"0x{i:04X}",
                    "pattern": "Validation Compare",
                    "bytes": " ".join(f"{b:02X}" for b in data[i:i+3]),
                    "context": " ".join(f"{b:02X}" for b in data[i:i+16])
                })
            
            # Pattern 3: Jump patterns that might indicate validation failure
            if (i + 2 <= len(data) and 
                data[i] in [0x02, 0x12] and
                data[i+1] in [0xA4, 0xA3, 0xA5]):
                section_patterns.append({
                    "offset": f"0x{i:04X}",
                    "pattern": "Potential Validation Jump",
                    "bytes": " ".join(f"{b:02X}" for b in data[i:i+2]),
                    "context": " ".join(f"{b:02X}" for b in data[i:i+16])
                })
            
            # Pattern 4: USB configuration patterns
            if (i + 4 <= len(data) and 
                data[i] == 0x09 and
                data[i+1] == 0x02 and
                data[i+2] in [0x01, 0x00]):
                section_patterns.append({
                    "offset": f"0x{i:04X}",
                    "pattern": "USB Configuration",
                    "bytes": " ".join(f"{b:02X}" for b in data[i:i+4]),
                    "context": " ".join(f"{b:02X}" for b in data[i:i+16])
                })
        
        if section_patterns:
            patterns_found[name] = section_patterns
            print(f"  Found {len(section_patterns)} potential patterns")
        else:
            print(f"  No patterns found")
    
    return patterns_found


def main() -> None:
    print("SN9C292B Missing Validation Mechanism Finder")
    print("=" * 50)
    
    base = read_firmware(IN_PATH)
    print(f"Loaded firmware: {IN_PATH}")
    print(f"Size: {len(base):#x} bytes")
    
    # Search for validation patterns
    print("\nSearching for missing validation mechanisms...")
    patterns = search_for_patterns(base)
    
    # Write analysis report
    print(f"\nWriting analysis report...")
    
    analysis_report = [
        f"Missing Validation Mechanism Analysis",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        f"",
        f"BACKGROUND:",
        f"  Our comprehensive 4-layer bypass failed with Code 10 error.",
        f"  This script searches for additional validation mechanisms we missed.",
        f"",
        f"KNOWN BYPASSED PATTERNS:",
    ]
    
    for pattern in KNOWN_PATTERNS:
        analysis_report.append(f"  - {pattern}")
    
    analysis_report.extend([
        f"",
        f"SEARCH RESULTS:",
        f"",
    ])
    
    for section_name, section_patterns in patterns.items():
        analysis_report.append(f"=== {section_name} ===")
        for pattern in section_patterns:
            analysis_report.append(f"  Offset: {pattern['offset']}")
            analysis_report.append(f"  Pattern: {pattern['pattern']}")
            analysis_report.append(f"  Bytes: {pattern['bytes']}")
            analysis_report.append(f"  Context: {pattern['context']}")
            analysis_report.append("")
    
    OUT_ANALYSIS.write_text("\n".join(analysis_report) + "\n")
    print(f"  Analysis report: {OUT_ANALYSIS}")
    
    # Write pattern summary
    pattern_summary = [
        f"Validation Pattern Summary",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        f"",
        f"Total patterns found: {sum(len(patterns) for patterns in patterns.values())}",
        f"",
    ]
    
    for section_name, section_patterns in patterns.items():
        pattern_summary.append(f"{section_name}: {len(section_patterns)} patterns")
    
    OUT_PATTERNS.write_text("\n".join(pattern_summary) + "\n")
    print(f"  Pattern summary: {OUT_PATTERNS}")
    
    print(f"\n✅ Analysis complete!")
    print(f"   Found {sum(len(patterns) for patterns in patterns.values())} potential validation patterns")
    print(f"   Check the reports for the missing validation mechanism")


if __name__ == "__main__":
    main() 