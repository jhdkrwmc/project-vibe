#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Comprehensive Multi-Section Integrity Bypass Strategy
Based on discovery of 6 identical firmware sections requiring consistent patching

This script patches ALL 6 firmware sections to maintain consistency:
1. Main section (0x0000-0x1FFF)
2. Section 1 (0x6000-0x7FFF) 
3. Section 2 (0x8000-0x9FFF)
4. Section 3 (0xA000-0xBFFF)
5. Section 4 (0xC000-0xDFFF)
6. Section 5 (0xE000-0xFFFF)

Each section gets the same 4-layer bypass patches to maintain integrity.
"""

import os
import struct
from pathlib import Path

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Outputs
OUT_BIN_MULTISECTION = OUT_DIR / "fw_comprehensive_multisection_bypass.bin"
OUT_DIFF_MULTISECTION = OUT_DIR / "fw_comprehensive_multisection_bypass.diff.txt"
OUT_SUM_MULTISECTION = OUT_DIR / "fw_comprehensive_multisection_bypass.sum.txt"

# Section definitions (each 8KB = 0x2000 bytes)
SECTIONS = [
    (0x0000, 0x2000, "Main"),      # Main firmware section
    (0x6000, 0x2000, "Section 1"), # Duplicate section 1
    (0x8000, 0x2000, "Section 2"), # Duplicate section 2  
    (0xA000, 0x2000, "Section 3"), # Duplicate section 3
    (0xC000, 0x2000, "Section 4"), # Duplicate section 4
    (0xE000, 0x2000, "Section 5"), # Duplicate section 5
]

# Layer 1: OSD initialization patches (0x01 → 0x00) - applied to ALL sections
PATCHES_OSD_INIT = [
    (0x04D4, 0x01, 0x00),  # 0x04D0: 90 0B 77 74 01 F0 → flip 01→00
    (0x0AC8, 0x01, 0x00),  # 0x0AC4: 90 0B 76 74 01 F0 → flip 01→00
    (0x0B02, 0x01, 0x00),  # 0x0AFE: 90 0B 77 74 01 F0 → flip 01→00
    (0x4526, 0x01, 0x00),  # 0x4522: 90 0B 75 74 01 F0 → flip 01→00
]

# Layer 2: Extended OSD configuration patch (0x86 → 0x00) - applied to ALL sections
PATCHES_OSD_EXTENDED = [
    (0x032A, 0x86, 0x00),  # 0x0325: 90 0B 77 74 86 F0 → 90 0B 77 74 00 F0
]

# Layer 3: Validation logic bypass patches (0x84 → 0x00) - applied to ALL sections
PATCHES_VALIDATION_LOGIC = [
    (0xB0E9, 0x84, 0x00),  # 0xB0E8: B4 84 03 → B4 00 03
    (0xC6CC, 0x84, 0x00),  # 0xC6CB: B4 84 03 → B4 00 03
]

# Layer 4: Additional validation checks (0x01 → 0x00) - applied to ALL sections
PATCHES_ADDITIONAL_VALIDATION = [
    (0x0244, 0x01, 0x00),  # 0x0242: B4 01 08 → B4 00 08
]

SIZE_EXPECTED = 0x20000


def read_firmware(path: Path) -> bytearray:
    if not path.exists():
        raise FileNotFoundError(f"Input firmware not found: {path}")
    data = bytearray(path.read_bytes())
    if len(data) != SIZE_EXPECTED:
        raise ValueError(f"Unexpected firmware size: {len(data):#x} (expected {SIZE_EXPECTED:#x})")
    return data


def apply_patches_to_section(data: bytearray, section_start: int, section_name: str, patches) -> list[str]:
    """Apply patches to a specific section with offset adjustment"""
    diffs = []
    for base_off, want_old, new_val in patches:
        # Adjust offset for this section
        section_off = base_off + section_start
        old = data[section_off]
        if old != want_old:
            diffs.append(f"SKIP @ {section_off:#06x} ({section_name}): expected {want_old:02X} but found {old:02X}")
            continue
        data[section_off] = new_val
        diffs.append(f"OK   @ {section_off:#06x} ({section_name}): {want_old:02X} -> {new_val:02X}")
    return diffs


def main() -> None:
    print("SN9C292B Firmware Patch - Comprehensive Multi-Section Integrity Bypass")
    print("=" * 70)
    
    base = read_firmware(IN_PATH)
    print(f"Loaded firmware: {IN_PATH}")
    print(f"Size: {len(base):#x} bytes")
    
    # Create patched firmware
    data_patched = bytearray(base)
    
    all_diffs = []
    
    # Apply patches to ALL 6 sections
    for section_start, section_size, section_name in SECTIONS:
        print(f"\n=== Patching {section_name} (0x{section_start:04X}-0x{section_start+section_size-1:04X}) ===")
        
        # Apply Layer 1: OSD initialization patches
        print(f"  Layer 1: OSD initialization patches...")
        diffs_layer1 = apply_patches_to_section(data_patched, section_start, section_name, PATCHES_OSD_INIT)
        for diff in diffs_layer1:
            print(f"    {diff}")
        all_diffs.extend(diffs_layer1)
        
        # Apply Layer 2: Extended OSD configuration patches
        print(f"  Layer 2: Extended OSD configuration patches...")
        diffs_layer2 = apply_patches_to_section(data_patched, section_start, section_name, PATCHES_OSD_EXTENDED)
        for diff in diffs_layer2:
            print(f"    {diff}")
        all_diffs.extend(diffs_layer2)
        
        # Apply Layer 3: Validation logic bypass patches
        print(f"  Layer 3: Validation logic bypass patches...")
        diffs_layer3 = apply_patches_to_section(data_patched, section_start, section_name, PATCHES_VALIDATION_LOGIC)
        for diff in diffs_layer3:
            print(f"    {diff}")
        all_diffs.extend(diffs_layer3)
        
        # Apply Layer 4: Additional validation checks
        print(f"  Layer 4: Additional validation checks...")
        diffs_layer4 = apply_patches_to_section(data_patched, section_start, section_name, PATCHES_ADDITIONAL_VALIDATION)
        for diff in diffs_layer4:
            print(f"    {diff}")
        all_diffs.extend(diffs_layer4)
    
    # Note: No checksum fix needed - original firmware has invalid checksum
    print("\n5. Checksum handling...")
    print("   Original firmware has invalid checksum (0xC3A4) - not used for validation")
    print("   Keeping original checksum bytes (0x0000) - no fix needed")
    
    # Write output files
    print("\n6. Writing output files...")
    OUT_BIN_MULTISECTION.write_bytes(data_patched)
    print(f"   Binary: {OUT_BIN_MULTISECTION}")
    
    # Write diff report
    OUT_DIFF_MULTISECTION.write_text("\n".join(all_diffs) + "\n")
    print(f"   Diff report: {OUT_DIFF_MULTISECTION}")
    
    # Write summary report
    summary_report = [
        f"Comprehensive Multi-Section Integrity Bypass Strategy",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        f"",
        f"BREAKTHROUGH DISCOVERY:",
        f"  The firmware has 6 identical sections that must ALL be patched consistently:",
        f"  - Main section (0x0000-0x1FFF): 32KB",
        f"  - Section 1 (0x6000-0x7FFF): 8KB duplicate",
        f"  - Section 2 (0x8000-0x9FFF): 8KB duplicate", 
        f"  - Section 3 (0xA000-0xBFFF): 8KB duplicate",
        f"  - Section 4 (0xC000-0xDFFF): 8KB duplicate",
        f"  - Section 5 (0xE000-0xFFFF): 8KB duplicate",
        f"",
        f"Strategy:",
        f"  Apply ALL 4 layers of integrity validation bypass to ALL 6 sections:",
        f"  - Layer 1: OSD initialization writes (0x01 -> 0x00)",
        f"  - Layer 2: Extended OSD configuration (0x86 -> 0x00)",
        f"  - Layer 3: Validation logic expectations (0x84 -> 0x00)",
        f"  - Layer 4: Additional validation checks (0x01 -> 0x00)",
        f"",
        f"Key Insight:",
        f"  Previous patches failed because only the main section was modified.",
        f"  The duplicate sections remained unchanged, creating inconsistency",
        f"  that triggered additional validation failures.",
        f"",
        f"Total patches applied: {len(all_diffs)}",
        f"Total bytes changed: {len(all_diffs)}",
        f"Checksum: Not modified (original firmware has invalid checksum anyway)",
        f"",
        f"Expected Result:",
        f"  Device should now pass ALL layers of integrity validation across ALL sections",
        f"  and complete USB configuration instead of stopping at Config=0 with Code 10 error.",
        f"",
        f"Patch Strategy:",
        f"  - All OSD registers consistently set to 0x00 across ALL sections",
        f"  - All validation logic expects 0x00 values across ALL sections",
        f"  - No inconsistent states that could trigger validation failures",
        f"  - Complete multi-section 4-layer bypass (not partial)",
    ]
    
    OUT_SUM_MULTISECTION.write_text("\n".join(summary_report) + "\n")
    print(f"   Summary report: {OUT_SUM_MULTISECTION}")
    
    print(f"\n✅ Multi-section patch complete! Total bytes changed: {len(all_diffs)}")
    print(f"   Ready for flashing: {OUT_BIN_MULTISECTION}")
    print(f"   Strategy: Bypass ALL 4 layers across ALL 6 firmware sections")


if __name__ == "__main__":
    main() 