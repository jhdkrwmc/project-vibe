#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Comprehensive 4-Layer Integrity Bypass Strategy (CORRECTED)
Based on clean IDA Pro 8051 analysis with correct byte offsets

This script patches ALL layers of integrity validation:
1. OSD initialization writes (0x01 → 0x00)
2. Extended OSD configuration (0x86 → 0x00) 
3. Validation logic expectations (0x84 → 0x00)
4. Additional validation checks (0x01 → 0x00)
"""

import os
import struct
from pathlib import Path

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Outputs
OUT_BIN_COMPREHENSIVE_CORRECTED = OUT_DIR / "fw_comprehensive_bypass_corrected.bin"
OUT_DIFF_COMPREHENSIVE_CORRECTED = OUT_DIR / "fw_comprehensive_bypass_corrected.diff.txt"
OUT_SUM_COMPREHENSIVE_CORRECTED = OUT_DIR / "fw_comprehensive_bypass_corrected.sum.txt"

# Layer 1: OSD initialization patches (0x01 → 0x00)
PATCHES_OSD_INIT = [
    (0x04D4, 0x01, 0x00),  # 0x04D0: 90 0B 77 74 01 F0 → flip 01→00
    (0x0AC8, 0x01, 0x00),  # 0x0AC4: 90 0B 76 74 01 F0 → flip 01→00
    (0x0B02, 0x01, 0x00),  # 0x0AFE: 90 0B 77 74 01 F0 → flip 01→00
    (0x4526, 0x01, 0x00),  # 0x4522: 90 0B 75 74 01 F0 → flip 01→00
]

# Layer 2: Extended OSD configuration patch (0x86 → 0x00) - CORRECTED OFFSET
PATCHES_OSD_EXTENDED = [
    (0x032A, 0x86, 0x00),  # 0x0325: 90 0B 77 74 86 F0 → 90 0B 77 74 00 F0 (write 0x00 instead of 0x86)
]

# Layer 3: Validation logic bypass patches (0x84 → 0x00) - CORRECTED OFFSETS
PATCHES_VALIDATION_LOGIC = [
    (0xB0E9, 0x84, 0x00),  # 0xB0E8: B4 84 03 → B4 00 03 (expect 0x00 instead of 0x84)
    (0xC6CC, 0x84, 0x00),  # 0xC6CB: B4 84 03 → B4 00 03 (expect 0x00 instead of 0x84)
]

# Layer 4: Additional validation checks (0x01 → 0x00)
PATCHES_ADDITIONAL_VALIDATION = [
    (0x0244, 0x01, 0x00),  # 0x0242: B4 01 08 → B4 00 08 (expect 0x00 instead of 0x01)
]

SIZE_EXPECTED = 0x20000


def read_firmware(path: Path) -> bytearray:
    if not path.exists():
        raise FileNotFoundError(f"Input firmware not found: {path}")
    data = bytearray(path.read_bytes())
    if len(data) != SIZE_EXPECTED:
        raise ValueError(f"Unexpected firmware size: {len(data):#x} (expected {SIZE_EXPECTED:#x})")
    return data


def apply_patches(data: bytearray, patches) -> list[str]:
    diffs = []
    for off, want_old, new_val in patches:
        old = data[off]
        if old != want_old:
            diffs.append(f"SKIP @ {off:#06x}: expected {want_old:02X} but found {old:02X}")
            continue
        data[off] = new_val
        diffs.append(f"OK   @ {off:#06x}: {want_old:02X} -> {new_val:02X}")
    return diffs


def main() -> None:
    print("SN9C292B Firmware Patch - Comprehensive 4-Layer Integrity Bypass (CORRECTED)")
    print("=" * 70)
    
    base = read_firmware(IN_PATH)
    print(f"Loaded firmware: {IN_PATH}")
    print(f"Size: {len(base):#x} bytes")
    
    # Create patched firmware
    data_patched = bytearray(base)
    
    # Apply Layer 1: OSD initialization patches
    print("\n1. Applying Layer 1: OSD initialization patches...")
    diffs_layer1 = apply_patches(data_patched, PATCHES_OSD_INIT)
    for diff in diffs_layer1:
        print(f"   {diff}")
    
    # Apply Layer 2: Extended OSD configuration patches
    print("\n2. Applying Layer 2: Extended OSD configuration patches...")
    diffs_layer2 = apply_patches(data_patched, PATCHES_OSD_EXTENDED)
    for diff in diffs_layer2:
        print(f"   {diff}")
    
    # Apply Layer 3: Validation logic bypass patches
    print("\n3. Applying Layer 3: Validation logic bypass patches...")
    diffs_layer3 = apply_patches(data_patched, PATCHES_VALIDATION_LOGIC)
    for diff in diffs_layer3:
        print(f"   {diff}")
    
    # Apply Layer 4: Additional validation checks
    print("\n4. Applying Layer 4: Additional validation checks...")
    diffs_layer4 = apply_patches(data_patched, PATCHES_ADDITIONAL_VALIDATION)
    for diff in diffs_layer4:
        print(f"   {diff}")
    
    # Note: No checksum fix needed - original firmware has invalid checksum
    print("\n5. Checksum handling...")
    print("   Original firmware has invalid checksum (0xC3A4) - not used for validation")
    print("   Keeping original checksum bytes (0x0000) - no fix needed")
    
    # Write output files
    print("\n6. Writing output files...")
    OUT_BIN_COMPREHENSIVE_CORRECTED.write_bytes(data_patched)
    print(f"   Binary: {OUT_BIN_COMPREHENSIVE_CORRECTED}")
    
    # Write diff report
    all_diffs = diffs_layer1 + diffs_layer2 + diffs_layer3 + diffs_layer4
    OUT_DIFF_COMPREHENSIVE_CORRECTED.write_text("\n".join(all_diffs) + "\n")
    print(f"   Diff report: {OUT_DIFF_COMPREHENSIVE_CORRECTED}")
    
    # Write summary report
    summary_report = [
        f"Comprehensive 4-Layer Integrity Bypass Strategy (CORRECTED)",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        f"",
        f"Strategy:",
        f"  Address ALL 4 layers of integrity validation with CORRECTED byte offsets:",
        f"  - Layer 1: OSD initialization writes (0x01 -> 0x00)",
        f"  - Layer 2: Extended OSD configuration (0x86 -> 0x00) - CORRECTED OFFSET",
        f"  - Layer 3: Validation logic expectations (0x84 -> 0x00) - CORRECTED OFFSETS",
        f"  - Layer 4: Additional validation checks (0x01 -> 0x00)",
        f"",
        f"Key Insight from Clean IDA Pro Analysis:",
        f"  - Mixed FLIRTs were corrupting instruction decoding",
        f"  - Clean 8051 analysis revealed correct byte offsets",
        f"  - All 4 layers must be bypassed simultaneously for success",
        f"",
        f"Layer 1 - OSD Initialization Patches Applied:",
    ] + diffs_layer1 + [
        f"",
        f"Layer 2 - Extended OSD Configuration Patches Applied:",
    ] + diffs_layer2 + [
        f"",
        f"Layer 3 - Validation Logic Bypass Patches Applied:",
    ] + diffs_layer3 + [
        f"",
        f"Layer 4 - Additional Validation Check Patches Applied:",
    ] + diffs_layer4 + [
        f"",
        f"Total bytes changed: {len(all_diffs)}",
        f"Checksum: Not modified (original firmware has invalid checksum anyway)",
        f"",
        f"Expected Result:",
        f"  Device should now pass ALL layers of integrity validation and complete USB configuration",
        f"  instead of stopping at Config=0 with Code 10 error.",
        f"",
        f"Patch Strategy:",
        f"  - All OSD registers consistently set to 0x00",
        f"  - All validation logic expects 0x00 values",
        f"  - No inconsistent states that could trigger validation failures",
        f"  - Complete 4-layer bypass (not partial)",
    ]
    
    OUT_SUM_COMPREHENSIVE_CORRECTED.write_text("\n".join(summary_report) + "\n")
    print(f"   Summary report: {OUT_SUM_COMPREHENSIVE_CORRECTED}")
    
    print(f"\n✅ Comprehensive patch complete! Total bytes changed: {len(all_diffs)}")
    print(f"   Ready for flashing: {OUT_BIN_COMPREHENSIVE_CORRECTED}")
    print(f"   Strategy: Bypass ALL 4 layers of runtime integrity validation (CORRECTED)")


if __name__ == "__main__":
    main() 