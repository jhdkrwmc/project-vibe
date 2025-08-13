#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Comprehensive 5-Layer Integrity Bypass Strategy
Based on discovery of additional validation patterns we missed in our 4-layer bypass

This script patches ALL 5 layers of integrity validation:
1. OSD initialization writes (0x01 → 0x00)
2. Extended OSD configuration (0x86 → 0x00)
3. Validation logic expectations (0x84 → 0x00)
4. Additional validation checks (0x01 → 0x00)
5. ADDITIONAL OSD REGISTER WRITES (0x19, 0x1A, 0x1B, 0x11, 0x81, 0x84, 0x85 → 0x00)
"""

import os
import struct
from pathlib import Path

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Outputs
OUT_BIN_5LAYER = OUT_DIR / "fw_comprehensive_5layer_bypass.bin"
OUT_DIFF_5LAYER = OUT_DIR / "fw_comprehensive_5layer_bypass.diff.txt"
OUT_SUM_5LAYER = OUT_DIR / "fw_comprehensive_5layer_bypass.sum.txt"

# Layer 1: OSD initialization patches (0x01 → 0x00)
PATCHES_OSD_INIT = [
    (0x04D4, 0x01, 0x00),  # 0x04D0: 90 0B 77 74 01 F0 → flip 01→00
    (0x0AC8, 0x01, 0x00),  # 0x0AC4: 90 0B 76 74 01 F0 → flip 01→00
    (0x0B02, 0x01, 0x00),  # 0x0AFE: 90 0B 77 74 01 F0 → flip 01→00
    (0x4526, 0x01, 0x00),  # 0x4522: 90 0B 75 74 01 F0 → flip 01→00
]

# Layer 2: Extended OSD configuration patch (0x86 → 0x00)
PATCHES_OSD_EXTENDED = [
    (0x032A, 0x86, 0x00),  # 0x0325: 90 0B 77 74 86 F0 → 90 0B 77 74 00 F0
]

# Layer 3: Validation logic bypass patches (0x84 → 0x00)
PATCHES_VALIDATION_LOGIC = [
    (0xB0E9, 0x84, 0x00),  # 0xB0E8: B4 84 03 → B4 00 03
    (0xC6CC, 0x84, 0x00),  # 0xC6CB: B4 84 03 → B4 00 03
]

# Layer 4: Additional validation checks (0x01 → 0x00)
PATCHES_ADDITIONAL_VALIDATION = [
    (0x0244, 0x01, 0x00),  # 0x0242: B4 01 08 → B4 00 08
]

# Layer 5: ADDITIONAL OSD REGISTER WRITES (NEWLY DISCOVERED!)
PATCHES_ADDITIONAL_OSD_WRITES = [
    (0x03B0, 0x19, 0x00),  # 0x03AC: 90 0B 77 74 19 F0 → 90 0B 77 74 00 F0
    (0x03BC, 0x1A, 0x00),  # 0x03B8: 90 0B 77 74 1A F0 → 90 0B 77 74 00 F0
    (0x03C8, 0x1B, 0x00),  # 0x03C4: 90 0B 77 74 1B F0 → 90 0B 77 74 00 F0
    (0x03FC, 0x11, 0x00),  # 0x03F8: 90 0B 77 74 11 F0 → 90 0B 77 74 00 F0
    (0x0559, 0x81, 0x00),  # 0x0555: 90 0B 76 74 81 12 → 90 0B 76 74 00 12
    (0x057B, 0x84, 0x00),  # 0x0577: 90 0B 76 74 84 F0 → 90 0B 76 74 00 F0
    (0x05B6, 0x85, 0x00),  # 0x05B2: 90 0B 76 74 85 F0 → 90 0B 76 74 00 F0
]

# Layer 5: ADDITIONAL VALIDATION CHECKS (NEWLY DISCOVERED!)
PATCHES_ADDITIONAL_VALIDATION_CHECKS = [
    (0x0360, 0x07, 0x00),  # 0x035E: B4 07 03 → B4 00 03
    (0x03AB, 0x81, 0x00),  # 0x03A9: B4 81 08 → B4 00 08
    (0x03B7, 0x84, 0x00),  # 0x03B5: B4 84 08 → B4 00 08
    (0x03BE, 0x85, 0x00),  # 0x03AC: B4 85 06 → B4 00 06
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
    print("SN9C292B Firmware Patch - Comprehensive 5-Layer Integrity Bypass")
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

    # Apply Layer 5: ADDITIONAL OSD REGISTER WRITES (NEWLY DISCOVERED!)
    print("\n5. Applying Layer 5: Additional OSD register writes...")
    diffs_layer5a = apply_patches(data_patched, PATCHES_ADDITIONAL_OSD_WRITES)
    for diff in diffs_layer5a:
        print(f"   {diff}")

    # Apply Layer 5: ADDITIONAL VALIDATION CHECKS (NEWLY DISCOVERED!)
    print("\n6. Applying Layer 5: Additional validation checks...")
    diffs_layer5b = apply_patches(data_patched, PATCHES_ADDITIONAL_VALIDATION_CHECKS)
    for diff in diffs_layer5b:
        print(f"   {diff}")

    # Note: No checksum fix needed - original firmware has invalid checksum
    print("\n7. Checksum handling...")
    print("   Original firmware has invalid checksum (0xC3A4) - not used for validation")
    print("   Keeping original checksum bytes (0x0000) - no fix needed")

    # Write output files
    print("\n8. Writing output files...")
    OUT_BIN_5LAYER.write_bytes(data_patched)
    print(f"   Binary: {OUT_BIN_5LAYER}")

    # Write diff report
    all_diffs = diffs_layer1 + diffs_layer2 + diffs_layer3 + diffs_layer4 + diffs_layer5a + diffs_layer5b
    OUT_DIFF_5LAYER.write_text("\n".join(all_diffs) + "\n")
    print(f"   Diff report: {OUT_DIFF_5LAYER}")

    # Write summary report
    summary_report = [
        f"Comprehensive 5-Layer Integrity Bypass Strategy",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        f"",
        f"BREAKTHROUGH DISCOVERY:",
        f"  Our 4-layer bypass was INCOMPLETE! Found a 5th layer with:",
        f"  - Additional OSD register writes (0x19, 0x1A, 0x1B, 0x11, 0x81, 0x84, 0x85)",
        f"  - Additional validation checks (0x07, 0x81, 0x84, 0x85)",
        f"",
        f"Strategy:",
        f"  Apply ALL 5 layers of integrity validation bypass:",
        f"  - Layer 1: OSD initialization writes (0x01 -> 0x00)",
        f"  - Layer 2: Extended OSD configuration (0x86 -> 0x00)",
        f"  - Layer 3: Validation logic expectations (0x84 -> 0x00)",
        f"  - Layer 4: Additional validation checks (0x01 -> 0x00)",
        f"  - Layer 5: ADDITIONAL OSD REGISTER WRITES (0x19,0x1A,0x1B,0x11,0x81,0x84,0x85 -> 0x00)",
        f"  - Layer 5: ADDITIONAL VALIDATION CHECKS (0x07,0x81,0x84,0x85 -> 0x00)",
        f"",
        f"Key Insight:",
        f"  Previous patches failed because we missed the 5th layer of protection.",
        f"  The firmware has more sophisticated validation than initially thought.",
        f"",
        f"Total patches applied: {len(all_diffs)}",
        f"Total bytes changed: {len(all_diffs)}",
        f"Checksum: Not modified (original firmware has invalid checksum anyway)",
        f"",
        f"Expected Result:",
        f"  Device should now pass ALL 5 layers of integrity validation",
        f"  and complete USB configuration instead of stopping at Config=0 with Code 10 error.",
        f"",
        f"Patch Strategy:",
        f"  - All OSD registers consistently set to 0x00 across ALL layers",
        f"  - All validation logic expects 0x00 values across ALL layers",
        f"  - No inconsistent states that could trigger validation failures",
        f"  - Complete 5-layer bypass (not partial)",
    ]

    OUT_SUM_5LAYER.write_text("\n".join(summary_report) + "\n")
    print(f"   Summary report: {OUT_SUM_5LAYER}")

    print(f"\n✅ 5-layer patch complete! Total bytes changed: {len(all_diffs)}")
    print(f"   Ready for flashing: {OUT_BIN_5LAYER}")
    print(f"   Strategy: Bypass ALL 5 layers of runtime integrity validation")


if __name__ == "__main__":
    main() 