#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Integrity Check Bypass Strategy (No Checksum Fix)
Based on deep analysis showing original firmware has invalid checksum

This script patches the integrity check logic to accept our OSD values
without attempting to fix the checksum (which is not used for validation).
"""

import os
import struct
from pathlib import Path

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Outputs
OUT_BIN_INTEGRITY_BYPASS = OUT_DIR / "fw_integrity_bypass_no_checksum.bin"
OUT_DIFF_INTEGRITY_BYPASS = OUT_DIR / "fw_integrity_bypass_no_checksum.diff.txt"
OUT_SUM_INTEGRITY_BYPASS = OUT_DIR / "fw_integrity_bypass_no_checksum.sum.txt"

# OSD patches: offsets -> expected original -> new
PATCHES_OSD = [
    (0x04D4, 0x01, 0x00),  # 0x04D0: 90 0B 77 74 01 F0 → flip 01→00
    (0x0AC8, 0x01, 0x00),  # 0x0AC4: 90 0B 76 74 01 F0 → flip 01→00
    (0x0B02, 0x01, 0x00),  # 0x0AFE: 90 0B 77 74 01 F0 → flip 01→00
    (0x4526, 0x01, 0x00),  # 0x4522: 90 0B 75 74 01 F0 → flip 01→00
]

# Integrity check logic bypass patches
# These change the expected values in the integrity checks to match our OSD patches
PATCHES_INTEGRITY_BYPASS = [
    (0x244, 0x01, 0x00),  # CJNE A,#01,+8 → CJNE A,#00,+8 (expect 0x00 instead of 0x01)
    (0x260, 0x84, 0x00),  # CJNE A,#0x84,+6 → CJNE A,#0x00,+6 (expect 0x00 instead of 0x84)
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
    print("SN9C292B Firmware Patch - Integrity Check Bypass Strategy (No Checksum)")
    print("=" * 70)
    
    base = read_firmware(IN_PATH)
    print(f"Loaded firmware: {IN_PATH}")
    print(f"Size: {len(base):#x} bytes")
    
    # Create patched firmware
    data_patched = bytearray(base)
    
    # Apply OSD patches
    print("\n1. Applying OSD disable patches...")
    diffs_osd = apply_patches(data_patched, PATCHES_OSD)
    for diff in diffs_osd:
        print(f"   {diff}")
    
    # Apply integrity check bypass patches
    print("\n2. Applying integrity check bypass patches...")
    diffs_integrity = apply_patches(data_patched, PATCHES_INTEGRITY_BYPASS)
    for diff in diffs_integrity:
        print(f"   {diff}")
    
    # Note: No checksum fix needed - original firmware has invalid checksum
    print("\n3. Checksum handling...")
    print("   Original firmware has invalid checksum (0xC3A4) - not used for validation")
    print("   Keeping original checksum bytes (0x0000) - no fix needed")
    
    # Write output files
    print("\n4. Writing output files...")
    OUT_BIN_INTEGRITY_BYPASS.write_bytes(data_patched)
    print(f"   Binary: {OUT_BIN_INTEGRITY_BYPASS}")
    
    # Write diff report
    all_diffs = diffs_osd + diffs_integrity
    OUT_DIFF_INTEGRITY_BYPASS.write_text("\n".join(all_diffs) + "\n")
    print(f"   Diff report: {OUT_DIFF_INTEGRITY_BYPASS}")
    
    # Write summary report
    summary_report = [
        f"Integrity Check Bypass Strategy - No Checksum Fix",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        f"",
        f"Strategy:",
        f"  Instead of just patching OSD writes, we now patch the integrity check logic",
        f"  to expect 0x00 values instead of 0x01/0x84. This should allow the device",
        f"  to pass validation and complete USB configuration.",
        f"",
        f"Key Insight:",
        f"  Original firmware has invalid checksum (0xC3A4) - checksum validation is NOT used.",
        f"  The device uses runtime integrity checks instead, which is what we're bypassing.",
        f"",
        f"OSD Patches Applied:",
    ] + diffs_osd + [
        f"",
        f"Integrity Check Bypass Patches Applied:",
    ] + diffs_integrity + [
        f"",
        f"Total bytes changed: {len(all_diffs)}",
        f"Checksum: Not modified (original firmware has invalid checksum anyway)",
        f"",
        f"Expected Result:",
        f"  Device should now pass integrity validation and complete USB configuration",
        f"  instead of stopping at Config=0 with Code 10 error.",
    ]
    
    OUT_SUM_INTEGRITY_BYPASS.write_text("\n".join(summary_report) + "\n")
    print(f"   Summary report: {OUT_SUM_INTEGRITY_BYPASS}")
    
    print(f"\n✅ Patch complete! Total bytes changed: {len(all_diffs)}")
    print(f"   Ready for flashing: {OUT_BIN_INTEGRITY_BYPASS}")
    print(f"   Strategy: Bypass runtime integrity checks (no checksum fix needed)")


if __name__ == "__main__":
    main() 