#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Integrity Check Bypass Strategy
Based on deep analysis of multi-stage integrity checks at 0x1C0-0x240

This script patches the integrity check logic to accept our OSD values
instead of just patching the OSD writes themselves.
"""

import os
import struct
from pathlib import Path

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Outputs
OUT_BIN_INTEGRITY_BYPASS = OUT_DIR / "fw_integrity_bypass_crc_fixed.bin"
OUT_DIFF_INTEGRITY_BYPASS = OUT_DIR / "fw_integrity_bypass_crc_fixed.diff.txt"
OUT_SUM_INTEGRITY_BYPASS = OUT_DIR / "fw_integrity_bypass_crc_fixed.sum.txt"

# OSD patches: offsets -> expected original -> new
PATCHES_OSD = [
    (0x04D4, 0x01, 0x00),  # 0x04D0: 90 0B 77 74 01 F0 → flip 01→00
    (0x0AC8, 0x01, 0x00),  # 0x0AC4: 90 0B 76 74 01 F0 → flip 01→00
    (0x0B02, 0x01, 0x00),  # 0x0AFE: 90 0B 77 74 01 F0 → flip 01→00
    (0x4526, 0x01, 0x00),  # 0x4522: 90 0B 75 74 01 F0 → flip 01→00
]

# NEW: Integrity check logic bypass patches
# These change the expected values in the integrity checks to match our OSD patches
PATCHES_INTEGRITY_BYPASS = [
    (0x244, 0x01, 0x00),  # CJNE A,#01,+8 → CJNE A,#00,+8 (expect 0x00 instead of 0x01)
    (0x260, 0x84, 0x00),  # CJNE A,#0x84,+6 → CJNE A,#0x00,+6 (expect 0x00 instead of 0x84)
]

SIZE_EXPECTED = 0x20000
CHK_POS = 0x1FFE  # little-endian uint16 checksum


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


def compute_checksum_bytesum(data: bytes) -> tuple[int, int]:
    end_excl = 0x1FFE
    s = 0
    for i in range(0, end_excl):
        s = (s + data[i]) & 0xFFFF
    comp = (-s) & 0xFFFF
    return s, comp


def write_checksum(data: bytearray, checksum: int) -> None:
    data[CHK_POS] = checksum & 0xFF
    data[CHK_POS + 1] = (checksum >> 8) & 0xFF


def sum_full_image_bytes(data: bytes) -> int:
    s = 0
    for b in data:
        s = (s + b) & 0xFFFF
    return s


def main() -> None:
    print("SN9C292B Firmware Patch - Integrity Check Bypass Strategy")
    print("=" * 60)
    
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
    
    # Compute and write checksum
    print("\n3. Computing and writing checksum...")
    partial, comp = compute_checksum_bytesum(data_patched)
    write_checksum(data_patched, comp)
    final_sum = sum_full_image_bytes(data_patched)
    
    print(f"   Partial sum [0x0000..0x1FFD]: {partial:#06x}")
    print(f"   Computed checksum (two's complement): {comp:#06x}")
    print(f"   Checksum bytes @ 0x1FFE..0x1FFF (LE): {comp & 0xFF:02X} {(comp >> 8) & 0xFF:02X}")
    print(f"   Final 16-bit sum of entire image: {final_sum:#06x}")
    print(f"   Verification: {'PASS' if final_sum == 0 else 'FAIL'}")
    
    # Write output files
    print("\n4. Writing output files...")
    OUT_BIN_INTEGRITY_BYPASS.write_bytes(data_patched)
    print(f"   Binary: {OUT_BIN_INTEGRITY_BYPASS}")
    
    # Write diff report
    all_diffs = diffs_osd + diffs_integrity
    OUT_DIFF_INTEGRITY_BYPASS.write_text("\n".join(all_diffs) + "\n")
    print(f"   Diff report: {OUT_DIFF_INTEGRITY_BYPASS}")
    
    # Write checksum report
    checksum_report = [
        f"Integrity Check Bypass Strategy - Checksum Report",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        f"",
        f"OSD Patches Applied:",
    ] + diffs_osd + [
        f"",
        f"Integrity Check Bypass Patches Applied:",
    ] + diffs_integrity + [
        f"",
        f"Checksum Calculation:",
        f"  Partial sum [0x0000..0x1FFD]: {partial:#06x}",
        f"  Computed checksum (two's complement): {comp:#06x}",
        f"  Checksum bytes @ 0x1FFE..0x1FFF (LE): {comp & 0xFF:02X} {(comp >> 8) & 0xFF:02X}",
        f"  Final 16-bit sum of entire image: {final_sum:#06x}",
        f"  Verification: {'PASS' if final_sum == 0 else 'FAIL'}",
        f"",
        f"Strategy:",
        f"  Instead of just patching OSD writes, we now patch the integrity check logic",
        f"  to expect 0x00 values instead of 0x01/0x84. This should allow the device",
        f"  to pass validation and complete USB configuration.",
    ]
    
    OUT_SUM_INTEGRITY_BYPASS.write_text("\n".join(checksum_report) + "\n")
    print(f"   Checksum report: {OUT_SUM_INTEGRITY_BYPASS}")
    
    print(f"\n✅ Patch complete! Total bytes changed: {len(all_diffs)}")
    print(f"   Ready for flashing: {OUT_BIN_INTEGRITY_BYPASS}")


if __name__ == "__main__":
    main() 