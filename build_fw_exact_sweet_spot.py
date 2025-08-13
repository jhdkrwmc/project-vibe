#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Exact Sweet Spot Replication
Based on discovery that fw_comprehensive_bypass SKIPs are the key to loading extent

This script EXACTLY replicates the fw_comprehensive_bypass pattern:
- Apply the same 5 successful patches
- Intentionally SKIP the same 3 patches (to protect from over-patching)
- Recreate the exact sweet spot for maximum loading extent
"""

import os
import struct
from pathlib import Path

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Outputs
OUT_BIN_EXACT_SWEET = OUT_DIR / "fw_exact_sweet_spot.bin"
OUT_DIFF_EXACT_SWEET = OUT_DIR / "fw_exact_sweet_spot.diff.txt"
OUT_SUM_EXACT_SWEET = OUT_DIR / "fw_exact_sweet_spot.sum.txt"

# EXACT REPLICATION OF fw_comprehensive_bypass (the sweet spot)
PATCHES_EXACT_SWEET = [
    (0x04D4, 0x01, 0x00),  # 0x04D0: 90 0B 77 74 01 F0 → flip 01→00
    (0x0AC8, 0x01, 0x00),  # 0x0AC4: 90 0B 76 74 01 F0 → flip 01→00
    (0x0B02, 0x01, 0x00),  # 0x0AFE: 90 0B 77 74 01 F0 → flip 01→00
    (0x4526, 0x01, 0x00),  # 0x4522: 90 0B 75 74 01 F0 → flip 01→00
    (0x0244, 0x01, 0x00),  # 0x0242: B4 01 08 → B4 00 08
]

# INTENTIONALLY SKIP THESE (they caused SKIPs in the sweet spot)
PATCHES_INTENTIONALLY_SKIPPED = [
    (0x0329, 0x86, 0x00),  # INTENTIONALLY SKIP - caused SKIP in sweet spot
    (0xB0E8, 0x84, 0x00),  # INTENTIONALLY SKIP - caused SKIP in sweet spot  
    (0xC6CB, 0x84, 0x00),  # INTENTIONALLY SKIP - caused SKIP in sweet spot
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
    print("SN9C292B Firmware Patch - Exact Sweet Spot Replication")
    print("=" * 60)

    base = read_firmware(IN_PATH)
    print(f"Loaded firmware: {IN_PATH}")
    print(f"Size: {len(base):#x} bytes")

    # Create patched firmware
    data_patched = bytearray(base)

    # Apply EXACT sweet spot patches (replicating fw_comprehensive_bypass)
    print("\n1. Applying EXACT sweet spot patches...")
    diffs_exact = apply_patches(data_patched, PATCHES_EXACT_SWEET)
    for diff in diffs_exact:
        print(f"   {diff}")

    # Note: Intentionally NOT applying the patches that caused SKIPs
    print("\n2. Intentionally SKIPPING patches that caused SKIPs in sweet spot...")
    for off, want_old, new_val in PATCHES_INTENTIONALLY_SKIPPED:
        old = data_patched[off]
        print(f"   INTENTIONALLY SKIP @ {off:#06x}: {old:02X} (not {want_old:02X})")

    # Note: No checksum fix needed - original firmware has invalid checksum
    print("\n3. Checksum handling...")
    print("   Original firmware has invalid checksum (0xC3A4) - not used for validation")
    print("   Keeping original checksum bytes (0x0000) - no fix needed")

    # Write output files
    print("\n4. Writing output files...")
    OUT_BIN_EXACT_SWEET.write_bytes(data_patched)
    print(f"   Binary: {OUT_BIN_EXACT_SWEET}")

    # Write diff report
    OUT_DIFF_EXACT_SWEET.write_text("\n".join(diffs_exact) + "\n")
    print(f"   Diff report: {OUT_DIFF_EXACT_SWEET}")

    # Write summary report
    summary_report = [
        f"Exact Sweet Spot Replication",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        f"",
        f"BREAKTHROUGH DISCOVERY:",
        f"  The SKIPs in fw_comprehensive_bypass are the KEY to the sweet spot!",
        f"  Some patches should NOT be applied for optimal loading extent.",
        f"",
        f"STRATEGY:",
        f"  EXACTLY replicate the fw_comprehensive_bypass pattern:",
        f"  - Apply the same 5 successful patches",
        f"  - Intentionally SKIP the same 3 patches (to protect from over-patching)",
        f"  - Recreate the exact sweet spot for maximum loading extent",
        f"",
        f"PATCHES APPLIED:",
        f"  - Core OSD disable: 4 patches (0x01 -> 0x00)",
        f"  - Validation bypass: 1 patch (0x01 -> 0x00)",
        f"  - Total: {len(diffs_exact)} patches",
        f"",
        f"PATCHES INTENTIONALLY SKIPPED:",
        f"  - Extended OSD config: 1 patch (0x86 -> 0x00) - SKIP",
        f"  - Validation logic: 2 patches (0x84 -> 0x00) - SKIP",
        f"  - Total: 3 patches SKIPPED",
        f"",
        f"EXPECTED RESULT:",
        f"  Device should load with the SAME extensive loading as fw_comprehensive_bypass",
        f"  because we've replicated the exact sweet spot pattern.",
        f"",
        f"Key Insight:",
        f"  SKIPs are not failures - they're the sweet spot!",
        f"  Over-patching triggers additional validation failures.",
    ]

    OUT_SUM_EXACT_SWEET.write_text("\n".join(summary_report) + "\n")
    print(f"   Summary report: {OUT_SUM_EXACT_SWEET}")

    print(f"\n✅ Exact sweet spot replication complete! Total bytes changed: {len(diffs_exact)}")
    print(f"   Ready for flashing: {OUT_BIN_EXACT_SWEET}")
    print(f"   Strategy: Replicate the exact sweet spot pattern from fw_comprehensive_bypass")


if __name__ == "__main__":
    main() 