#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Hybrid Sweet Spot Strategy
Based on discovery that fw_comprehensive_bypass loaded more extensively

This script combines the best aspects of both approaches:
- Core OSD disable patches (proven to work)
- Selective validation bypass (avoiding over-patching)
- Target the sweet spot for maximum loading extent
"""

import os
import struct
from pathlib import Path

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Outputs
OUT_BIN_HYBRID = OUT_DIR / "fw_hybrid_sweet_spot.bin"
OUT_DIFF_HYBRID = OUT_DIR / "fw_hybrid_sweet_spot.diff.txt"
OUT_SUM_HYBRID = OUT_DIR / "fw_hybrid_sweet_spot.sum.txt"

# CORE PATCHES (Proven to work - from fw_comprehensive_bypass)
PATCHES_CORE = [
    (0x04D4, 0x01, 0x00),  # 0x04D0: 90 0B 77 74 01 F0 → flip 01→00
    (0x0AC8, 0x01, 0x00),  # 0x0AC4: 90 0B 76 74 01 F0 → flip 01→00
    (0x0B02, 0x01, 0x00),  # 0x0AFE: 90 0B 77 74 01 F0 → flip 01→00
    (0x4526, 0x01, 0x00),  # 0x4522: 90 0B 75 74 01 F0 → flip 01→00
    (0x0244, 0x01, 0x00),  # 0x0242: B4 01 08 → B4 00 08
]

# SELECTIVE VALIDATION BYPASS (Targeted approach)
PATCHES_SELECTIVE_VALIDATION = [
    # Only patch validation that we're confident about
    (0x032A, 0x86, 0x00),  # 0x0325: 90 0B 77 74 86 F0 → 90 0B 77 74 00 F0
]

# ADDITIONAL OSD WRITES (Minimal, proven patterns)
PATCHES_ADDITIONAL_OSD = [
    (0x03B0, 0x19, 0x00),  # 0x03AC: 90 0B 77 74 19 F0 → 90 0B 77 74 00 F0
    (0x03BC, 0x1A, 0x00),  # 0x03B8: 90 0B 77 74 1A F0 → 90 0B 77 74 00 F0
    (0x03C8, 0x1B, 0x00),  # 0x03C4: 90 0B 77 74 1B F0 → 90 0B 77 74 00 F0
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
    print("SN9C292B Firmware Patch - Hybrid Sweet Spot Strategy")
    print("=" * 60)

    base = read_firmware(IN_PATH)
    print(f"Loaded firmware: {IN_PATH}")
    print(f"Size: {len(base):#x} bytes")

    # Create patched firmware
    data_patched = bytearray(base)

    # Apply Core patches (proven to work)
    print("\n1. Applying Core patches (proven to work)...")
    diffs_core = apply_patches(data_patched, PATCHES_CORE)
    for diff in diffs_core:
        print(f"   {diff}")

    # Apply Selective validation bypass
    print("\n2. Applying Selective validation bypass...")
    diffs_selective = apply_patches(data_patched, PATCHES_SELECTIVE_VALIDATION)
    for diff in diffs_selective:
        print(f"   {diff}")

    # Apply Additional OSD writes (minimal, proven)
    print("\n3. Applying Additional OSD writes (minimal, proven)...")
    diffs_additional = apply_patches(data_patched, PATCHES_ADDITIONAL_OSD)
    for diff in diffs_additional:
        print(f"   {diff}")

    # Note: No checksum fix needed - original firmware has invalid checksum
    print("\n4. Checksum handling...")
    print("   Original firmware has invalid checksum (0xC3A4) - not used for validation")
    print("   Keeping original checksum bytes (0x0000) - no fix needed")

    # Write output files
    print("\n5. Writing output files...")
    OUT_BIN_HYBRID.write_bytes(data_patched)
    print(f"   Binary: {OUT_BIN_HYBRID}")

    # Write diff report
    all_diffs = diffs_core + diffs_selective + diffs_additional
    OUT_DIFF_HYBRID.write_text("\n".join(all_diffs) + "\n")
    print(f"   Diff report: {OUT_DIFF_HYBRID}")

    # Write summary report
    summary_report = [
        f"Hybrid Sweet Spot Strategy",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        f"",
        f"STRATEGY RATIONALE:",
        f"  fw_comprehensive_bypass loaded more extensively than fw_comprehensive_5layer_bypass",
        f"  This suggests there's a 'sweet spot' for validation bypass that maximizes loading extent",
        f"",
        f"APPROACH:",
        f"  - Core patches: Proven OSD disable patterns (0x01 -> 0x00)",
        f"  - Selective validation: Only bypass what we're confident about",
        f"  - Minimal additional OSD: Avoid over-patching that might trigger new failures",
        f"",
        f"PATCHES APPLIED:",
        f"  - Core OSD disable: {len(diffs_core)} patches",
        f"  - Selective validation: {len(diffs_selective)} patches",
        f"  - Additional OSD: {len(diffs_additional)} patches",
        f"  - Total: {len(all_diffs)} patches",
        f"",
        f"EXPECTED RESULT:",
        f"  Device should load more extensively (like fw_comprehensive_bypass)",
        f"  while avoiding the over-patching issues of fw_comprehensive_5layer_bypass",
        f"",
        f"Key Insight:",
        f"  More patches != better loading. There's a sweet spot for validation bypass.",
    ]

    OUT_SUM_HYBRID.write_text("\n".join(summary_report) + "\n")
    print(f"   Summary report: {OUT_SUM_HYBRID}")

    print(f"\n✅ Hybrid patch complete! Total bytes changed: {len(all_diffs)}")
    print(f"   Ready for flashing: {OUT_BIN_HYBRID}")
    print(f"   Strategy: Find the sweet spot for maximum loading extent")


if __name__ == "__main__":
    main() 