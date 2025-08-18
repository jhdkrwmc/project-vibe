#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Single-Flip Diagnostic Approach
Based on strategy to test each OSD site individually to identify the critical path

This script generates 4 firmware variants:
1. Only 0x04D4 flipped (0x01 -> 0x00) - affects 0x0B77 (OSD data/mode)
2. Only 0x0AC8 flipped (0x01 -> 0x00) - affects 0x0B76 (2nd enable)
3. Only 0x0B02 flipped (0x01 -> 0x00) - affects 0x0B77 (another write)
4. Only 0x4526 flipped (0x01 -> 0x00) - affects 0x0B75 (primary enable, reset path)

No checksum/footer modification is performed.
"""

import os
import struct
from pathlib import Path

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Outputs for each single-flip variant
OUTPUTS = {
    "0x04D4": {
        "bin": OUT_DIR / "fw_single_flip_04D4.bin",
        "diff": OUT_DIR / "fw_single_flip_04D4.diff.txt",
        "sum": OUT_DIR / "fw_single_flip_04D4.sum.txt",
        "description": "Only 0x04D4 flipped - affects 0x0B77 (OSD data/mode)"
    },
    "0x0AC8": {
        "bin": OUT_DIR / "fw_single_flip_0AC8.bin",
        "diff": OUT_DIR / "fw_single_flip_0AC8.diff.txt",
        "sum": OUT_DIR / "fw_single_flip_0AC8.sum.txt",
        "description": "Only 0x0AC8 flipped - affects 0x0B76 (2nd enable)"
    },
    "0x0B02": {
        "bin": OUT_DIR / "fw_single_flip_0B02.bin",
        "diff": OUT_DIR / "fw_single_flip_0B02.diff.txt",
        "sum": OUT_DIR / "fw_single_flip_0B02.sum.txt",
        "description": "Only 0x0B02 flipped - affects 0x0B77 (another write)"
    },
    "0x4526": {
        "bin": OUT_DIR / "fw_single_flip_4526.bin",
        "diff": OUT_DIR / "fw_single_flip_4526.diff.txt",
        "sum": OUT_DIR / "fw_single_flip_4526.sum.txt",
        "description": "Only 0x4526 flipped - affects 0x0B75 (primary enable, reset path)"
    }
}

# Single-flip patches (one at a time)
SINGLE_PATCHES = {
    "0x04D4": [(0x04D4, 0x01, 0x00)],  # 0x04D0: 90 0B 77 74 01 F0 → flip 01→00
    "0x0AC8": [(0x0AC8, 0x01, 0x00)],  # 0x0AC4: 90 0B 76 74 01 F0 → flip 01→00
    "0x0B02": [(0x0B02, 0x01, 0x00)],  # 0x0AFE: 90 0B 77 74 01 F0 → flip 01→00
    "0x4526": [(0x4526, 0x01, 0x00)],  # 0x4522: 90 0B 75 74 01 F0 → flip 01→00
}

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


def write_firmware_atomic(path: Path, data: bytes) -> None:
    """Write firmware bytes atomically and verify size."""
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_bytes(data)
    # Verify size before replacing
    written = tmp_path.stat().st_size
    if written != len(data):
        raise RuntimeError(f"Write size mismatch for {path}: wrote {written}, expected {len(data)}")
    # Atomic replace
    os.replace(tmp_path, path)


def verify_single_flip(base: bytes, variant: bytes, site_name: str) -> list[str]:
    """Verify only the intended site byte changed and size is intact."""
    notes: list[str] = []
    if len(variant) != len(base):
        notes.append(f"ERROR: size changed {len(variant)} vs {len(base)}")
        return notes

    # Map of site immediate offsets
    site_to_offset = {
        "0x04D4": 0x04D4,
        "0x0AC8": 0x0AC8,
        "0x0B02": 0x0B02,
        "0x4526": 0x4526,
    }
    # Check the intended site flipped from 0x01 to 0x00
    off = site_to_offset[site_name]
    notes.append(f"INTENDED @ {off:#06x}: base={base[off]:02X} variant={variant[off]:02X}")
    # Check the other sites remained as base
    for other_site, other_off in site_to_offset.items():
        if other_site == site_name:
            continue
        if variant[other_off] != base[other_off]:
            notes.append(f"ERROR: unintended change @ {other_off:#06x}: base={base[other_off]:02X} variant={variant[other_off]:02X}")
    return notes


def main() -> None:
    print("SN9C292B Firmware Patch - Single-Flip Diagnostic Approach")
    print("=" * 65)

    base = read_firmware(IN_PATH)
    print(f"Loaded firmware: {IN_PATH}")
    print(f"Size: {len(base):#x} bytes")

    # Generate each single-flip variant
    for site_name, patches in SINGLE_PATCHES.items():
        print(f"\n=== Generating {site_name} variant ===")
        
        # Create patched firmware
        data_patched = bytearray(base)
        
        # Apply single patch
        print(f"Applying single patch: {site_name}")
        diffs = apply_patches(data_patched, patches)
        for diff in diffs:
            print(f"   {diff}")
        
        # Write output files
        outputs = OUTPUTS[site_name]
        # Write binary atomically and verify size
        write_firmware_atomic(outputs["bin"], bytes(data_patched))
        print(f"   Binary: {outputs['bin']}")

        # Verify only intended byte changed
        verify_notes = verify_single_flip(bytes(base), bytes(data_patched), site_name)
        if verify_notes:
            for n in verify_notes:
                print(f"   {n}")
        
        # Write diff report
        outputs["diff"].write_text("\n".join(diffs) + "\n")
        print(f"   Diff report: {outputs['diff']}")
        
        # Write summary report
        summary_report = [
            f"Single-Flip Diagnostic Variant: {site_name}",
            f"Generated: {__import__('datetime').datetime.now().isoformat()}",
            f"",
            f"STRATEGY:",
            f"  Test each OSD site individually to identify the critical path",
            f"  This variant changes ONLY {site_name} to isolate its effect",
            f"",
            f"PATCH APPLIED:",
            f"  {site_name}: 0x01 -> 0x00",
            f"  {OUTPUTS[site_name]['description']}",
            f"",
            f"INTEGRITY NOTE:",
            f"  No checksum/footer fix applied in this diagnostic build.",
            f"",
            f"EXPECTED RESULT:",
            f"  If this single flip can boot clean, the issue is elsewhere.",
            f"  If it still gets Code 10, this site is on the critical path.",
            f"",
            f"DIAGNOSTIC VALUE:",
            f"  Compare USB Tree Viewer results with other variants",
            f"  Look for differences in loading extent, Config values, etc.",
        ]
        
        outputs["sum"].write_text("\n".join(summary_report) + "\n")
        print(f"   Summary report: {outputs['sum']}")

    print(f"\n✅ Single-flip diagnostic variants complete!")
    print(f"   Generated 4 variants for systematic testing")
    print(f"   Strategy: Test each OSD site individually to identify the critical path")
    print(f"")
    print(f"TESTING PLAN:")
    print(f"  1. Flash each variant individually")
    print(f"  2. Capture USB Tree Viewer results")
    print(f"  3. Compare loading extent, Config values, error codes")
    print(f"  4. Identify which site (if any) allows clean boot")
    print(f"  5. Focus analysis on the actual critical path")


if __name__ == "__main__":
    main() 