#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Integrity-Relaxed Only (no OSD flips, no footer edits)

Goal:
- Revert to the minimal plan: DO NOT touch OSD enable sites
- ONLY relax early integrity/sanity compares so zero is acceptable
- DO NOT modify the footer/checksum

Targets (expected encoding: CJNE A,#imm,rel → B4 imm rel):
- 0x0244: B4 01 xx  → change imm to 00
- 0x0260: B4 84 xx  → change imm to 00

If an exact offset does not match, search a small ±8 byte window for B4 <imm> <rel> and apply.

Outputs:
- out/fw_integrity_relaxed_only.bin
- out/fw_integrity_relaxed_only.diff.txt
- out/fw_integrity_relaxed_only.sum.txt
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Tuple


IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_BIN = OUT_DIR / "fw_integrity_relaxed_only.bin"
OUT_DIFF = OUT_DIR / "fw_integrity_relaxed_only.diff.txt"
OUT_SUM = OUT_DIR / "fw_integrity_relaxed_only.sum.txt"

SIZE_EXPECTED = 0x20000

# Intended CJNE sites: (target_offset, expected_imm)
CJNE_SITES: List[Tuple[int, int]] = [
    (0x0244, 0x01),  # CJNE A,#0x01,rel  → accept zero
    (0x0260, 0x84),  # CJNE A,#0x84,rel  → accept zero
]

# OSD enable triplets we must NOT touch (for reporting sanity only)
OSD_SITES: List[int] = [
    0x04D0,  # 90 0B 77 74 01 F0 → keep 01
    0x0AC4,  # 90 0B 76 74 01 F0 → keep 01
    0x0AFE,  # 90 0B 77 74 01 F0 → keep 01
    0x4522,  # 90 0B 75 74 01 F0 → keep 01
]


def read_firmware(path: Path) -> bytearray:
    if not path.exists():
        raise FileNotFoundError(f"Input firmware not found: {path}")
    data = bytearray(path.read_bytes())
    if len(data) != SIZE_EXPECTED:
        raise ValueError(f"Unexpected firmware size: {len(data):#x} (expected {SIZE_EXPECTED:#x})")
    return data


def write_firmware_atomic(path: Path, data: bytes) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_bytes(data)
    if tmp_path.stat().st_size != len(data):
        raise RuntimeError(
            f"Write size mismatch for {path}: wrote {tmp_path.stat().st_size}, expected {len(data)}"
        )
    os.replace(tmp_path, path)


def patch_cjne_relax(data: bytearray, addr: int, expected_imm: int, window: int = 8) -> str:
    """Relax CJNE A,#imm,rel immediate to 0x00.

    Prefers exact addr match; if not present, searches in ±window bytes for B4 <imm> <rel>.
    Returns a human-readable result string.
    """
    # Exact match first
    if data[addr] == 0xB4 and data[addr + 1] == expected_imm:
        old = data[addr + 1]
        data[addr + 1] = 0x00
        return f"OK   @ {addr:#06x}: B4 {old:02X} -> B4 00"

    # Fallback: small window search
    start = max(0, addr - window)
    end = min(len(data) - 3, addr + window)
    for i in range(start, end + 1):
        if data[i] == 0xB4 and data[i + 1] == expected_imm:
            old = data[i + 1]
            data[i + 1] = 0x00
            return f"OK*  @ {i:#06x} (shifted from {addr:#06x}): B4 {old:02X} -> B4 00"

    return f"SKIP @ {addr:#06x}: CJNE A,#0x{expected_imm:02X} not found (±{window})"


def dump_bytes_span(data: bytes, start: int, length: int) -> str:
    return " ".join(f"{data[i]:02X}" for i in range(start, start + length))


def main() -> None:
    print("SN9C292B Firmware Patch - Integrity-Relaxed Only")
    print("=" * 60)

    base = read_firmware(IN_PATH)
    print(f"Loaded firmware: {IN_PATH}")
    print(f"Size: {len(base):#x} bytes")

    data = bytearray(base)

    print("\nApplying integrity relaxations (no OSD flips, no footer edits)...")
    results: List[str] = []
    for addr, imm in CJNE_SITES:
        res = patch_cjne_relax(data, addr, imm)
        results.append(res)
        print(f"  {res}")

    # Write binary atomically
    write_firmware_atomic(OUT_BIN, bytes(data))
    print(f"\nBinary: {OUT_BIN}")

    # Create diff report
    OUT_DIFF.write_text("\n".join(results) + "\n")
    print(f"Diff report: {OUT_DIFF}")

    # Summary including OSD sites sanity
    summary_lines: List[str] = []
    summary_lines.append("Integrity-Relaxed Only Build")
    summary_lines.append(f"Generated: {__import__('datetime').datetime.now().isoformat()}")
    summary_lines.append("")
    summary_lines.append("CHANGES:")
    summary_lines.extend([f"  - {r}" for r in results])
    summary_lines.append("")
    summary_lines.append("OSD SITES (should remain enabled=01):")
    for s in OSD_SITES:
        # The immediate is the 5th byte (offset + 4) within the 6-byte triplet
        triplet = dump_bytes_span(base, s, 6)
        triplet_after = dump_bytes_span(data, s, 6)
        summary_lines.append(
            f"  @ {s:#06x} BEFORE: {triplet}  AFTER: {triplet_after}"
        )

    OUT_SUM.write_text("\n".join(summary_lines) + "\n")
    print(f"Summary report: {OUT_SUM}")
    print("\n✅ Build complete. Flash and collect USBTree output (expect: if this boots further, OSD unchanged).")


if __name__ == "__main__":
    main()

