#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Broad Integrity Relaxation (no OSD flips)

Goal:
- Do not touch OSD enables
- Relax all early CJNE A,#imm,rel compares in 0x0200-0x0360 that expect non-zero magic values
- Immediates to relax -> 0x00: {0x01, 0x81, 0x84, 0x07}

Outputs:
- out/fw_integrity_relaxed_broad.bin
- out/fw_integrity_relaxed_broad.diff.txt
- out/fw_integrity_relaxed_broad.sum.txt
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Tuple

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_BIN = OUT_DIR / "fw_integrity_relaxed_broad.bin"
OUT_DIFF = OUT_DIR / "fw_integrity_relaxed_broad.diff.txt"
OUT_SUM = OUT_DIR / "fw_integrity_relaxed_broad.sum.txt"

SIZE_EXPECTED = 0x20000

SCAN_START = 0x0200
SCAN_END = 0x0360
IMM_TARGETS = {0x01, 0x81, 0x84, 0x07}

OSD_SITES = [0x04D0, 0x0AC4, 0x0AFE, 0x4522]


def read_firmware(path: Path) -> bytearray:
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


def relax_cjne_block(data: bytearray) -> List[str]:
    diffs: List[str] = []
    i = SCAN_START
    while i < min(SCAN_END, len(data) - 2):
        if data[i] == 0xB4:  # CJNE A,#imm,rel
            imm = data[i + 1]
            rel = data[i + 2]
            if imm in IMM_TARGETS:
                old = data[i + 1]
                data[i + 1] = 0x00
                diffs.append(f"OK   @ {i:#06x}: B4 {old:02X} -> B4 00 (rel {rel:02X})")
            i += 3
        else:
            i += 1
    if not diffs:
        diffs.append("No CJNE targets found in scan window")
    return diffs


def main() -> None:
    print("SN9C292B Firmware Patch - Broad Integrity Relaxation")
    print("=" * 64)

    base = read_firmware(IN_PATH)
    print(f"Loaded: {IN_PATH} size={len(base):#x}")

    data = bytearray(base)
    diffs = relax_cjne_block(data)
    for d in diffs:
        print("  " + d)

    write_firmware_atomic(OUT_BIN, bytes(data))
    print(f"Binary: {OUT_BIN}")

    OUT_DIFF.write_text("\n".join(diffs) + "\n")
    print(f"Diff report: {OUT_DIFF}")

    # Summary with OSD site sanity
    lines: List[str] = []
    lines.append("Broad Integrity Relaxation Build")
    lines.append(f"Generated: {__import__('datetime').datetime.now().isoformat()}")
    lines.append("")
    lines.append("CHANGES:")
    lines.extend([f"  - {d}" for d in diffs])
    lines.append("")
    lines.append("OSD SITES (unchanged):")
    for s in OSD_SITES:
        before = " ".join(f"{b:02X}" for b in base[s:s+6])
        after = " ".join(f"{b:02X}" for b in data[s:s+6])
        lines.append(f"  @ {s:#06x} BEFORE: {before} AFTER: {after}")

    OUT_SUM.write_text("\n".join(lines) + "\n")
    print(f"Summary report: {OUT_SUM}")
    print("\n✅ Build complete. Flash and capture USBTree output.")


if __name__ == "__main__":
    main()

