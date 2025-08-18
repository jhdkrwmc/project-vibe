#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Integrity Relaxed PLUS (no OSD flips)

What it does:
- Broad CJNE relax in 0x0200-0x0360 for immediates {0x01,0x81,0x84,0x07}
- Neutralize conditional branches directly following MOVX A,@DPTR checks
  Patterns patched to NOP NOP (0x00 0x00):
    - E0 64 xx 60 rr   (MOVX; XRL #xx; JZ rel)
    - E0 60 rr         (MOVX; JZ rel)
    - E0 70 rr         (MOVX; JNZ rel)

Outputs:
- out/fw_integrity_relaxed_plus.bin
- out/fw_integrity_relaxed_plus.diff.txt
- out/fw_integrity_relaxed_plus.sum.txt
"""

from __future__ import annotations

from pathlib import Path
from typing import List
import os

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_BIN = OUT_DIR / "fw_integrity_relaxed_plus.bin"
OUT_DIFF = OUT_DIR / "fw_integrity_relaxed_plus.diff.txt"
OUT_SUM = OUT_DIR / "fw_integrity_relaxed_plus.sum.txt"

SIZE_EXPECTED = 0x20000

SCAN_START = 0x0200
SCAN_END = 0x0360
IMM_TARGETS = {0x01, 0x81, 0x84, 0x07}
OSD_SITES = [0x04D0, 0x0AC4, 0x0AFE, 0x4522]


def read_firmware(path: Path) -> bytearray:
    data = bytearray(path.read_bytes())
    if len(data) != SIZE_EXPECTED:
        raise ValueError(f"Unexpected firmware size: {len(data):#x}")
    return data


def write_firmware_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    if tmp.stat().st_size != len(data):
        raise RuntimeError("write size mismatch")
    os.replace(tmp, path)


def relax_cjne(data: bytearray) -> List[str]:
    diffs: List[str] = []
    i = SCAN_START
    while i < min(SCAN_END, len(data) - 2):
        if data[i] == 0xB4 and data[i + 1] in IMM_TARGETS:
            old = data[i + 1]
            data[i + 1] = 0x00
            diffs.append(f"CJNE @ {i:#06x}: B4 {old:02X} -> B4 00")
            i += 3
        else:
            i += 1
    return diffs


def neutralize_jumps(data: bytearray) -> List[str]:
    diffs: List[str] = []
    i = SCAN_START
    end = min(SCAN_END, len(data) - 2)
    while i < end:
        if data[i] == 0xE0:  # MOVX A,@DPTR
            # Pattern E0 64 xx 60 rr or 70 rr
            if i + 4 < end and data[i + 1] == 0x64 and data[i + 3] in (0x60, 0x70):
                op = data[i + 3]
                rr = data[i + 4]
                data[i + 3] = 0x00
                data[i + 4] = 0x00
                diffs.append(f"J{ 'Z' if op==0x60 else 'NZ' } nulled @ {i+3:#06x} (after E0 64 xx)")
                i += 5
                continue
            # Pattern E0 60 rr or E0 70 rr
            if i + 2 < end and data[i + 1] in (0x60, 0x70):
                op = data[i + 1]
                rr = data[i + 2]
                data[i + 1] = 0x00
                data[i + 2] = 0x00
                diffs.append(f"J{ 'Z' if op==0x60 else 'NZ' } nulled @ {i+1:#06x} (after E0)")
                i += 3
                continue
        i += 1
    if not diffs:
        diffs.append("No MOVX->JZ/JNZ patterns found")
    return diffs


def main() -> None:
    print("SN9C292B Firmware Patch - Integrity Relaxed PLUS")
    print("=" * 60)

    base = read_firmware(IN_PATH)
    data = bytearray(base)

    cjne_diffs = relax_cjne(data)
    jmp_diffs = neutralize_jumps(data)

    for d in cjne_diffs + jmp_diffs:
        print("  " + d)

    write_firmware_atomic(OUT_BIN, bytes(data))
    OUT_DIFF.write_text("\n".join(cjne_diffs + jmp_diffs) + "\n")

    lines: List[str] = []
    lines.append("Integrity Relaxed PLUS Build")
    lines.append(f"Generated: {__import__('datetime').datetime.now().isoformat()}")
    lines.append("")
    lines.append("CHANGES:")
    lines.extend([f"  - {d}" for d in cjne_diffs + jmp_diffs])
    lines.append("")
    lines.append("OSD SITES (unchanged):")
    for s in OSD_SITES:
        before = " ".join(f"{b:02X}" for b in base[s:s+6])
        after = " ".join(f"{b:02X}" for b in data[s:s+6])
        lines.append(f"  @ {s:#06x} BEFORE: {before} AFTER: {after}")

    OUT_SUM.write_text("\n".join(lines) + "\n")
    print(f"Binary: {OUT_BIN}")
    print(f"Diff report: {OUT_DIFF}")
    print(f"Summary report: {OUT_SUM}")
    print("\n✅ Build complete. Flash and capture USBTree output.")


if __name__ == "__main__":
    main()

