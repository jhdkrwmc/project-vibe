#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Late Clear Enable-Only Hook

Goal:
- Leave all OSD enables and compares untouched during init
- Inject a tiny stub that clears 0x0B75 and 0x0B76 late, but PRESERVES 0x0B77
- Hook at 0x032C (LJMP 0xA4A0) similar to late_clear_hook

Rationale:
- Validation likely expects A==86 at entry of 0xA4A0 path. Clearing 0x0B77 caused failure.
- Disabling engine via 0x0B76 (and 0x0B75) should neutralize OSD while keeping expected state.

Stub bytes (12 bytes total):
  90 0B 75   ; MOV DPTR,#0x0B75
  E4         ; CLR A
  F0         ; MOVX @DPTR,A
  90 0B 76   ; MOV DPTR,#0x0B76
  F0         ; MOVX @DPTR,A
  02 A4 A0   ; LJMP 0xA4A0 (original target)

Outputs:
- out/fw_late_clear_enable_only.bin
- out/fw_late_clear_enable_only.diff.txt
- out/fw_late_clear_enable_only.sum.txt
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List


IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_BIN = OUT_DIR / "fw_late_clear_enable_only.bin"
OUT_DIFF = OUT_DIR / "fw_late_clear_enable_only.diff.txt"
OUT_SUM = OUT_DIR / "fw_late_clear_enable_only.sum.txt"

SIZE_EXPECTED = 0x20000

HOOK_ADDR_EXPECTED = 0x032C
HOOK_OLD = bytes([0x02, 0xA4, 0xA0])  # LJMP 0xA4A0


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


def find_hook_site(data: bytes) -> int:
    if data[HOOK_ADDR_EXPECTED:HOOK_ADDR_EXPECTED + 3] == HOOK_OLD:
        return HOOK_ADDR_EXPECTED
    for i in range(HOOK_ADDR_EXPECTED - 16, HOOK_ADDR_EXPECTED + 17):
        if 0 <= i and i + 3 <= len(data) and data[i:i + 3] == HOOK_OLD:
            return i
    idx = data.find(HOOK_OLD)
    if idx != -1:
        return idx
    raise RuntimeError("Hook LJMP 02 A4 A0 not found")


def find_code_cave(data: bytes, length_needed: int, search_end: int = 0x10000) -> int:
    def scan_for(byte_val: int) -> int | None:
        run_len = 0
        run_end = None
        start = max(0, min(len(data), search_end) - 1)
        for i in range(start, -1, -1):
            if data[i] == byte_val:
                if run_len == 0:
                    run_end = i
                run_len += 1
                if run_len >= length_needed:
                    cave_start = run_end - run_len + 1
                    return cave_start
            else:
                run_len = 0
                run_end = None
        return None

    cave = scan_for(0xFF)
    if cave is not None:
        return cave
    cave = scan_for(0x00)
    if cave is not None:
        return cave
    raise RuntimeError("No suitable code cave (FF/00) found within 0x0000..0xFFFF")


def assemble_stub() -> bytes:
    stub = bytearray()
    # MOV DPTR,#0x0B75
    stub += bytes([0x90, 0x0B, 0x75])
    # CLR A
    stub += bytes([0xE4])
    # MOVX @DPTR,A
    stub += bytes([0xF0])
    # MOV DPTR,#0x0B76
    stub += bytes([0x90, 0x0B, 0x76])
    # MOVX @DPTR,A
    stub += bytes([0xF0])
    # LJMP 0xA4A0
    stub += bytes([0x02, 0xA4, 0xA0])
    assert len(stub) == 12
    return bytes(stub)


def build() -> None:
    print("SN9C292B Firmware Patch - Late Clear Enable-Only Hook")
    print("=" * 58)

    base = read_firmware(IN_PATH)
    print(f"Loaded firmware: {IN_PATH}")
    print(f"Size: {len(base):#x} bytes")

    data = bytearray(base)

    hook_site = find_hook_site(base)
    print(f"Hook site: 0x{hook_site:04X} (bytes={base[hook_site:hook_site+3].hex().upper()})")

    cave_addr = find_code_cave(base, 12, search_end=0x10000)
    print(f"Code cave: 0x{cave_addr:04X} (len=12)")

    stub = assemble_stub()
    data[cave_addr:cave_addr + len(stub)] = stub

    cave_hi = (cave_addr >> 8) & 0xFF
    cave_lo = cave_addr & 0xFF
    data[hook_site:hook_site + 3] = bytes([0x02, cave_hi, cave_lo])

    write_firmware_atomic(OUT_BIN, bytes(data))
    print(f"Binary: {OUT_BIN}")

    diffs: List[str] = []
    diffs.append(f"Hook site @ 0x{hook_site:04X}: {base[hook_site:hook_site+3].hex().upper()} -> {data[hook_site:hook_site+3].hex().upper()}")
    diffs.append(f"Stub placed @ 0x{cave_addr:04X} (12 bytes)")

    OUT_DIFF.write_text("\n".join(diffs) + "\n")
    print(f"Diff report: {OUT_DIFF}")

    summary_lines: List[str] = []
    summary_lines.append("Late Clear Enable-Only Hook Build")
    summary_lines.append(f"Generated: {__import__('datetime').datetime.now().isoformat()}")
    summary_lines.append("")
    summary_lines.append("HOOK:")
    summary_lines.append(f"  Overwrote LJMP at 0x{hook_site:04X} to LJMP 0x{cave_addr:04X}")
    summary_lines.append(f"  Stub preserves 0x0B77, clears 0x0B75/0x0B76, then LJMP 0xA4A0")
    summary_lines.append("")
    summary_lines.append("OSD SITES (unchanged):")
    for addr, label in ((0x04D0, 'OSD #1'), (0x0AC4, 'OSD #2'), (0x0AFE, 'OSD #3'), (0x4522, 'OSD early')):
        summary_lines.append(
            f"  {label} @ 0x{addr:04X}: BEFORE={' '.join(f'{b:02X}' for b in base[addr:addr+6])} AFTER={' '.join(f'{b:02X}' for b in data[addr:addr+6])}"
        )

    OUT_SUM.write_text("\n".join(summary_lines) + "\n")
    print(f"Summary report: {OUT_SUM}")
    print("\n✅ Build complete. Flash and collect USBTree output.")


if __name__ == "__main__":
    build()

