#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Late Clear Hook at A51A Entry

Goal:
- Avoid interfering with early init and set-configuration path
- Run the clear stub immediately before code_A51A via an existing LJMP 0xA51A
- Clear only 0x0B75 and 0x0B76 (preserve 0x0B77)

Implementation:
- Patch LJMP at 0xA4B9 (bytes 02 A5 1A) to LJMP <cave>
- In cave, clear 0x0B75/0x0B76, then LJMP 0xA51A

Outputs:
- out/fw_late_clear_hook_at_a51a.bin
- out/fw_late_clear_hook_at_a51a.diff.txt
- out/fw_late_clear_hook_at_a51a.sum.txt
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_BIN = OUT_DIR / "fw_late_clear_hook_at_a51a.bin"
OUT_DIFF = OUT_DIR / "fw_late_clear_hook_at_a51a.diff.txt"
OUT_SUM = OUT_DIR / "fw_late_clear_hook_at_a51a.sum.txt"

SIZE_EXPECTED = 0x20000

HOOK_ADDR = 0xA4B9  # observed 'ljmp code_A51A' here
HOOK_OLD = bytes([0x02, 0xA5, 0x1A])


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
    # MOV DPTR,#0x0B75 ; CLR A; MOVX @DPTR,A
    stub += bytes([0x90, 0x0B, 0x75, 0xE4, 0xF0])
    # MOV DPTR,#0x0B76 ; MOVX @DPTR,A
    stub += bytes([0x90, 0x0B, 0x76, 0xF0])
    # LJMP 0xA51A
    stub += bytes([0x02, 0xA5, 0x1A])
    # total 12 bytes
    assert len(stub) == 12
    return bytes(stub)


def build() -> None:
    print("SN9C292B Firmware Patch - Late Clear Hook at A51A Entry")
    print("=" * 64)

    base = read_firmware(IN_PATH)
    print(f"Loaded: {IN_PATH} size={len(base):#x}")

    if base[HOOK_ADDR:HOOK_ADDR + 3] != HOOK_OLD:
        raise RuntimeError(f"Unexpected bytes at {HOOK_ADDR:#06x}: {base[HOOK_ADDR:HOOK_ADDR+3].hex()} != {HOOK_OLD.hex()}")

    data = bytearray(base)

    cave_addr = find_code_cave(base, 12, search_end=0x10000)
    print(f"Code cave: 0x{cave_addr:04X} (len=12)")

    stub = assemble_stub()
    data[cave_addr:cave_addr + len(stub)] = stub

    cave_hi = (cave_addr >> 8) & 0xFF
    cave_lo = cave_addr & 0xFF
    data[HOOK_ADDR:HOOK_ADDR + 3] = bytes([0x02, cave_hi, cave_lo])

    write_firmware_atomic(OUT_BIN, bytes(data))
    print(f"Binary: {OUT_BIN}")

    diffs: List[str] = []
    diffs.append(f"Hook @ {HOOK_ADDR:#06x}: {base[HOOK_ADDR:HOOK_ADDR+3].hex().upper()} -> {data[HOOK_ADDR:HOOK_ADDR+3].hex().upper()}")
    diffs.append(f"Stub @ 0x{cave_addr:04X}: {' '.join(f'{b:02X}' for b in stub)}")
    OUT_DIFF.write_text("\n".join(diffs) + "\n")
    print(f"Diff report: {OUT_DIFF}")

    summary: List[str] = []
    summary.append("Late Clear Hook at A51A Entry Build")
    summary.append(f"Generated: {__import__('datetime').datetime.now().isoformat()}")
    summary.append("")
    summary.append(f"Patched LJMP 0xA51A at {HOOK_ADDR:#06x} to LJMP cave 0x{cave_addr:04X}")
    summary.append("Stub clears 0x0B75/0x0B76, preserves 0x0B77, then LJMP 0xA51A")
    OUT_SUM.write_text("\n".join(summary) + "\n")
    print(f"Summary report: {OUT_SUM}")
    print("\n✅ Build complete. Flash and capture USBTree output.")


if __name__ == "__main__":
    build()

