#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Late Clear Hook at A51A (preserve regs)

Goal:
- Hook the LJMP 0xA51A path (at 0xA4B9) but preserve ACC and DPTR to avoid corrupting context
- Clear only 0x0B75 and 0x0B76, leave 0x0B77 untouched

Stub (22 bytes):
  C0 E0        ; PUSH ACC
  C0 82        ; PUSH DPL
  C0 83        ; PUSH DPH
  90 0B 75     ; MOV DPTR,#0x0B75
  E4           ; CLR A
  F0           ; MOVX @DPTR,A
  90 0B 76     ; MOV DPTR,#0x0B76
  F0           ; MOVX @DPTR,A
  D0 83        ; POP DPH
  D0 82        ; POP DPL
  D0 E0        ; POP ACC
  02 A5 1A     ; LJMP 0xA51A

Outputs:
- out/fw_late_clear_hook_at_a51a_v2.bin
- out/fw_late_clear_hook_at_a51a_v2.diff.txt
- out/fw_late_clear_hook_at_a51a_v2.sum.txt
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_BIN = OUT_DIR / "fw_late_clear_hook_at_a51a_v2.bin"
OUT_DIFF = OUT_DIR / "fw_late_clear_hook_at_a51a_v2.diff.txt"
OUT_SUM = OUT_DIR / "fw_late_clear_hook_at_a51a_v2.sum.txt"

SIZE_EXPECTED = 0x20000

HOOK_ADDR = 0xA4B9
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
    stub += bytes([0xC0, 0xE0])              # PUSH ACC
    stub += bytes([0xC0, 0x82])              # PUSH DPL
    stub += bytes([0xC0, 0x83])              # PUSH DPH
    stub += bytes([0x90, 0x0B, 0x75])        # MOV DPTR,#0x0B75
    stub += bytes([0xE4])                    # CLR A
    stub += bytes([0xF0])                    # MOVX @DPTR,A
    stub += bytes([0x90, 0x0B, 0x76])        # MOV DPTR,#0x0B76
    stub += bytes([0xF0])                    # MOVX @DPTR,A
    stub += bytes([0xD0, 0x83])              # POP DPH
    stub += bytes([0xD0, 0x82])              # POP DPL
    stub += bytes([0xD0, 0xE0])              # POP ACC
    stub += bytes([0x02, 0xA5, 0x1A])        # LJMP 0xA51A
    assert len(stub) == 24
    return bytes(stub)


def build() -> None:
    print("SN9C292B Firmware Patch - Late Clear Hook at A51A (preserve regs)")
    print("=" * 70)

    base = read_firmware(IN_PATH)
    print(f"Loaded: {IN_PATH} size={len(base):#x}")

    if base[HOOK_ADDR:HOOK_ADDR + 3] != HOOK_OLD:
        raise RuntimeError(f"Unexpected bytes at {HOOK_ADDR:#06x}: {base[HOOK_ADDR:HOOK_ADDR+3].hex()} != {HOOK_OLD.hex()}")

    data = bytearray(base)

    cave_addr = find_code_cave(base, 24, search_end=0x10000)
    print(f"Code cave: 0x{cave_addr:04X} (len=24)")

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
    summary.append("Late Clear Hook at A51A (preserve regs)")
    summary.append(f"Generated: {__import__('datetime').datetime.now().isoformat()}")
    summary.append(f"Patched LJMP @ {HOOK_ADDR:#06x} -> LJMP cave 0x{cave_addr:04X}")
    summary.append("Stub clears 0x0B75/0x0B76 with ACC/DPTR saved, then LJMP 0xA51A")
    OUT_SUM.write_text("\n".join(summary) + "\n")
    print(f"Summary report: {OUT_SUM}")
    print("\n✅ Build complete. Flash and capture USBTree output.")


if __name__ == "__main__":
    build()

