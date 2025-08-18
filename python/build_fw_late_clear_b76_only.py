#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Late Clear B76 Only (keep B75,B77)

Goal:
- Keep early init intact
- After 0x032C, clear only 0x0B76 (OSD engine enable), preserve 0x0B75 and 0x0B77
- Safer than clearing both enables; earlier late-clear enumerated but still Code 10

Hook:
- Replace LJMP 0xA4A0 at 0x032C with LJMP <cave>
- Cave stub saves ACC/DPTR, clears 0x0B76, restores, LJMP 0xA4A0

Outputs:
- out/fw_late_clear_b76_only.bin
- out/fw_late_clear_b76_only.diff.txt
- out/fw_late_clear_b76_only.sum.txt
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_BIN = OUT_DIR / "fw_late_clear_b76_only.bin"
OUT_DIFF = OUT_DIR / "fw_late_clear_b76_only.diff.txt"
OUT_SUM = OUT_DIR / "fw_late_clear_b76_only.sum.txt"

SIZE_EXPECTED = 0x20000

HOOK_ADDR_EXPECTED = 0x032C
HOOK_OLD = bytes([0x02, 0xA4, 0xA0])  # LJMP 0xA4A0


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


def find_hook_site(data: bytes) -> int:
    if data[HOOK_ADDR_EXPECTED:HOOK_ADDR_EXPECTED + 3] == HOOK_OLD:
        return HOOK_ADDR_EXPECTED
    # Search vicinity
    for i in range(HOOK_ADDR_EXPECTED - 16, HOOK_ADDR_EXPECTED + 17):
        if 0 <= i and i + 3 <= len(data) and data[i:i + 3] == HOOK_OLD:
            return i
    # Global fallback
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
    # PUSH ACC,DPL,DPH; MOV DPTR,#0x0B76; CLR A; MOVX @DPTR,A; POP DPH,DPL,ACC; LJMP 0xA4A0
    stub = bytearray()
    stub += bytes([0xC0, 0xE0, 0xC0, 0x82, 0xC0, 0x83])
    stub += bytes([0x90, 0x0B, 0x76])  # DPTR=0x0B76
    stub += bytes([0xE4, 0xF0])        # CLR A; MOVX @DPTR,A
    stub += bytes([0xD0, 0x83, 0xD0, 0x82, 0xD0, 0xE0])  # POP DPH,DPL,ACC
    stub += bytes([0x02, 0xA4, 0xA0])  # LJMP 0xA4A0
    # total length = 6 + 3 + 2 + 6 + 3 = 20 bytes
    assert len(stub) == 20
    return bytes(stub)


def build() -> None:
    print("SN9C292B Firmware Patch - Late Clear B76 Only")
    print("=" * 52)

    base = read_firmware(IN_PATH)
    print(f"Loaded: {IN_PATH} size={len(base):#x}")

    hook_site = find_hook_site(base)
    print(f"Hook site: 0x{hook_site:04X} (bytes={base[hook_site:hook_site+3].hex().upper()})")

    data = bytearray(base)

    cave_addr = find_code_cave(base, 20, search_end=0x10000)
    print(f"Code cave: 0x{cave_addr:04X} (len=20)")

    stub = assemble_stub()
    data[cave_addr:cave_addr + len(stub)] = stub

    cave_hi = (cave_addr >> 8) & 0xFF
    cave_lo = cave_addr & 0xFF
    data[hook_site:hook_site + 3] = bytes([0x02, cave_hi, cave_lo])

    write_firmware_atomic(OUT_BIN, bytes(data))
    print(f"Binary: {OUT_BIN}")

    diffs: List[str] = []
    diffs.append(f"Hook @ 0x{hook_site:04X}: {base[hook_site:hook_site+3].hex().upper()} -> {data[hook_site:hook_site+3].hex().upper()}")
    diffs.append(f"Stub @ 0x{cave_addr:04X}: {' '.join(f'{b:02X}' for b in stub)}")
    OUT_DIFF.write_text("\n".join(diffs) + "\n")
    print(f"Diff report: {OUT_DIFF}")

    summary: List[str] = []
    summary.append("Late Clear B76 Only Build")
    summary.append(f"Generated: {__import__('datetime').datetime.now().isoformat()}")
    summary.append(f"Hooked 0x032C -> cave 0x{cave_addr:04X}; clears only 0x0B76; preserves 0x0B75/0x0B77")
    OUT_SUM.write_text("\n".join(summary) + "\n")
    print(f"Summary report: {OUT_SUM}")
    print("\n✅ Build complete. Flash and capture USBTree output.")


if __name__ == "__main__":
    build()

