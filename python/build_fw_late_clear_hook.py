#!/usr/bin/env python3
"""
SN9C292B Firmware Patch - Late Clear Hook

Goal:
- Leave all OSD enables and early integrity checks untouched
- Inject a tiny stub that clears 0x0B75, 0x0B76, 0x0B77 late in boot
- Hook it by replacing an existing LJMP with LJMP to our stub, then LJMP back

Hook site chosen:
- At 0x032C: LJMP 0xA4A0 (bytes: 02 A4 A0). We will overwrite with LJMP <stub>.
- Stub will end with LJMP 0xA4A0 to preserve original flow.

Stub bytes (16 bytes total):
  90 0B 75   ; MOV DPTR,#0x0B75
  E4         ; CLR A
  F0         ; MOVX @DPTR,A
  90 0B 76   ; MOV DPTR,#0x0B76
  F0         ; MOVX @DPTR,A
  90 0B 77   ; MOV DPTR,#0x0B77
  F0         ; MOVX @DPTR,A
  02 A4 A0   ; LJMP 0xA4A0 (original target)

We search a code cave (>=16 bytes of 0xFF) within 0x0000..0xFFFF to host the stub.
Priority: high addresses first to minimize interference.

Outputs:
- out/fw_late_clear_hook.bin
- out/fw_late_clear_hook.diff.txt
- out/fw_late_clear_hook.sum.txt
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple, List


IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUT_BIN = OUT_DIR / "fw_late_clear_hook.bin"
OUT_DIFF = OUT_DIR / "fw_late_clear_hook.diff.txt"
OUT_SUM = OUT_DIR / "fw_late_clear_hook.sum.txt"

SIZE_EXPECTED = 0x20000

HOOK_ADDR_EXPECTED = 0x032C
HOOK_OLD = bytes([0x02, 0xA4, 0xA0])  # LJMP 0xA4A0
ORIG_TARGET = (0xA4, 0xA0)  # HI, LO


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
    # Prefer the expected site; otherwise search small window for 02 A4 A0
    if data[HOOK_ADDR_EXPECTED:HOOK_ADDR_EXPECTED + 3] == HOOK_OLD:
        return HOOK_ADDR_EXPECTED
    # Search in vicinity ±16 bytes
    for i in range(HOOK_ADDR_EXPECTED - 16, HOOK_ADDR_EXPECTED + 17):
        if i >= 0 and i + 3 <= len(data) and data[i:i + 3] == HOOK_OLD:
            return i
    # Global fallback (rare)
    idx = data.find(HOOK_OLD)
    if idx != -1:
        return idx
    raise RuntimeError("Hook LJMP 02 A4 A0 not found")


def find_code_cave(data: bytes, length_needed: int, search_end: int = 0x10000) -> int:
    """Search from high addresses downwards within 0x0000..search_end for a run of 0xFF or 0x00."""
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

    # Prefer FF caves
    cave = scan_for(0xFF)
    if cave is not None:
        return cave
    # Fallback: accept 00 caves (NOPs) if available
    cave = scan_for(0x00)
    if cave is not None:
        return cave
    raise RuntimeError("No suitable code cave (FF/00) found within 0x0000..0xFFFF")


def assemble_stub(cave_addr: int) -> bytes:
    # Build the 16-byte stub as documented
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
    # MOV DPTR,#0x0B77
    stub += bytes([0x90, 0x0B, 0x77])
    # MOVX @DPTR,A
    stub += bytes([0xF0])
    # LJMP 0xA4A0 (opcode 0x02, then HI, LO)
    stub += bytes([0x02, ORIG_TARGET[0], ORIG_TARGET[1]])
    assert len(stub) == 16, f"Stub size unexpected: {len(stub)}"
    return bytes(stub)


def build() -> None:
    print("SN9C292B Firmware Patch - Late Clear Hook")
    print("=" * 50)

    base = read_firmware(IN_PATH)
    print(f"Loaded firmware: {IN_PATH}")
    print(f"Size: {len(base):#x} bytes")

    data = bytearray(base)

    # Locate hook site
    hook_site = find_hook_site(base)
    print(f"Hook site: 0x{hook_site:04X} (bytes={base[hook_site:hook_site+3].hex().upper()})")

    # Find code cave for stub (16 bytes) within 0x0000..0xFFFF
    cave_addr = find_code_cave(base, 16, search_end=0x10000)
    print(f"Code cave: 0x{cave_addr:04X} (len=16)")

    # Assemble and place stub
    stub = assemble_stub(cave_addr)
    data[cave_addr:cave_addr + len(stub)] = stub

    # Overwrite LJMP at hook site to jump to stub (opcode 0x02, then HI, LO)
    cave_hi = (cave_addr >> 8) & 0xFF
    cave_lo = cave_addr & 0xFF
    data[hook_site:hook_site + 3] = bytes([0x02, cave_hi, cave_lo])

    # Write output
    write_firmware_atomic(OUT_BIN, bytes(data))
    print(f"Binary: {OUT_BIN}")

    # Prepare diff logs
    diffs: List[str] = []
    diffs.append(f"Hook site @ 0x{hook_site:04X}: {base[hook_site:hook_site+3].hex().upper()} -> {data[hook_site:hook_site+3].hex().upper()}")
    diffs.append(f"Stub placed @ 0x{cave_addr:04X} (16 bytes)")

    OUT_DIFF.write_text("\n".join(diffs) + "\n")
    print(f"Diff report: {OUT_DIFF}")

    # Summary
    summary_lines: List[str] = []
    summary_lines.append("Late Clear Hook Build")
    summary_lines.append(f"Generated: {__import__('datetime').datetime.now().isoformat()}")
    summary_lines.append("")
    summary_lines.append("HOOK:")
    summary_lines.append(f"  Overwrote LJMP at 0x{hook_site:04X} to LJMP 0x{cave_addr:04X}")
    summary_lines.append(f"  Original target preserved via LJMP 0xA4A0 at end of stub")
    summary_lines.append("")
    summary_lines.append("STUB:")
    summary_lines.append(f"  Clears XDATA 0x0B75, 0x0B76, 0x0B77 to 0x00")
    summary_lines.append(f"  Bytes @ 0x{cave_addr:04X}: {' '.join(f'{b:02X}' for b in stub)}")
    summary_lines.append("")
    summary_lines.append("SANITY:")
    for addr, label in ((0x04D0, 'OSD post-boot #1'), (0x0AC4, 'OSD post-boot #2'), (0x0AFE, 'OSD post-boot #3'), (0x4522, 'OSD early init')):
        summary_lines.append(
            f"  {label} @ 0x{addr:04X}: BEFORE={' '.join(f'{b:02X}' for b in base[addr:addr+6])} AFTER={' '.join(f'{b:02X}' for b in data[addr:addr+6])}"
        )

    OUT_SUM.write_text("\n".join(summary_lines) + "\n")
    print(f"Summary report: {OUT_SUM}")
    print("\n✅ Build complete. Flash and collect USBTree output.")


if __name__ == "__main__":
    build()

