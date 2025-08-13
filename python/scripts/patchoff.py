#!/usr/bin/env python3
import sys, pathlib, struct, hashlib

OFFS = [0x4D0, 0xAC4, 0xAFE]          # 3 MOVX @0B76/77,#01 sites

if len(sys.argv) < 2:
    print("usage: repack_osd_off.py  <128-KiB-dump.bin>")
    sys.exit(1)

p      = pathlib.Path(sys.argv[1])
data   = bytearray(p.read_bytes())
assert len(data) == 0x20000, "file must be 131 072 bytes"

for off in OFFS:                      # flip 01 → 00
    assert data[off+4] == 0x01, f"pattern mismatch at {hex(off)}"
    data[off+4] = 0x00

# ----- correct way: write only two bytes, don’t truncate -----
chk = (-sum(data[:0x1FFE]) & 0xFFFF)  # additive 16-bit checksum
data[0x1FFE] =  chk       & 0xFF      # LSB
data[0x1FFF] = (chk >> 8) & 0xFF      # MSB

out   = p.with_suffix('.osd_off_fixed.bin')
out.write_bytes(data)
print("patched ->", out, "SHA-256", hashlib.sha256(data).hexdigest())
