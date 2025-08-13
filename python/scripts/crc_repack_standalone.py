
#!/usr/bin/env python3
# External helper — Recompute & repack CRCs without IDA
#
# Usage:
#   python crc_repack.py in.bin out.bin --base 0x10 --boundary 0xE3F2
#   python crc_repack.py in.bin out.bin --base 0x10 --autocal
#
# Notes:
# - Assumes two 32-bit LE CRCs are stored at header+0x08 and +0x0C.
# - --autocal tries to find the split by matching existing stored CRCs (on stock fw).
#
import sys, os, binascii

def crc32(data): return binascii.crc32(data) & 0xFFFFFFFF

def read_u32_le(buf, off): return int.from_bytes(buf[off:off+4], "little")
def write_u32_le(buf, off, val): buf[off:off+4] = int(val & 0xFFFFFFFF).to_bytes(4, "little")

def autocal(buf, base, hdr):
    stored1 = read_u32_le(buf, hdr+0x08)
    stored2 = read_u32_le(buf, hdr+0x0C)
    for step in (0x100, 0x40, 0x10, 0x04, 0x01):
        lo = base+0x400
        hi = len(buf)-0x400
        while lo < hi:
            c1 = crc32(buf[base:lo]); c2 = crc32(buf[lo:])
            if c1 == stored1 and c2 == stored2:
                return lo
            lo += step
    return None

def main():
    if len(sys.argv) < 3:
        print("Usage: crc_repack.py IN.bin OUT.bin [--base 0x10] [--boundary 0xE3F2 | --autocal] [--hdr 0x0]")
        return
    inf, outf = sys.argv[1], sys.argv[2]
    base = 0x10
    hdr = 0x0
    boundary = None
    autocal_flag = False
    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == "--base":
            base = int(sys.argv[i+1], 0); i += 2
        elif sys.argv[i] == "--boundary":
            boundary = int(sys.argv[i+1], 0); i += 2
        elif sys.argv[i] == "--autocal":
            autocal_flag = True; i += 1
        elif sys.argv[i] == "--hdr":
            hdr = int(sys.argv[i+1], 0); i += 2
        else:
            i += 1

    buf = bytearray(open(inf, "rb").read())
    if autocal_flag and boundary is None:
        boundary = autocal(buf, base, hdr)
        if boundary is None:
            print("Auto-calibration failed. Provide --boundary explicitly."); return
        print(f"[crc_repack] boundary: 0x{boundary:04X}")

    if boundary is None:
        print("Boundary is required (or use --autocal)."); return

    c1 = crc32(buf[base:boundary])
    c2 = crc32(buf[boundary:])
    write_u32_le(buf, hdr+0x08, c1)
    write_u32_le(buf, hdr+0x0C, c2)
    with open(outf, "wb") as f:
        f.write(buf)
    print(f"[crc_repack] wrote {outf}; CRC1={c1:08X} CRC2={c2:08X}")

if __name__ == "__main__":
    main()
