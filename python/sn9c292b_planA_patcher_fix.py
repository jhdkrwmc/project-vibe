#!/usr/bin/env python3
import argparse, sys

IMG_SIZE_EXPECTED = 128 * 1024  # 131072

# Post-integrity window and behavior
SITE_ADDR    = 0xF094
SITE_EXPECT6 = bytes([0x90,0x09,0x8F,0x74,0x01,0xF0])  # MOV DPTR,#098F ; MOV A,#1 ; MOVX @DPTR,A

# We replace the 6-byte window with LJMP cave + NOPs (no re-emit at 0xF09A!)
CAVE_ADDR    = 0x00BFA8
OSD_HELPER   = 0x00BB73

# Stub will: save regs, call helper, perform displaced MOV A,#1 ; MOVX @0x098F,A, restore regs, jump back to 0xF09A
RETURN_ADDR  = 0x00F09A


def hexb(b: bytes) -> str:
    return ' '.join(f'{x:02X}' for x in b)


def sum16_bytes(d: bytes) -> int:
    return sum(d) & 0xFFFF


def sum16_words_le(d: bytes) -> int:
    n=len(d)
    total=0
    i=0
    while i+1<n:
        total=(total + (d[i] | (d[i+1]<<8))) & 0xFFFF
        i+=2
    if i<n:
        total=(total + d[i]) & 0xFFFF  # if odd
    return total


def pick_scheme(orig: bytes, footer_addr: int) -> str:
    sb_as_is = sum16_bytes(orig)
    sw_as_is = sum16_words_le(orig)
    if sb_as_is == 0 and sw_as_is != 0: return "byte"
    if sw_as_is == 0 and sb_as_is != 0: return "word"
    if sb_as_is == 0 and sw_as_is == 0: return "word"
    work = bytearray(orig)
    work[footer_addr:footer_addr+2] = b'\x00\x00'
    sb_base = sum16_bytes(work)
    sw_base = sum16_words_le(work)
    if sb_base != 0 and sw_base == 0: return "word"
    if sw_base != 0 and sb_base == 0: return "byte"
    return "word"


def calc_fix_bytes(data: bytearray, footer_addr: int, scheme: str) -> int:
    data[footer_addr:footer_addr+2] = b'\x00\x00'
    s = sum16_bytes(data) if scheme == "byte" else sum16_words_le(data)
    fix = (-s) & 0xFFFF
    data[footer_addr]     = fix & 0xFF
    data[footer_addr + 1] = (fix >> 8) & 0xFF
    return fix


def build_stub() -> bytes:
    code = bytearray()
    # save regs we will clobber
    code += bytes([0xC0,0xD0])  # PUSH PSW
    code += bytes([0xC0,0xE0])  # PUSH ACC
    code += bytes([0xC0,0x82])  # PUSH DPL
    code += bytes([0xC0,0x83])  # PUSH DPH
    # call OSD helper
    code += bytes([0x12, (OSD_HELPER>>8)&0xFF, OSD_HELPER & 0xFF])  # LCALL 0xBB73
    # perform displaced ops: MOV DPTR,#0x098F ; MOV A,#1 ; MOVX @DPTR,A
    code += bytes([0x90, 0x09, 0x8F, 0x74, 0x01, 0xF0])
    # restore regs
    code += bytes([0xD0,0x83])  # POP DPH
    code += bytes([0xD0,0x82])  # POP DPL
    code += bytes([0xD0,0xE0])  # POP ACC
    code += bytes([0xD0,0xD0])  # POP PSW
    # jump back to 0xF09A (next original instruction)
    code += bytes([0x02, (RETURN_ADDR>>8)&0xFF, RETURN_ADDR & 0xFF])  # LJMP RETURN_ADDR
    return bytes(code)


def main():
    ap = argparse.ArgumentParser(description="SN9C292B Plan A FIX patcher (stub in cave, no touch @0xF09A)")
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--no-size-check", action="store_true")
    args = ap.parse_args()

    data = bytearray(open(args.input, "rb").read())
    n = len(data)
    if not args.no_size_check and n != IMG_SIZE_EXPECTED:
        print(f"[ERROR] Unexpected size {n}, expected {IMG_SIZE_EXPECTED}", file=sys.stderr)
        sys.exit(2)

    footer = n - 2

    # Guard window
    have6 = bytes(data[SITE_ADDR:SITE_ADDR+6])
    if have6 != SITE_EXPECT6:
        print(f"[ERROR] Signature mismatch at 0x{SITE_ADDR:04X}. Have: {hexb(have6)} Want: {hexb(SITE_EXPECT6)}", file=sys.stderr)
        sys.exit(3)

    # Guard cave space is zeroed (at least 32 bytes)
    cave_span = bytes(data[CAVE_ADDR:CAVE_ADDR+32])
    if any(b != 0x00 for b in cave_span):
        print(f"[ERROR] Cave @0x{CAVE_ADDR:04X} not blank", file=sys.stderr)
        sys.exit(4)

    # Write stub in cave
    stub = build_stub()
    data[CAVE_ADDR:CAVE_ADDR+len(stub)] = stub

    # Replace site: LJMP cave + NOP NOP NOP
    data[SITE_ADDR:SITE_ADDR+6] = bytes([0x02, (CAVE_ADDR>>8)&0xFF, CAVE_ADDR & 0xFF, 0x00, 0x00, 0x00])

    # Choose checksum scheme on original
    scheme = pick_scheme(open(args.input, "rb").read(), footer)

    # Fix footer
    fix = calc_fix_bytes(data, footer, scheme)

    # Verify
    final = sum16_bytes(data) if scheme == "byte" else sum16_words_le(data)
    if final != 0:
        print(f"[ERROR] Final {scheme}-sum != 0 (0x{final:04X})", file=sys.stderr)
        sys.exit(5)

    # Report
    print("== Plan A FIX summary ==")
    print(f"Image size          : {n} bytes")
    print(f"Footer addr         : 0x{footer:05X}")
    print(f"Scheme (auto)       : {scheme}-sum16")
    print(f"Site @0x{SITE_ADDR:04X}: {hexb(SITE_EXPECT6)}  ->  LJMP 0x{CAVE_ADDR:04X} ; 00 00 00")
    print(f"Stub @0x{CAVE_ADDR:04X}  : {len(stub)} bytes (save regs, call 0x{OSD_HELPER:04X}, displaced MOV A,#1;MOVX, restore, LJMP 0x{RETURN_ADDR:04X})")
    print(f"Fix word (LE)       : 0x{fix:04X}")
    print(f"Final {scheme}-sum16: 0x{final:04X}")

    open(args.output, "wb").write(data)
    print(f"[OK] wrote {args.output}")


if __name__ == "__main__":
    main()


