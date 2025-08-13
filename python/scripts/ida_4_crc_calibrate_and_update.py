
# IDA 9.1 / IDAPython 3.x
# Action 4 — Calibrate CRC coverage & write updated CRCs after patch
#
# Usage (two phases):
#  Calibrate on STOCK (unmodified) fw to discover the boundary:
#   ida -A -S"ida_4_crc_calibrate_and_update.py --calibrate --base 0x10 --step 0x20" stock.bin
#
#  Then update CRCs on the CURRENT (possibly patched) IDB image and dump to file:
#   ida -A -S"ida_4_crc_calibrate_and_update.py --apply --base 0x10 --boundary 0xE3F2 --out patched.bin" patched.idb
#
# What it does (why):
# 4.1 Reads stored CRC1/CRC2 from header fields.
# 4.2 (Calibrate) Brute-searches for a split boundary that matches both stored CRCs.
# 4.3 (Apply) Recomputes CRCs over [base:boundary) and [boundary:EOF), writes them into header, dumps file.
#
import sys, os, binascii
import idaapi, idc, ida_bytes, ida_name

def get_args():
    argv = sys.argv[1:]
    args = {"calibrate": False, "apply": False, "base": 0x10, "boundary": None, "step": 0x20, "out": None}
    i = 0
    while i < len(argv):
        if argv[i] == "--calibrate":
            args["calibrate"] = True; i += 1
        elif argv[i] == "--apply":
            args["apply"] = True; i += 1
        elif argv[i] == "--base":
            args["base"] = int(argv[i+1], 0); i += 2
        elif argv[i] == "--boundary":
            args["boundary"] = int(argv[i+1], 0); i += 2
        elif argv[i] == "--step":
            args["step"] = int(argv[i+1], 0); i += 2
        elif argv[i] == "--out":
            args["out"] = argv[i+1]; i += 2
        else:
            i += 1
    return args

def info(m): print("[ida_4] " + m)

def get_header_and_crc_fields():
    hdr = idc.get_name_ea_simple("FW_Header_Signature")
    if hdr == idaapi.BADADDR: hdr = 0
    crc1 = idc.get_name_ea_simple("FW_CRC1_LE")
    crc2 = idc.get_name_ea_simple("FW_CRC2_LE")
    if crc1 == idaapi.BADADDR: crc1 = hdr + 0x08
    if crc2 == idaapi.BADADDR: crc2 = hdr + 0x0C
    return hdr, crc1, crc2

def read_u32_le(ea):
    b = ida_bytes.get_bytes(ea, 4)
    if not b: return None
    return int.from_bytes(b, "little")

def write_u32_le(ea, val):
    ida_bytes.patch_bytes(ea, int(val & 0xFFFFFFFF).to_bytes(4, "little"))

def grab_image():
    # Dump full input file image (0..max_ea is usually fine for flat BIN)
    maxea = idaapi.get_inf_structure().max_ea
    return ida_bytes.get_bytes(0, maxea) or b""

def calibrate(base, step):
    hdr, crc1_ea, crc2_ea = get_header_and_crc_fields()
    data = grab_image()
    if len(data) < base + 0x100:
        info("Image too small for calibration."); return None
    stored1 = read_u32_le(crc1_ea)
    stored2 = read_u32_le(crc2_ea)
    info(f"Stored CRC1={stored1:08X} CRC2={stored2:08X}")
    found = None
    # Search split point; coarse step then refine ±step
    for split in range(base+0x400, len(data)-0x400, step):
        c1 = binascii.crc32(data[base:split]) & 0xFFFFFFFF
        c2 = binascii.crc32(data[split:len(data)]) & 0xFFFFFFFF
        if c1 == stored1 and c2 == stored2:
            found = split
            info(f"Boundary found @ 0x{split:04X}")
            break
    if not found:
        info("Boundary not found with current step; try smaller --step or verify header/CRC offsets.")
    return found

def apply(base, boundary, outpath):
    hdr, crc1_ea, crc2_ea = get_header_and_crc_fields()
    data = grab_image()
    if boundary is None:
        info("Boundary is required for --apply."); return
    c1 = binascii.crc32(data[base:boundary]) & 0xFFFFFFFF
    c2 = binascii.crc32(data[boundary:len(data)]) & 0xFFFFFFFF
    write_u32_le(crc1_ea, c1)
    write_u32_le(crc2_ea, c2)
    info(f"Updated CRC1={c1:08X} CRC2={c2:08X} in IDB image.")
    # Dump to file
    if not outpath:
        outpath = "fw_patched_with_crc.bin"
    with open(outpath, "wb") as f:
        f.write(ida_bytes.get_bytes(0, len(data)))
    info(f"Wrote {len(data)} bytes to {outpath}")

def main():
    args = get_args()
    if args["calibrate"]:
        split = calibrate(args["base"], args["step"])
        if split:
            info(f"Calibration OK. Use --boundary 0x{split:X} for apply phase.")
    if args["apply"]:
        apply(args["base"], args["boundary"], args["out"])

if __name__ == "__main__":
    main()
