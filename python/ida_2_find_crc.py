
# IDA 9.1 / IDAPython 3.x
# Action 2 — Locate CRC routine(s) and references to header CRC fields
#
# Usage:
#   ida -A -S"ida_2_find_crc.py --hdr 0x0 --crc1_off 0x8 --crc2_off 0xC" firmware.bin
#
# What it does (why):
# 2.1 Finds header & CRC fields (by signature or provided offsets).
# 2.2 Finds XREFs to those addresses (typical MOV DPTR,#imm; reads).
# 2.3 Scans for CRC-32 polynomial bytes (ED B8 83 20) and nearby functions.
# 2.4 Ranks & renames likely CRC functions; emits a report.
#
import sys, struct
import idaapi, idc
import ida_bytes, ida_auto, ida_name, ida_search, ida_funcs, ida_kernwin, ida_ua

def get_args():
    argv = sys.argv[1:]
    args = {"hdr": None, "crc1_off": 0x8, "crc2_off": 0xC}
    i = 0
    while i < len(argv):
        if argv[i] == "--hdr":
            args["hdr"] = int(argv[i+1], 0); i += 2
        elif argv[i] == "--crc1_off":
            args["crc1_off"] = int(argv[i+1], 0); i += 2
        elif argv[i] == "--crc2_off":
            args["crc2_off"] = int(argv[i+1], 0); i += 2
        else:
            i += 1
    return args

def info(m): print("[ida_2] " + m)

def find_header(default=None):
    if default is not None:
        return default
    # try name set by previous script
    ea = idc.get_name_ea_simple("FW_Header_Signature")
    if ea != idaapi.BADADDR:
        return ea
    # try scan
    data = ida_bytes.get_bytes(0, 0x200) or b""
    off = data.find(b"SN9C292")
    if off >= 0:
        return off
    return None

def find_mov_dptr_refs(addr):
    # MOV DPTR,#imm16 opcode is 0x90 HI LO
    hi = (addr >> 8) & 0xFF
    lo = addr & 0xFF
    pat1 = bytes([0x90, hi, lo])
    pat2 = bytes([0x90, lo, hi])  # handle weirdness just in case
    res = []
    img = ida_bytes.get_bytes(0, idaapi.get_inf_structure().max_ea) or b""
    for pat in (pat1, pat2):
        pos = 0
        while True:
            pos = img.find(pat, pos)
            if pos < 0: break
            res.append(pos)
            pos += 1
    return sorted(set(res))

def func_of(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else None

def search_crc_poly():
    # Look for EDB88320 (little-endian) byte sequence inside file
    poly = b"\x20\x83\xB8\xED"
    img = ida_bytes.get_bytes(0, idaapi.get_inf_structure().max_ea) or b""
    hits = []
    pos = 0
    while True:
        pos = img.find(poly, pos)
        if pos < 0: break
        hits.append(pos)
        pos += 1
    return hits

def main():
    args = get_args()
    hdr = find_header(args["hdr"])
    if hdr is None:
        info("Header not found. Provide --hdr.")
        return
    crc1_ptr = hdr + args["crc1_off"]
    crc2_ptr = hdr + args["crc2_off"]
    ida_name.set_name(crc1_ptr, "FW_CRC1_LE", ida_name.SN_CHECK)
    ida_name.set_name(crc2_ptr, "FW_CRC2_LE", ida_name.SN_CHECK)
    info(f"Header @ 0x{hdr:04X}; CRC1 @ 0x{crc1_ptr:04X}; CRC2 @ 0x{crc2_ptr:04X}")

    # 2.2 XREF-like scan for MOV DPTR,#(crc_field)
    refs1 = find_mov_dptr_refs(crc1_ptr)
    refs2 = find_mov_dptr_refs(crc2_ptr)
    info(f"MOV DPTR,#CRC1 refs: {[hex(x) for x in refs1[:10]]}{' ...' if len(refs1)>10 else ''}")
    info(f"MOV DPTR,#CRC2 refs: {[hex(x) for x in refs2[:10]]}{' ...' if len(refs2)>10 else ''}")

    # Map to functions & rename
    cand_funcs = {}
    for ea in refs1 + refs2:
        fea = func_of(ea)
        if fea:
            cand_funcs[fea] = cand_funcs.get(fea, 0) + 1
    # 2.3 Scan polynomial locations
    polys = search_crc_poly()
    info(f"CRC poly byte hits: {[hex(x) for x in polys[:10]]}{' ...' if len(polys)>10 else ''}")
    for ea in polys:
        fea = func_of(ea)
        if fea:
            cand_funcs[fea] = cand_funcs.get(fea, 0) + 2  # weight poly-hits higher

    # 2.4 Rank candidates
    ranked = sorted(cand_funcs.items(), key=lambda kv: kv[1], reverse=True)
    for i,(fea,score) in enumerate(ranked[:10],1):
        ida_name.set_name(fea, f"crc_candidate_{i}", ida_name.SN_CHECK)
        ida_bytes.set_cmt(fea, f"Likely CRC routine (score={score})", 1)
        info(f"CRC candidate {i}: 0x{fea:04X} (score={score})")
    info("Done. Review candidates and rename the true one to 'crc32_check' for the next steps, if desired.")

if __name__ == "__main__":
    main()
