
# IDA 9.1 / IDAPython 3.x
# Action 1 — Load & map firmware, set processor, mark header, find code start
#
# Usage (headless):
#   ida -A -B -S"ida_1_load_map.py --code-start 0x???? --xdata-size 0x1000" firmware.bin
#
# If --code-start is omitted, a heuristic scan is used.
#
# What it does (why):
# 1.1 Set processor to 8051 (mcs51) so IDA decodes instructions correctly.
# 1.2 Tag the SN9C292 header and CRC fields for later scripts to reference.
# 1.3 Create an XDATA segment (external RAM) for better MOVX analysis.
# 1.4 Heuristically locate first real code and set an entry point for analysis.
# 1.5 Run auto-analysis and add comments to key areas.
#
import sys, struct, re
import idaapi, idc
import ida_bytes, ida_auto, ida_name, ida_funcs, ida_kernwin, ida_nalt, ida_idaapi, ida_segment, ida_ua, ida_idp

def get_args():
    # IDA passes args via sys.argv after the script name
    argv = sys.argv[1:]
    args = {"code_start": None, "xdata_size": 0x1000}
    i = 0
    while i < len(argv):
        if argv[i] == "--code-start":
            args["code_start"] = int(argv[i+1], 0); i += 2
        elif argv[i] == "--xdata-size":
            args["xdata_size"] = int(argv[i+1], 0); i += 2
        else:
            i += 1
    return args

def info(m): print("[ida_1] " + m)

def set_processor():
    import ida_idp
    # Ensure 8051. Prefer USER level; fall back to LOADER_NON_FATAL.
    try:
        ok = idc.set_processor_type("mcs51", ida_idp.SETPROC_USER)
    except Exception:
        ok = idc.set_processor_type("mcs51", ida_idp.SETPROC_LOADER_NON_FATAL)
    info("Processor set to mcs51 (8051/8032). ok=%s" % ok)

def find_signature():
    # Search for ASCII "SN9C292" (with optional terminator)
    bin_start = idaapi.get_segm_by_name(".text").start_ea if idaapi.get_segm_by_name(".text") else 0
    bin_end   = idaapi.get_segm_by_name(".text").end_ea if idaapi.get_segm_by_name(".text") else idaapi.get_inf_structure().max_ea
    max_scan = min(bin_start + 0x100, bin_end)  # header should be very early
    data = ida_bytes.get_bytes(bin_start, max_scan - bin_start) or b""
    off = data.find(b"SN9C292")
    if off < 0:
        # fallback: look for "SN9C"
        off = data.find(b"SN9C")
    if off >= 0:
        hdr_ea = bin_start + off
        return hdr_ea
    return None

def mark_header(hdr_ea):
    ida_bytes.set_cmt(hdr_ea, "SN9C292 header signature", 0)
    # Assume two 32-bit CRCs at +0x08 and +0x0C (LE). We won't hard-rely—scripts stay overrideable.
    crc1_ea = hdr_ea + 0x08
    crc2_ea = hdr_ea + 0x0C
    ida_name.set_name(hdr_ea, "FW_Header_Signature", ida_name.SN_CHECK)
    ida_name.set_name(crc1_ea, "FW_CRC1_LE", ida_name.SN_CHECK)
    ida_name.set_name(crc2_ea, "FW_CRC2_LE", ida_name.SN_CHECK)
    ida_bytes.set_cmt(crc1_ea, "CRC#1 (32-bit LE) — main region (assumed)", 0)
    ida_bytes.set_cmt(crc2_ea, "CRC#2 (32-bit LE) — data region (assumed)", 0)
    info(f"Header @ 0x{hdr_ea:04X} (CRC1 @ +0x08, CRC2 @ +0x0C).")

def create_xdata_segment(size):
    # Create a non-backed XDATA segment for 8051 external RAM at 0x0000..size
    start = 0x00000000
    end   = start + size
    seg = ida_segment.segment_t()
    seg.start_ea = start
    seg.end_ea   = end
    seg.align    = ida_segment.saRelPara
    seg.comb     = ida_segment.scPub
    seg.bitness  = 0          # 8-bit for 8051
    seg.perm     = ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE
    if ida_segment.add_segm_ex(seg, "XDATA", "XDATA", ida_segment.ADDSEG_SPARSE|ida_segment.ADDSEG_QUIET):
        info(f"Created XDATA segment 0x{start:04X}..0x{end:04X}.")
    else:
        info("XDATA segment create failed (might already exist).")

def is_valid_code_window(ea, length=128, min_ok=64):
    # Try to decode 'length' bytes of instructions; if enough decodes succeed, consider as code window
    ok = 0
    ptr = ea
    for _ in range(200):  # limit number of insns decoded
        if ptr >= ea + length: break
        sz = ida_ua.create_insn(ptr)
        if sz <= 0:
            ptr += 1
            continue
        ok += sz
        ptr += sz
    return ok >= min_ok

def find_code_start_heuristic():
    # Scan early area (first 0x800 bytes) for a window that decodes well
    start = idaapi.get_segm_by_name(".text").start_ea if idaapi.get_segm_by_name(".text") else 0
    end   = start + 0x800
    step  = 8
    best = None
    for ea in range(start, end, step):
        if is_valid_code_window(ea, length=192, min_ok=96):
            best = ea; break
    return best

def add_entry(ea):
    try:
        ida_funcs.add_func(ea, idaapi.BADADDR)
    except:
        pass
    idc.add_entry(ea, ea, "start", True)
    ida_bytes.set_cmt(ea, "Heuristic code start", 0)
    info(f"Entry set at 0x{ea:04X}.")

def main():
    args = get_args()
    set_processor()

    hdr = find_signature()
    if hdr: mark_header(hdr)
    else: info("SN9C292 signature not found (will proceed).")

    # Create XDATA to help MOVX analysis
    create_xdata_segment(args["xdata_size"])

    code_start = args["code_start"] or find_code_start_heuristic()
    if not code_start:
        # fall back to 0x100 as a safe-ish default
        code_start = 0x100
        info("Heuristic failed; using fallback 0x100.")
    add_entry(code_start)

    ida_auto.auto_wait()
    info("Auto-analysis complete.")

if __name__ == "__main__":
    main()
