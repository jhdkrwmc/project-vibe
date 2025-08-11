# track_ram_flow.py
# IDA Pro 9.x | 8051 (mcs51) firmware
# Scan for XDATA (MOVX) accesses to target ranges (e.g., 0x0B00-0x0BFF) and write a JSON report.
#
# Output:
#   <IDA user dir>/ram_usage_analysis.json
#   <DB folder>   /ram_usage_analysis.json  (copy)
#
# Each item:
#   {
#     "func_ea": "0x....", "func_name": "...",
#     "dptr_set_ea": "0x....", "movx_ea": "0x....",
#     "target": "0x0Bxx", "access": "write|read",
#     "imm_val": "0x.. | null",
#     "context32": "AA BB ...",             # 32B from dptr_set_ea
#     "bytes_movx": "AA BB ...",            # 8B around movx
#   }

import idaapi, idautils, idc
import ida_bytes, ida_funcs, ida_segment
import json, os

# ----------------------------- CONFIG ---------------------------------

# XDATA address windows to scan. Add more tuples if needed.
SCAN_XDATA_RANGES = [
    (0x0B00, 0x0BFF),   # OSD / control cluster
    # (0x0000, 0xFFFF), # <- uncomment to scan all XDATA (slower)
]

# How far ahead after a DPTR set to look for the MOVX that uses it
LOOKAHEAD_INSNS = 8

# Bytes to capture for context around the two key sites
CONTEXT_BEFORE_MOVX = 4
CONTEXT_AFTER_MOVX  = 4
CONTEXT_AT_DPTR     = 32

# ----------------------------------------------------------------------

def get_db_dir() -> str:
    """Robust path to current DB folder (IDA 8/9)."""
    try:
        p = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        if p:
            return os.path.dirname(p)
    except Exception:
        pass
    try:
        import ida_nalt
        p = ida_nalt.get_input_file_path()
        if p:
            return os.path.dirname(p)
    except Exception:
        pass
    try:
        p = idaapi.get_input_file_path()
        if p:
            return os.path.dirname(p)
    except Exception:
        pass
    return os.getcwd()

def is_code_ea(ea: int) -> bool:
    try:
        return ida_bytes.is_code(ida_bytes.get_full_flags(ea))
    except Exception:
        return idaapi.is_code(idaapi.get_flags(ea))

def op(ea: int, n: int) -> str:
    s = idc.print_operand(ea, n)
    return (s or "").lower()

def mnem(ea: int) -> str:
    return (idc.print_insn_mnem(ea) or "").lower()

def get_bytes_hex(ea: int, n: int) -> str:
    b = idaapi.get_bytes(ea, n) or b""
    return " ".join(f"{x:02X}" for x in b)

def in_any_range(val: int, ranges) -> bool:
    for lo, hi in ranges:
        if lo <= val <= hi:
            return True
    return False

def parse_imm16_from_mov_dptr(ea: int) -> int | None:
    """
    Expect something like:  MOV DPTR, #0x0B75
    On 8051 in IDA, operand 1 is an immediate; idc.get_operand_value returns integer.
    """
    if mnem(ea) != "mov":
        return None
    if op(ea, 0) != "dptr":
        return None
    # Immediate?
    try:
        t = idc.get_operand_type(ea, 1)
        if t != idc.o_imm:
            return None
        v = idc.get_operand_value(ea, 1)
        if v is None:
            return None
        return int(v) & 0xFFFF
    except Exception:
        return None

def find_movx_use_after(ea_dptr: int, func_end: int):
    """
    Scan forward up to LOOKAHEAD_INSNS inside the function for a MOVX using @DPTR.
    Return (ea_movx, is_write) or (None, None).
    """
    ea = ea_dptr
    steps = 0
    while steps < LOOKAHEAD_INSNS:
        ea = idc.next_head(ea, func_end)
        if ea == idc.BADADDR or ea >= func_end:
            break
        mm = mnem(ea)
        if mm != "movx":
            steps += 1
            continue
        # MOVX patterns of interest:
        #   MOVX @DPTR, A   -> write
        #   MOVX A, @DPTR   -> read
        dst = op(ea, 0)
        src = op(ea, 1)
        if dst == "@dptr" and src == "a":
            return ea, True
        if dst == "a" and src == "@dptr":
            return ea, False
        steps += 1
    return None, None

def find_imm_before_movx(ea_start: int, ea_end: int):
    """
    If sequence is: MOV A, #imm ... MOVX @DPTR, A
    return imm value; also accept CLR A as imm=0.
    """
    ea = ea_start
    while ea < ea_end:
        ea = idc.next_head(ea, ea_end)
        if ea == idc.BADADDR or ea >= ea_end:
            break
        mm = mnem(ea)
        if mm == "mov" and op(ea, 0) == "a" and idc.get_operand_type(ea, 1) == idc.o_imm:
            return int(idc.get_operand_value(ea, 1)) & 0xFF
        if mm == "clr" and op(ea, 0) == "a":
            return 0
    return None

def analyze_function_for_xdata(fn) -> list[dict]:
    """
    Inside a function, look for:
        MOV DPTR,#imm16  (imm in target ranges)
        ... within N instructions ...
        MOVX @DPTR,A   (write)  [optionally preceded by MOV A,#imm / CLR A]
      or
        MOVX A,@DPTR   (read)
    """
    rows = []
    ea = fn.start_ea
    while ea < fn.end_ea:
        # DPTR set?
        imm16 = parse_imm16_from_mov_dptr(ea)
        if imm16 is not None and in_any_range(imm16, SCAN_XDATA_RANGES):
            movx_ea, is_write = find_movx_use_after(ea, fn.end_ea)
            if movx_ea:
                imm_val = None
                if is_write:
                    imm_val = find_imm_before_movx(ea, movx_ea)
                rows.append({
                    "func_ea": f"0x{fn.start_ea:X}",
                    "func_name": idc.get_func_name(fn.start_ea) or f"sub_{fn.start_ea:X}",
                    "dptr_set_ea": f"0x{ea:X}",
                    "movx_ea": f"0x{movx_ea:X}",
                    "target": f"0x{imm16:04X}",
                    "access": "write" if is_write else "read",
                    "imm_val": f"0x{imm_val:02X}" if imm_val is not None else None,
                    "context32": get_bytes_hex(ea, CONTEXT_AT_DPTR),
                    "bytes_movx": get_bytes_hex(max(fn.start_ea, movx_ea - CONTEXT_BEFORE_MOVX),
                                                CONTEXT_BEFORE_MOVX + CONTEXT_AFTER_MOVX)
                })
                # continue scanning after movx_ea
                ea = movx_ea
        ea = idc.next_head(ea, fn.end_ea)
        if ea == idc.BADADDR:
            break
    return rows

def analyze_ram_flow():
    all_rows = []
    # Limit to CODE segments
    qty = idaapi.get_segm_qty()
    for i in range(qty):
        s = idaapi.getnseg(i)
        if not s or s.type != ida_segment.SEG_CODE:
            continue
        # iterate functions in this segment
        ea = s.start_ea
        while ea < s.end_ea:
            f = ida_funcs.get_func(ea)
            if not f:
                ea = idc.next_head(ea, s.end_ea)
                if ea == idc.BADADDR:
                    break
                continue
            all_rows.extend(analyze_function_for_xdata(f))
            ea = f.end_ea

    # Compose output
    out = {
        "ranges": [{"start": f"0x{lo:04X}", "end": f"0x{hi:04X}"} for (lo, hi) in SCAN_XDATA_RANGES],
        "items": all_rows,
        "counts": {
            "total": len(all_rows),
            "writes": sum(1 for r in all_rows if r["access"] == "write"),
            "reads":  sum(1 for r in all_rows if r["access"] == "read"),
        }
    }

    # Save to user dir
    user_path = os.path.join(idaapi.get_user_idadir(), "ram_usage_analysis.json")
    with open(user_path, "w", encoding="utf-8") as fp:
        json.dump(out, fp, indent=2)
    print(f"[=] wrote {user_path} ({len(all_rows)} items)")

    # Save next to DB as well
    proj_path = os.path.join(get_db_dir(), "ram_usage_analysis.json")
    if proj_path != user_path:
        with open(proj_path, "w", encoding="utf-8") as fp:
            json.dump(out, fp, indent=2)
        print(f"[=] copied to {proj_path}")

def main():
    print("=== track_ram_flow.py (8051/XDATA MOVX scanner) ===")
    print("Scan ranges:", ", ".join([f"0x{lo:04X}-0x{hi:04X}" for lo,hi in SCAN_XDATA_RANGES]))
    analyze_ram_flow()
    print("[=] Done.")

if __name__ == "__main__":
    main()
