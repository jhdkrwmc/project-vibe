# track_memory_initialization.py
# IDA Pro 9.x | 8051 (mcs51)
#
# Purpose
#   Track initialization / modification of selected XDATA addresses
#   (e.g., 0x0B76 / 0x0B77 / 0x0BA5) by detecting:
#     MOV DPTR,#<addr>  ... (≤N insns) ...  MOVX @DPTR,A  -> write
#     MOV DPTR,#<addr>  ... (≤N insns) ...  MOVX A,@DPTR  -> read
#   If a write is preceded by "MOV A,#imm" or "CLR A", the immediate value is recorded.
#
# Output
#   <IDA user dir>/memory_initialization_analysis.json
#   <DB folder>   /memory_initialization_analysis.json (copy)
#
# Each access item:
#   {
#     "ea": "0x....",                 # EA of the MOVX
#     "dptr_set_ea": "0x....",        # EA of the MOV DPTR,#imm
#     "access_type": "write|read",
#     "value": "0x.. | null",         # immediate written (if detected)
#     "function": "name",
#     "target": "0x0B76",
#     "context_before": [ {"ea":"0x..","disasm":"..."} , ... ],
#     "context_after":  [ ... ]
#   }

import json
import os
from collections import defaultdict

import idaapi, idautils, idc
import ida_bytes, ida_funcs, ida_segment

# ----------------------------- CONFIG ---------------------------------

MEMORY_LOCATIONS = [0x0B76, 0x0B77, 0x0BA5]  # edit as needed
LOOKAHEAD_INSNS  = 8                         # search window after DPTR set
CTX_BEFORE_INSNS = 6                         # lines of disasm before MOVX
CTX_AFTER_INSNS  = 10                        # lines of disasm after MOVX

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

def is_code_seg_ea(ea: int) -> bool:
    s = ida_segment.getseg(ea)
    return bool(s) and s.type == ida_segment.SEG_CODE

def is_code_ea(ea: int) -> bool:
    try:
        return ida_bytes.is_code(ida_bytes.get_full_flags(ea))
    except Exception:
        return idaapi.is_code(idaapi.get_flags(ea))

def mnem(ea: int) -> str:
    return (idc.print_insn_mnem(ea) or "").lower()

def op(ea: int, n: int) -> str:
    return (idc.print_operand(ea, n) or "").lower()

def dis(ea: int) -> str:
    return idc.generate_disasm_line(ea, 0) or idc.GetDisasm(ea) or ""

def parse_mov_dptr_imm(ea: int) -> int | None:
    """Return 16-bit immediate if instruction is MOV DPTR,#imm."""
    if mnem(ea) != "mov":
        return None
    if op(ea, 0) != "dptr":
        return None
    if idc.get_operand_type(ea, 1) != idc.o_imm:
        return None
    try:
        return int(idc.get_operand_value(ea, 1)) & 0xFFFF
    except Exception:
        return None

def find_movx_use_after(ea_start: int, fn_end: int):
    """
    Scan forward up to LOOKAHEAD_INSNS for a MOVX using DPTR.
    Returns (ea_movx, access_type) or (None, None).
    """
    cnt = 0
    ea = ea_start
    while cnt < LOOKAHEAD_INSNS:
        ea = idc.next_head(ea, fn_end)
        if ea == idc.BADADDR or ea >= fn_end:
            break
        mm = mnem(ea)
        if mm != "movx":
            cnt += 1
            continue
        dst = op(ea, 0)
        src = op(ea, 1)
        if dst == "@dptr" and src == "a":
            return ea, "write"
        if dst == "a" and src == "@dptr":
            return ea, "read"
        cnt += 1
    return None, None

def find_imm_for_write(dptr_ea: int, movx_ea: int, fn_start: int):
    """
    Look between DPTR set and MOVX for immediate accumulator value:
      MOV A,#imm   or  CLR A
    Returns integer 0..255 or None.
    """
    ea = dptr_ea
    while True:
        ea = idc.next_head(ea, movx_ea)
        if ea == idc.BADADDR or ea >= movx_ea:
            break
        if mnem(ea) == "mov" and op(ea, 0) == "a" and idc.get_operand_type(ea, 1) == idc.o_imm:
            return int(idc.get_operand_value(ea, 1)) & 0xFF
        if mnem(ea) == "clr" and op(ea, 0) == "a":
            return 0
    return None

def gather_context(ea_center: int, fn_start: int, fn_end: int, before_n: int, after_n: int):
    """Collect a small disasm window around ea_center (instruction-wise)."""
    # walk backwards
    before = []
    ea = ea_center
    for _ in range(before_n):
        prev_ea = idc.prev_head(ea, fn_start)
        if prev_ea == idc.BADADDR or prev_ea < fn_start:
            break
        before.append(prev_ea)
        ea = prev_ea
    before.reverse()

    # walk forwards
    after = []
    ea = ea_center
    for _ in range(after_n):
        next_ea = idc.next_head(ea, fn_end)
        if next_ea == idc.BADADDR or next_ea >= fn_end:
            break
        after.append(next_ea)
        ea = next_ea

    def pack(lst):
        out = []
        for x in lst:
            if not is_code_ea(x):  # skip data/align
                continue
            out.append({"ea": f"0x{x:X}", "disasm": dis(x)})
        return out

    return pack(before), pack(after)

def scan_function_for_targets(fn, targets_set):
    """Find all MOV DPTR,#<target> ... MOVX uses inside a function."""
    rows = []
    ea = fn.start_ea
    while ea < fn.end_ea:
        t = parse_mov_dptr_imm(ea)
        if t is not None and t in targets_set:
            movx_ea, atype = find_movx_use_after(ea, fn.end_ea)
            if movx_ea:
                imm = None
                if atype == "write":
                    imm = find_imm_for_write(ea, movx_ea, fn.start_ea)
                ctx_before, ctx_after = gather_context(movx_ea, fn.start_ea, fn.end_ea,
                                                       CTX_BEFORE_INSNS, CTX_AFTER_INSNS)
                rows.append({
                    "ea": f"0x{movx_ea:X}",
                    "dptr_set_ea": f"0x{ea:X}",
                    "access_type": atype,
                    "value": (f"0x{imm:02X}" if imm is not None else None),
                    "function": idc.get_func_name(fn.start_ea) or f"sub_{fn.start_ea:X}",
                    "target": f"0x{t:04X}",
                    "context_before": ctx_before,
                    "context_after": ctx_after,
                })
                ea = movx_ea  # continue after the movx
        ea = idc.next_head(ea, fn.end_ea)
        if ea == idc.BADADDR:
            break
    return rows

def get_all_code_functions():
    """Yield function_t for all CODE segments."""
    qty = idaapi.get_segm_qty()
    for i in range(qty):
        s = idaapi.getnseg(i)
        if not s or s.type != ida_segment.SEG_CODE:
            continue
        ea = s.start_ea
        while ea < s.end_ea:
            f = ida_funcs.get_func(ea)
            if not f:
                ea = idc.next_head(ea, s.end_ea)
                if ea == idc.BADADDR:
                    break
                continue
            yield f
            ea = f.end_ea

def get_output_paths():
    user = os.path.join(idaapi.get_user_idadir(), 'memory_initialization_analysis.json')
    proj = os.path.join(get_db_dir(), 'memory_initialization_analysis.json')
    return user, proj

def analyze_memory_initialization():
    targets = set(MEMORY_LOCATIONS)
    results = {f"0x{t:04X}": {"stats": {}, "accesses": [], "functions": {}} for t in targets}

    print("=== Memory Initialization Tracker (8051/XDATA) ===")
    print("Targets:", ", ".join([f"0x{t:04X}" for t in targets]))

    all_rows = []
    for fn in get_all_code_functions():
        rows = scan_function_for_targets(fn, targets)
        all_rows.extend(rows)

    # Partition per target
    by_target = defaultdict(list)
    for r in all_rows:
        by_target[r["target"]].append(r)

    # Build results + stats
    for t in results.keys():
        acc = by_target.get(t, [])
        func_groups = defaultdict(list)
        for a in acc:
            func_groups[a["function"]].append(a)

        stats = {
            "total_accesses": len(acc),
            "writes": sum(1 for a in acc if a["access_type"] == "write"),
            "reads":  sum(1 for a in acc if a["access_type"] == "read"),
            "functions_accessing": len(func_groups),
        }

        results[t]["stats"] = stats
        results[t]["accesses"] = acc
        results[t]["functions"] = func_groups  # JSON will serialize dict of lists

    # Write outputs
    user_out, proj_out = get_output_paths()
    with open(user_out, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"[=] Saved: {user_out}")

    if proj_out != user_out:
        with open(proj_out, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print(f"[=] Copied: {proj_out}")

    # Console summary
    print("\n=== Summary ===")
    for t in results:
        st = results[t]["stats"]
        print(f"{t}: total={st['total_accesses']}  writes={st['writes']}  reads={st['reads']}  funcs={st['functions_accessing']}")

    return results

if __name__ == "__main__":
    analyze_memory_initialization()
