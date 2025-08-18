
# IDA 9.1 / IDAPython 3.x
# Action 3 — Locate OSD autoload candidates and optionally patch them
#
# Usage:
#   ida -A -S"ida_3_locate_osd_patch.py --auto-top 1 --patch ret" firmware.bin
# Options:
#   --list-only         : only list candidates (default)
#   --auto-top N        : automatically patch the top-N candidates
#   --patch ret|nopcall : patch strategy
#
# What it does (why):
# 3.1 Scores functions by the number of MOVX @DPTR writes (bulk copies → OSD/font loaders).
# 3.2 Lists top candidates; annotates with comments & names.
# 3.3 Optionally patches: 'ret' → force early return; 'nopcall' → NOP out callers of that func.
#
import sys
import idaapi, ida_funcs, ida_ua, ida_bytes, ida_name, ida_xref, ida_search

def get_args():
    argv = sys.argv[1:]
    args = {"list_only": True, "auto_top": 0, "patch": "ret"}
    i = 0
    while i < len(argv):
        if argv[i] == "--list-only":
            args["list_only"] = True; i += 1
        elif argv[i] == "--auto-top":
            args["auto_top"] = int(argv[i+1], 0); args["list_only"] = False; i += 2
        elif argv[i] == "--patch":
            args["patch"] = argv[i+1]; i += 2
        else:
            i += 1
    return args

def info(m): print("[ida_3] " + m)

def count_movx_writes(func_ea):
    # Count number of decoded MOVX @DPTR,A (0xF0) and MOVX @R0,A (0xA2? not stable) within function
    f = ida_funcs.get_func(func_ea)
    if not f: return 0
    ea = f.start_ea
    cnt = 0
    while ea < f.end_ea:
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if size <= 0:
            ea += 1
            continue
        # Check opcode bytes directly (safer across mcs51 variants)
        b = ida_bytes.get_bytes(ea, size) or b""
        if b and b[-1] == 0xF0:  # MOVX @DPTR,A is often single byte 0xF0 as the final byte of insn
            cnt += 1
        ea += size
    return cnt

def list_candidates(limit=15):
    cands = []
    for f in ida_funcs.Functions():
        score = count_movx_writes(f)
        if score > 0:
            cands.append((score, f))
    cands.sort(key=lambda x: x[0], reverse=True)
    for i,(score, fea) in enumerate(cands[:limit], 1):
        ida_name.set_name(fea, f"osd_copy_cand_{i}", ida_name.SN_CHECK)
        ida_bytes.set_cmt(fea, f"OSD loader candidate; MOVX@DPTR writes={score}", 1)
        info(f"{i:02d}. 0x{fea:04X}  MOVX_writes={score}")
    return cands

def patch_ret(func_ea):
    # Overwrite first byte with 0x22 (RET)
    ida_bytes.patch_byte(func_ea, 0x22)
    ida_bytes.set_cmt(func_ea, "patched: early RET", 0)

def nop_out_callers(func_ea, max_callers=8):
    # Find callers (LCALL opcode 0x12 addr16) and NOP out the 3 bytes
    n = 0
    for x in ida_xref.get_xrefs_to(func_ea):
        ea = x.frm
        op = ida_bytes.get_byte(ea)
        if op == 0x12:
            ida_bytes.patch_byte(ea+0, 0x00)
            ida_bytes.patch_byte(ea+1, 0x00)
            ida_bytes.patch_byte(ea+2, 0x00)
            ida_bytes.set_cmt(ea, f"patched: NOP LCALL -> {hex(func_ea)}", 0)
            n += 1
            if n >= max_callers: break
    return n

def main():
    args = get_args()
    cands = list_candidates(limit=30)
    if args["list_only"] or args["auto_top"] <= 0:
        info("Listed candidates. Inspect & re-run with --auto-top N to patch.")
        return

    to_patch = cands[:args["auto_top"]]
    for score, fea in to_patch:
        if args["patch"] == "ret":
            patch_ret(fea)
            info(f"Patched func 0x{fea:04X} with early RET.")
        elif args["patch"] == "nopcall":
            n = nop_out_callers(fea)
            info(f"NOP'd {n} callers of 0x{fea:04X}.")
        else:
            info(f"Unknown patch mode: {args['patch']} (skipping)")

    idaapi.save_database(None, idaapi.DBFL_BAK)
    info("Patched. Save IDC/I64 and export a BIN if needed.")

if __name__ == "__main__":
    main()
