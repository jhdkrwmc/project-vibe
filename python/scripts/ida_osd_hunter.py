# ida_sonix_osd_hunter_fixed.py
# Hunts for MOV DPTR,#0x0B?? -> MOV A,#imm -> MOVX @DPTR,A sequences

import idaapi
import idautils
import idc

TARGET_PAGE = 0x0B  # Page 0x0Bxx suspected for OSD
CTX_LINES = 6

REPORT_FILE = idaapi.ask_file(1, "*.md", "Save OSD hunter report as")
results = []

def is_mov_dptr_imm(ea):
    return idc.print_insn_mnem(ea).lower() == "mov" \
        and idc.print_operand(ea, 0).lower() == "dptr" \
        and idc.get_operand_type(ea, 1) == idaapi.o_imm

def is_mov_a_imm(ea):
    return idc.print_insn_mnem(ea).lower() == "mov" \
        and idc.print_operand(ea, 0).lower() == "a" \
        and idc.get_operand_type(ea, 1) == idaapi.o_imm

def is_movx_dptr_a(ea):
    return idc.print_insn_mnem(ea).lower() == "movx" \
        and idc.print_operand(ea, 0).lower() == "@dptr" \
        and idc.print_operand(ea, 1).lower() == "a"

for seg_ea in idautils.Segments():
    ea = seg_ea
    while ea != idaapi.BADADDR and ea < idc.get_segm_end(seg_ea):
        if is_mov_dptr_imm(ea):
            dptr_val = idc.get_operand_value(ea, 1)
            if (dptr_val >> 8) == TARGET_PAGE:
                ea2 = idc.next_head(ea)
                if is_mov_a_imm(ea2):
                    const_val = idc.get_operand_value(ea2, 1)
                    ea3 = idc.next_head(ea2)
                    if is_movx_dptr_a(ea3):
                        func = idc.get_func_name(ea) or "<no_func>"
                        # grab context
                        ctx_start = ea
                        ctx_lines = []
                        ctx_ea = idc.prev_head(ea, CTX_LINES)
                        for _ in range(CTX_LINES * 2):
                            ctx_lines.append(f"{ctx_ea:04X}: {idc.GetDisasm(ctx_ea)}")
                            ctx_ea = idc.next_head(ctx_ea)
                            if ctx_ea > ea3:
                                break
                        results.append({
                            "ea": ea,
                            "func": func,
                            "dptr": dptr_val,
                            "val": const_val,
                            "context": ctx_lines
                        })
        ea = idc.next_head(ea)

if REPORT_FILE:
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(f"# OSD Hunter Report (DPTR page 0x{TARGET_PAGE:02X})\n\n")
        for idx, r in enumerate(results, 1):
            f.write(f"## {idx}. EA {r['ea']:04X} in `{r['func']}`\n")
            f.write(f"- DPTR: 0x{r['dptr']:04X}\n")
            f.write(f"- Const written: 0x{r['val']:02X}\n")
            f.write("- Context:\n```\n")
            for line in r['context']:
                f.write(line + "\n")
            f.write("```\n\n")
    print(f"[+] Found {len(results)} OSD candidate writes. Report saved to {REPORT_FILE}")
else:
    print("[!] No report file chosen.")