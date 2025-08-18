# ida_sonix_osd_hunter.py
# Scans 8051 firmware in IDA for MOVX @DPTR,A to 0x0Bxx range
# and reports candidate OSD control writes.

import idaapi
import idautils
import idc

TARGET_PAGE = 0x0B  # OSD/overlay control page
CTX_LINES = 6       # context disasm lines before/after
REPORT_FILE = idaapi.ask_file(1, "*.md", "Save OSD hunter report as")

def is_mov_dptr_imm(insn):
    """Check if instruction is 'mov dptr,#imm16'."""
    return insn.get_canon_mnem() == "mov" and insn.Op1.type == idaapi.o_reg and insn.Op1.reg == idaapi.DPTR and insn.Op2.type == idaapi.o_imm

def is_mov_a_imm(insn):
    """Check if instruction is 'mov a,#imm'."""
    return insn.get_canon_mnem() == "mov" and insn.Op1.type == idaapi.o_reg and insn.Op1.reg == idaapi.A and insn.Op2.type == idaapi.o_imm

def is_movx_dptr_a(insn):
    """Check if instruction is 'movx @dptr,a'."""
    return insn.get_canon_mnem() == "movx" and insn.Op1.type == idaapi.o_phrase and insn.Op1.reg == idaapi.DPTR and insn.Op2.type == idaapi.o_reg and insn.Op2.reg == idaapi.A

results = []

for seg_ea in idautils.Segments():
    ea = seg_ea
    end_ea = idc.get_segm_end(seg_ea)
    while ea != idaapi.BADADDR and ea < end_ea:
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, ea):
            # Look for MOV DPTR,#0x0B..
            if is_mov_dptr_imm(insn):
                dptr_val = insn.Op2.value
                if (dptr_val >> 8) == TARGET_PAGE:
                    # Peek ahead: MOV A,#imm then MOVX @DPTR,A
                    ea2 = idc.next_head(ea)
                    insn2 = idaapi.insn_t()
                    if idaapi.decode_insn(insn2, ea2) and is_mov_a_imm(insn2):
                        ea3 = idc.next_head(ea2)
                        insn3 = idaapi.insn_t()
                        if idaapi.decode_insn(insn3, ea3) and is_movx_dptr_a(insn3):
                            func = idc.get_func_name(ea)
                            const_val = insn2.Op2.value
                            # Grab context
                            ctx_start = idc.prev_head(ea, CTX_LINES)
                            ctx_end = ea3
                            context_lines = []
                            ctx_ea = ctx_start
                            for _ in range(CTX_LINES*2):
                                context_lines.append(f"{ctx_ea:04X}: {idc.GetDisasm(ctx_ea)}")
                                ctx_ea = idc.next_head(ctx_ea)
                                if ctx_ea > ctx_end:
                                    break
                            results.append({
                                "ea": ea,
                                "func": func,
                                "dptr": dptr_val,
                                "val": const_val,
                                "context": context_lines
                            })
        ea = idc.next_head(ea)

# Write report
if REPORT_FILE:
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(f"# OSD Hunter Report for DPTR page 0x{TARGET_PAGE:02X}\n\n")
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
