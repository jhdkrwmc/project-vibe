# ida_sonix_osd_patcher_extended.py
# Finds and patches OSD enable write at DPTR=0x0B77 from A=#0x86 to A=#0x00
# Creates a diff log, patches IDA memory, and exports a new .bin

import idaapi
import idc
import idautils
import os

PATCH_DPTR = 0x0B77
OLD_CONST = 0x86
NEW_CONST = 0x00  # change if you want another value
CTX_LINES = 6

# Ask for output locations
OUTPUT_BIN = idaapi.ask_file(1, "*.bin", "Save patched firmware as")
OUTPUT_DIFF = os.path.splitext(OUTPUT_BIN)[0] + "_patch_diff.txt" if OUTPUT_BIN else None

patches = []

def is_mov_dptr_imm(ea, val):
    return idc.print_insn_mnem(ea).lower() == "mov" \
        and idc.print_operand(ea, 0).lower() == "dptr" \
        and idc.get_operand_value(ea, 1) == val

def is_mov_a_imm(ea, val):
    return idc.print_insn_mnem(ea).lower() == "mov" \
        and idc.print_operand(ea, 0).lower() == "a" \
        and idc.get_operand_value(ea, 1) == val

def is_movx_dptr_a(ea):
    return idc.print_insn_mnem(ea).lower() == "movx" \
        and idc.print_operand(ea, 0).lower() == "@dptr" \
        and idc.print_operand(ea, 1).lower() == "a"

print("[*] Scanning for OSD write sequence...")
for seg_ea in idautils.Segments():
    ea = seg_ea
    while ea != idaapi.BADADDR and ea < idc.get_segm_end(seg_ea):
        if is_mov_dptr_imm(ea, PATCH_DPTR):
            ea2 = idc.next_head(ea)
            if is_mov_a_imm(ea2, OLD_CONST):
                ea3 = idc.next_head(ea2)
                if is_movx_dptr_a(ea3):
                    func = idc.get_func_name(ea) or "<no_func>"
                    file_off = idaapi.get_fileregion_offset(ea2 + 1)
                    old_byte = idc.get_wide_byte(ea2 + 1)
                    ctx = []
                    ctx_ea = idc.prev_head(ea, CTX_LINES)
                    for _ in range(CTX_LINES * 2):
                        ctx.append(f"{ctx_ea:04X}: {idc.GetDisasm(ctx_ea)}")
                        ctx_ea = idc.next_head(ctx_ea)
                        if ctx_ea > ea3:
                            break
                    # Patch in IDA memory
                    idc.patch_byte(ea2 + 1, NEW_CONST)
                    patches.append({
                        "ea": ea,
                        "func": func,
                        "file_off": file_off,
                        "old_byte": old_byte,
                        "new_byte": NEW_CONST,
                        "context": ctx
                    })
        ea = idc.next_head(ea)

if not patches:
    print("[!] No matching OSD write sequences found.")
else:
    print(f"[+] Patched {len(patches)} occurrence(s) in IDA memory.")

    # Save diff log
    if OUTPUT_DIFF:
        with open(OUTPUT_DIFF, "w", encoding="utf-8") as f:
            f.write("# OSD Patch Diff Log\n\n")
            for p in patches:
                f.write(f"EA: 0x{p['ea']:04X} in {p['func']}\n")
                f.write(f"File offset: 0x{p['file_off']:X}\n")
                f.write(f"Old byte: 0x{p['old_byte']:02X} → New byte: 0x{p['new_byte']:02X}\n")
                f.write("Context:\n```\n")
                for line in p['context']:
                    f.write(line + "\n")
                f.write("```\n\n")
        print(f"[✓] Diff log saved to {OUTPUT_DIFF}")

        # Export all loaded segments contiguously
if OUTPUT_BIN:
    with open(OUTPUT_BIN, "wb") as f:
        for seg_ea in idautils.Segments():
            start = idc.get_segm_start(seg_ea)
            end   = idc.get_segm_end(seg_ea)
            f.write(idaapi.get_bytes(start, end - start))
    print(f"[✓] Patched firmware saved to {OUTPUT_BIN}")