
import idaapi, idc, idautils, os, shutil

EARLY_DPTR   = 0x0B77
EARLY_CONST  = 0x86      # restore this
EARLY_EA     = 0x0326    # from your report

LATE_TARGETS = {0x0B08, 0x0B09}
LATE_MIN_EA  = 0xAF00    # only patch after this EA (post-init)

OUT_BIN = idaapi.ask_file(True, "*.bin", "Save patched firmware as")
if not OUT_BIN:
    raise RuntimeError("No output path selected.")

diffs = []

def add_diff(ea, newb, note):
    off = idaapi.get_fileregion_offset(ea)
    if off == idaapi.BADADDR:
        return
    oldb = idc.get_wide_byte(ea)
    if oldb == newb:
        return
    idc.patch_byte(ea, newb)
    diffs.append((off, oldb, newb, ea, note))

def is_mov_dptr_imm(ea):
    return idc.print_insn_mnem(ea).lower()=="mov" and idc.print_operand(ea,0).lower()=="dptr" and idc.get_operand_type(ea,1)==idaapi.o_imm

def is_mov_a_imm(ea):
    return idc.print_insn_mnem(ea).lower()=="mov" and idc.print_operand(ea,0).lower() in ("a","acc") and idc.get_operand_type(ea,1)==idaapi.o_imm

def is_movx_dptr_a(ea):
    return idc.print_insn_mnem(ea).lower()=="movx" and idc.print_operand(ea,0).lower()=="@dptr" and idc.print_operand(ea,1).lower() in ("a","acc")

# 1) Restore early site (0326: mov dptr,#0x0B77 ; 0329: mov a,#imm)
ea = EARLY_EA
if is_mov_dptr_imm(ea) and idc.get_operand_value(ea,1)==EARLY_DPTR:
    ea2 = idc.next_head(ea)
    if is_mov_a_imm(ea2):
        # imm byte is at ea2+1 on 8051
        add_diff(ea2+1, EARLY_CONST, f"restore early A immediate at {ea2:04X} to {EARLY_CONST:#04x}")

# 2) Kill late MOVX @DPTR,A for B08/B09 after LATE_MIN_EA
for seg in idautils.Segments():
    ea = seg
    end = idc.get_segm_end(seg)
    while ea != idaapi.BADADDR and ea < end:
        if ea >= LATE_MIN_EA and is_mov_dptr_imm(ea):
            dptr = idc.get_operand_value(ea,1) & 0xFFFF
            if dptr in LATE_TARGETS:
                ea2 = idc.next_head(ea)
                ea3 = idc.next_head(ea2)
                if is_movx_dptr_a(ea3):
                    # Replace MOVX @DPTR,A with MOV A,A (NOP-like)
                    # Encoding: MOV A,A = 0xE5 0xE0
                    add_diff(ea3,   0xE5, f"NOP late MOVX @DPTR,A at {ea3:04X} (page 0x{dptr>>8:02X})")
                    add_diff(ea3+1, 0xE0, f"NOP late MOVX @DPTR,A at {ea3:04X}+1")
        ea = idc.next_head(ea)

# 3) Strict in-place export: copy original then write bytes at file offsets
orig = idaapi.get_input_file_path()
import io
def strict_export(src, dst, changes):
    shutil.copyfile(src, dst)
    with open(dst, "r+b") as f:
        for off, oldb, newb, ea, note in changes:
            f.seek(off)
            f.write(bytes([newb]))

strict_export(orig, OUT_BIN, diffs)

# 4) Write a diff log
log_path = os.path.splitext(OUT_BIN)[0] + "_diff.txt"
with open(log_path, "w", encoding="utf-8") as f:
    f.write("# Sonix OSD late-patch diff\n")
    for off, oldb, newb, ea, note in diffs:
        f.write(f"off=0x{off:X} ea=0x{ea:04X} {oldb:02X}->{newb:02X}   {note}\n")

print(f"[?] Wrote {len(diffs)} byte changes.")
print(f"[?] Patched BIN: {OUT_BIN}")
print(f"[?] Diff log   : {log_path}")
