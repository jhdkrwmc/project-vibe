# ida_sonix_osd_probe.py (IDA 9.1 compatible)
# Scan 8051 firmware for MOVX @DPTR,A into 0x0B00–0x0BFF and related patterns.
# Run inside IDA: File -> Script...
#
# Outputs: prompts for basename and writes <basename>.csv and <basename>.md

import idaapi
import idc
import idautils
import ida_bytes
import ida_ua
import ida_funcs
import ida_kernwin
import ida_lines
import ida_ida

from collections import deque
import csv
import os
import re
import time

PROC_OK = ida_ida.inf_get_procname().lower().startswith('8051')
if not PROC_OK:
    ida_kernwin.warning(
        "Processor is '%s' (expected 8051). Script will still try, but results may be off."
        % ida_ida.inf_get_procname()
    )

HEX = lambda x: ("0x%X" % (x,))

# Helpers ------------------------------------------------------------

def disasm_line(ea):
    try:
        s = ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS) or ""
    except Exception:
        try:
            s = idc.GetDisasm(ea) or ""
        except Exception:
            s = ""
    return s

def get_mnem(ea):
    try:
        return idc.print_insn_mnem(ea).lower()
    except Exception:
        return ""

def op_text(ea, n):
    try:
        return idc.print_operand(ea, n).lower()
    except Exception:
        return ""

def op_type(ea, n):
    ins = ida_ua.insn_t()
    if ida_ua.decode_insn(ins, ea):
        return ins.ops[n].type
    return -1

def get_imm(ea, n):
    ins = ida_ua.insn_t()
    if ida_ua.decode_insn(ins, ea):
        op = ins.ops[n]
        if op.type == ida_ua.o_imm:
            return op.value & 0xFFFFFFFF
    return None

def is_movx_read(ea):
    return (get_mnem(ea) == 'movx' and op_text(ea,0) == 'a' and '@dptr' in op_text(ea,1))

def is_movx_write(ea):
    return (get_mnem(ea) == 'movx' and '@dptr' in op_text(ea,0) and op_text(ea,1) == 'a')

def is_mov_dptr_imm(ea):
    return (get_mnem(ea) == 'mov' and op_text(ea,0) == 'dptr' and op_type(ea,1) == ida_ua.o_imm)

def is_mov_dph_imm(ea):
    return (get_mnem(ea) == 'mov' and op_text(ea,0) == 'dph' and op_type(ea,1) == ida_ua.o_imm)

def is_mov_dpl_imm(ea):
    return (get_mnem(ea) == 'mov' and op_text(ea,0) == 'dpl' and op_type(ea,1) == ida_ua.o_imm)

def is_mov_a_imm(ea):
    return (get_mnem(ea) == 'mov' and op_text(ea,0) == 'a' and op_type(ea,1) == ida_ua.o_imm)

def is_mask_anl(ea):
    return (get_mnem(ea) == 'anl' and op_text(ea,0) == 'a' and op_type(ea,1) == ida_ua.o_imm)

def is_mask_orl(ea):
    return (get_mnem(ea) == 'orl' and op_text(ea,0) == 'a' and op_type(ea,1) == ida_ua.o_imm)

def is_cpl_acc_bit(ea):
    if get_mnem(ea) != 'cpl':
        return False
    t0 = op_text(ea,0)
    return t0.startswith('acc.') or t0.startswith('acc/')

def is_movc_table(ea):
    return (get_mnem(ea) == 'movc' and op_text(ea,0) == 'a' and '@a+dptr' in op_text(ea,1))

def has_imm_86_near(ctx_lines):
    blob = ("\n".join(ctx_lines)).lower()
    return ('#0x86' in blob) or (' 86h' in blob) or re.search(r'[#\s]86[\s,]', blob)

def read_imm(ea, n):
    v = get_imm(ea, n)
    return (v & 0xFF) if v is not None else None

class State:
    def __init__(self):
        self.dpl = None
        self.dph = None
        self.dptr = None
        self.a_imm = None
        self.last_movx_read = False
        self.masks = []  # list of (kind, value, ea)
        self.ctx = deque(maxlen=8)
    def update_dptr(self):
        if self.dpl is not None and self.dph is not None:
            self.dptr = ((self.dph & 0xFF) << 8) | (self.dpl & 0xFF)

def analyze():
    results = []
    dp_hits_specific = []
    movc_sites = []
    imm86_sites = []

    idaapi.auto_wait()

    st = State()
    start = ida_ida.inf_get_min_ea()
    end   = ida_ida.inf_get_max_ea()
    for ea in idautils.Heads(start, end):
        s = "%08X: %s" % (ea, disasm_line(ea))

        f = ida_funcs.get_func(ea)
        if f and f.start_ea == ea:
            st = State()

        st.ctx.append(s)

        if is_movc_table(ea):
            movc_sites.append((ea, list(st.ctx)))

        if is_mov_dptr_imm(ea):
            v = read_imm(ea, 1)
            if v is not None:
                st.dptr = v & 0xFFFF
                st.dpl = st.dptr & 0xFF
                st.dph = (st.dptr >> 8) & 0xFF
                if 0x0B70 <= st.dptr <= 0x0B7F:
                    dp_hits_specific.append((ea, st.dptr, list(st.ctx)))
        elif is_mov_dph_imm(ea):
            v = read_imm(ea, 1)
            if v is not None:
                st.dph = v & 0xFF
                st.update_dptr()
        elif is_mov_dpl_imm(ea):
            v = read_imm(ea, 1)
            if v is not None:
                st.dpl = v & 0xFF
                st.update_dptr()
        elif is_mov_a_imm(ea):
            st.a_imm = read_imm(ea, 1)
            st.last_movx_read = False
            st.masks.clear()
        elif is_movx_read(ea):
            st.last_movx_read = True
            st.a_imm = None
            st.masks.clear()
        elif is_mask_anl(ea):
            v = read_imm(ea, 1)
            if v is not None:
                st.masks.append(('ANL', v, ea))
        elif is_mask_orl(ea):
            v = read_imm(ea, 1)
            if v is not None:
                st.masks.append(('ORL', v, ea))
        elif is_cpl_acc_bit(ea):
            t0 = op_text(ea,0)
            m = re.search(r'acc\.(\d)', t0)
            bit = int(m.group(1)) if m else -1
            st.masks.append(('CPL', bit, ea))

        if is_movx_write(ea):
            tgt = st.dptr
            if tgt is not None and (0x0B00 <= tgt <= 0x0BFF):
                if st.a_imm is not None and not st.last_movx_read and not st.masks:
                    wtype = "IMM->WRITE"
                    src = st.a_imm
                elif st.a_imm is not None and st.masks:
                    wtype = "IMM->MASK->WRITE"
                    src = st.a_imm
                elif st.last_movx_read and st.masks:
                    wtype = "RMW->MASK->WRITE"
                    src = None
                elif st.last_movx_read and not st.masks:
                    wtype = "RMW->WRITE(no mask)"
                    src = None
                else:
                    wtype = "WRITE(unknown)"
                    src = None

                ctx_lines = list(st.ctx)
                results.append({
                    'ea': ea,
                    'dptr': tgt,
                    'range_hit': "0x0B70-0x0B7F" if 0x0B70 <= tgt <= 0x0B7F else "0x0B00-0x0BFF",
                    'type': wtype,
                    'a_imm': src,
                    'masks': list(st.masks),
                    'imm86_near': has_imm_86_near(ctx_lines),
                    'context': ctx_lines
                })
                st.last_movx_read = False
                st.masks.clear()

        if has_imm_86_near([s]):
            imm86_sites.append((ea, s))

    return results, dp_hits_specific, movc_sites, imm86_sites

def write_reports(results, dp_hits_specific, movc_sites, imm86_sites):
    base = ida_kernwin.ask_file(True, "osd_probe_report.md", "Save report as...")
    if not base:
        ida_kernwin.msg("Cancelled.\n")
        return
    root, ext = os.path.splitext(base)
    csv_path = root + ".csv"
    md_path  = root + ".md"

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ea","dptr","range_hit","type","a_imm","masks","imm86_near","context"])
        for r in results:
            masks_str = ";".join("%s:%s" % (k, (HEX(v) if k!='CPL' else "bit.%d"%v)) for k,v,_ea in r['masks'])
            w.writerow([HEX(r['ea']), HEX(r['dptr']), r['range_hit'], r['type'],
                        (HEX(r['a_imm']) if r['a_imm'] is not None else ""),
                        masks_str,
                        "yes" if r['imm86_near'] else "no",
                        " | ".join(r['context'][-4:])])

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Sonix 8051 OSD/Config Writer Probe (IDAPython)\n\n")
        f.write(f"- Generated: {time.ctime()}\n")
        f.write(f"- Processor: {ida_ida.inf_get_procname()}\n\n")

        f.write("## Summary\n")
        f.write(f"- MOVX writes into 0x0B00–0x0BFF: **{len(results)}**\n")
        f.write(f"- DPTR loads into 0x0B70–0x0B7F: **{len(dp_hits_specific)}**\n")
        f.write(f"- MOVC table users: **{len(movc_sites)}**\n")
        f.write(f"- #0x86 immediates seen (anywhere): **{len(imm86_sites)}**\n\n")

        def emit_ctx(ctx):
            f.write("```\n")
            for line in ctx[-8:]:
                f.write(line + "\n")
            f.write("```\n\n")

        f.write("## MOVX @DPTR, A into 0x0Bxx\n\n")
        for r in results:
            f.write(f"**EA {HEX(r['ea'])} | DPTR {HEX(r['dptr'])} ({r['range_hit']})**\n\n")
            f.write(f"- Type: {r['type']}\n")
            f.write(f"- A immediate: {(HEX(r['a_imm']) if r['a_imm'] is not None else '-')}\n")
            if r['masks']:
                ms = ", ".join("%s:%s@%s" % (k, (HEX(v) if k!='CPL' else "bit.%d"%v), HEX(ea)) for k,v,ea in r['masks'])
            else:
                ms = "-"
            f.write(f"- Masks: {ms}\n")
            f.write(f"- 0x86 near: {'yes' if r['imm86_near'] else 'no'}\n")
            f.write("- Context:\n")
            emit_ctx(r['context'])

        f.write("## DPTR loads into 0x0B70–0x0B7F\n\n")
        for ea, dptr, ctx in dp_hits_specific:
            f.write(f"**EA {HEX(ea)} | DPTR {HEX(dptr)}**\n\n")
            emit_ctx(ctx)

        f.write("## MOVC A,@A+DPTR (table users)\n\n")
        for ea, ctx in movc_sites:
            f.write(f"**EA {HEX(ea)}**\n\n")
            emit_ctx(ctx)

        f.write("## #0x86 immediates (anywhere)\n\n")
        for ea, line in imm86_sites[:500]:
            f.write(f"- {HEX(ea)}: {line}\n")

    ida_kernwin.info("Wrote:\n%s\n%s" % (csv_path, md_path))

def main():
    results, dp_hits_specific, movc_sites, imm86_sites = analyze()
    write_reports(results, dp_hits_specific, movc_sites, imm86_sites)

if __name__ == '__main__':
    main()


with open("/mnt/data/ida_sonix_osd_probe.py", "w", encoding="utf-8") as f:
    f.write(fixed_script)

print("Updated script written to /mnt/data/ida_sonix_osd_probe.py")
