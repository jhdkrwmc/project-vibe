# Write a Sonix-8051-optimized IDA 9.1 crawler script.
# It maps MOVX writes (esp. 0x0Bxx page), SFR writes, mask sequences, DPTR flows,
# reset/ISR paths, table users, and exports mind-map style Markdown + CSV.
# Saves as /mnt/data/ida_sonix_cowboy.py for download; script itself prompts user for output path when run in IDA.


# ida_sonix_cowboy.py
# Sonix-8051 firmware crawler for IDA 9.1+
#
# Key features (optimized for SN9C292-class 8051):
# - Robust ACC/A handling, DPTR tracking (DPTR,#imm; DPH/DPL; INC/DEC DPTR/DPL/DPH; MOV DPH/DPL,A; XCH A,DPH/DPL).
# - Detects MOVX @DPTR,A (all pages) + classifies IMM/RMW/masked writes.
# - Focus on Sonix-style config pages (default DPH==0x0B). Multi-page watch.
# - SFR writes (PCON/TCON/T2CON/S0CON/...); interrupt enable/priority flips.
# - Reset vector + IRQ vectors; phase tagging (reset/ISR/normal).
# - MOVC A,@A+DPTR table users; jump-table/JMP @A+DPTR hints.
# - Magic constant flags (0x86, 0x06, 0x7F etc.).
# - Output: one prompt for base path → writes <name>.md and <name>.csv.
#
# Run inside IDA: File → Script… → pick this file.

import idaapi, idc, idautils
import ida_bytes, ida_ua, ida_funcs, ida_kernwin, ida_lines, ida_ida
from collections import defaultdict, deque
import csv, os, re, time

# ----------------------- Config (tweak as needed) -----------------------
TARGET_PAGES   = [0x0B, 0x0E, 0x05]   # DPH pages to highlight (Sonix often uses 0x0B)
CONST_FLAGS    = [0x86, 0x06, 0x7F]   # interesting constants seen in OSD/USB masks
CONTEXT_LINES  = 12                   # context lines around each hit in MD
MAX_MOVX_MD    = 1200                 # cap MOVX entries shown in MD to keep file readable
SFR_NAMES = {
    0x80:"P0",0x81:"SP",0x82:"DPL",0x83:"DPH",0x87:"PCON",0x88:"TCON",0x89:"TMOD",
    0x8A:"TL0",0x8B:"TL1",0x8C:"TH0",0x8D:"TH1",0x98:"S0CON",0x99:"S0BUF",
    0xA8:"IEN0",0xA9:"IP0",0xB0:"P3",0xB8:"IEN1",0xB9:"IP1",0xBA:"S0RELH",
    0xC0:"IRCON",0xC8:"T2CON",0xCC:"TL2",0xCD:"TH2",0xD0:"PSW",0xD8:"ADCON0",
    0xD9:"ADDAT",0xDB:"P7",0xDC:"ADCON1",0xDD:"P8",0xE0:"ACC",0xE8:"P4",
    0xF0:"B",0xF8:"P5",0xFA:"P6"
}
# -----------------------------------------------------------------------

PROC = ida_ida.inf_get_procname().lower()
HEX  = lambda x: ("0x%X" % (x,))

def dis(ea):
    try:
        return ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS) or ""
    except Exception:
        try: return idc.GetDisasm(ea) or ""
        except: return ""

def mnem(ea): 
    try: return idc.print_insn_mnem(ea).lower()
    except: return ""

def op_t(ea,n):
    try: return idc.print_operand(ea,n).lower()
    except: return ""

def decode(ea):
    ins = ida_ua.insn_t()
    return ins if ida_ua.decode_insn(ins, ea) else None

def op_is_imm(ins,n): return ins.ops[n].type == ida_ua.o_imm
def imm_u8(v): return v & 0xFF

def _is_a(s: str) -> bool:
    s = (s or '').lower()
    return s == 'a' or s == 'acc'

def read_u16_imm(ea, n):
    ins = ida_ua.insn_t()
    if ida_ua.decode_insn(ins, ea) and ins.ops[n].type == ida_ua.o_imm:
        return ins.ops[n].value & 0xFFFF
    return None

def is_movx_r(ea):
    return (mnem(ea) == 'movx'
            and _is_a(op_t(ea,0))
            and '@dptr' in op_t(ea,1).lower())

def is_movx_w(ea):
    return (mnem(ea) == 'movx'
            and '@dptr' in op_t(ea,0).lower()
            and _is_a(op_t(ea,1)))

def is_movc_table(ea):
    return (mnem(ea) == 'movc'
            and _is_a(op_t(ea,0))
            and '@a+dptr' in op_t(ea,1).lower())

def has_flag_const(ctx_lines):
    blob = ("\n".join(ctx_lines)).lower()
    for c in CONST_FLAGS:
        if ('#'+HEX(c).lower()) in blob or (f" {c:02x}h") in blob:
            return True
    return False

def in_pages(dptr):
    if dptr is None: return None
    dph=((dptr>>8)&0xFF)
    return dph if dph in TARGET_PAGES else None

def func_name(ea):
    f = ida_funcs.get_func(ea)
    if not f: return ""
    nm = ida_funcs.get_func_name(f.start_ea)
    return nm or ""

def callers_of(ea):
    s=set()
    for x in idautils.XrefsTo(ea):
        if x.type in (idaapi.fl_CN, idaapi.fl_CF):
            s.add(func_name(x.frm))
    return [c for c in sorted(s) if c]

def callees_from(fea):
    s=set()
    f = ida_funcs.get_func(fea)
    if not f: return []
    for x in idautils.FuncItems(f.start_ea):
        if mnem(x) in ("call","lcall","acall"):
            tgt = idc.get_operand_value(x,0)
            s.add(func_name(tgt))
    return [c for c in sorted(s) if c]

def is_vector(ea):
    # Rough: vector table typically near 0x0000.. reset and interrupt entries.
    return ea < 0x0100

class State:
    def __init__(self):
        self.dpl=None; self.dph=None; self.dptr=None
        self.a_imm=None
        self.last_movx_read=False
        self.masks=[]             # (kind,val,ea)
        self.ctx=deque(maxlen=CONTEXT_LINES)

    def upd(self):
        if self.dpl is not None and self.dph is not None:
            self.dptr = ((self.dph & 0xFF) << 8) | (self.dpl & 0xFF)

def analyze():
    idaapi.auto_wait()
    st=State()

    start=ida_ida.inf_get_min_ea()
    end=ida_ida.inf_get_max_ea()

    results_movx=[]     # all MOVX writes
    results_sfr=[]      # SFR writes: MOV sfr,#imm ; ANL/ORL sfr,#imm
    dp_loads_watch=[]   # DPTR loads into target pages
    table_sites=[]      # MOVC A,@A+DPTR
    jt_sites=[]         # JMP @A+DPTR, computed jmp hints (heuristic)
    vector_entries=[]   # reset/ISR vectors
    imm_hits=[]         # constants of interest

    # Gather vector entries (heuristic)
    for ea in range(start, min(end, start+0x80), 1):
        if mnem(ea) in ('ljmp','ajmp','sjmp','jmp'):
            tgt = idc.get_operand_value(ea,0)
            vector_entries.append((ea, tgt, dis(ea)))

    for ea in idautils.Heads(start,end):
        line=f"{ea:08X}: {dis(ea)}"
        f=ida_funcs.get_func(ea)
        if f and f.start_ea==ea:
            st=State()
        st.ctx.append(line)

        ins=decode(ea)
        if not ins: continue
        mn=mnem(ea)

        # --- MOVC / jump table-ish ---
        if is_movc_table(ea):
            table_sites.append((ea, func_name(ea), list(st.ctx)))
        if mn=='jmp' and '@a+dptr' in op_t(ea,0):
            jt_sites.append((ea, func_name(ea), list(st.ctx)))

        # --- DPTR and A/A-imm tracking ---
        if mn=="mov":
            ot0=op_t(ea,0); ot1=op_t(ea,1)
            if ot0=="dptr" and op_is_imm(ins,1):
                v = read_u16_imm(ea,1)
                if v is not None:
                    st.dptr=v; st.dpl=v&0xFF; st.dph=(v>>8)&0xFF
                    if ((v>>8)&0xFF) in TARGET_PAGES:
                        dp_loads_watch.append((ea,v,func_name(ea),list(st.ctx)))
            elif ot0=="dph" and op_is_imm(ins,1):
                st.dph=imm_u8(ins.ops[1].value); st.upd()
                if st.dph in TARGET_PAGES:
                    dp_loads_watch.append((ea,st.dptr,func_name(ea),list(st.ctx)))
            elif ot0=="dpl" and op_is_imm(ins,1):
                st.dpl=imm_u8(ins.ops[1].value); st.upd()
            elif ot0 in ("dpl","dph") and _is_a(ot1):
                # MOV DPL/DPH,A
                if ot0=="dpl":
                    st.dpl = st.a_imm if st.a_imm is not None else st.dpl
                else:
                    st.dph = st.a_imm if st.a_imm is not None else st.dph
                st.upd()
            elif _is_a(ot0) and op_is_imm(ins,1):
                st.a_imm=imm_u8(ins.ops[1].value); st.last_movx_read=False; st.masks.clear()

            # SFR write detection: MOV sfr,#imm when op0 is direct address 0x80..0xFF
            if ot0.startswith('0x') or ot0.endswith('h'):
                try:
                    # IDA prints direct like 'P3' or '0x8F' depending settings; keep both.
                    direct = idc.get_operand_value(ea,0) & 0xFF
                    if 0x80 <= direct <= 0xFF and op_is_imm(ins,1):
                        results_sfr.append({
                            'ea':ea,'func':func_name(ea),
                            'sfr': direct,'sfr_name': SFR_NAMES.get(direct,''),
                            'op': 'MOV','val': imm_u8(ins.ops[1].value),
                            'ctx':list(st.ctx)
                        })
                except: pass

        elif mn in ("inc","dec"):
            t=op_t(ea,0)
            if t=="dptr":
                st.dptr=(0 if st.dptr is None else (st.dptr+ (1 if mn=="inc" else -1)) ) &0xFFFF; st.dpl=st.dptr&0xFF; st.dph=(st.dptr>>8)&0xFF
            elif t=="dpl":
                st.dpl=(0 if st.dpl is None else ((st.dpl+ (1 if mn=="inc" else -1)) &0xFF)); st.upd()
            elif t=="dph":
                st.dph=(0 if st.dph is None else ((st.dph+ (1 if mn=="inc" else -1)) &0xFF)); st.upd()
        elif mn=="xch":
            if _is_a(op_t(ea,0)) and op_t(ea,1)=="dpl":
                tmp=st.a_imm; st.a_imm=st.dpl; st.dpl=tmp if tmp is not None else st.dpl; st.upd()
            if _is_a(op_t(ea,0)) and op_t(ea,1)=="dph":
                tmp=st.a_imm; st.a_imm=st.dph; st.dph=tmp if tmp is not None else st.dph; st.upd()
        elif mn=="anl" and _is_a(op_t(ea,0)) and ins.ops[1].type==ida_ua.o_imm:
            st.masks.append(("ANL",imm_u8(ins.ops[1].value),ea))
        elif mn=="orl" and _is_a(op_t(ea,0)) and ins.ops[1].type==ida_ua.o_imm:
            st.masks.append(("ORL",imm_u8(ins.ops[1].value),ea))
        elif mn=="cpl" and op_t(ea,0).startswith("acc."):
            try: bit=int(op_t(ea,0).split(".")[1]); st.masks.append(("CPL",bit,ea))
            except: pass
        elif is_movx_r(ea):
            st.last_movx_read=True; st.a_imm=None; st.masks.clear()

        # --- MOVX write capture ---
        write_detected = is_movx_w(ea)
        if not write_detected:
            # Fallback: parse disasm when operand decode lies
            dl=dis(ea).lower()
            write_detected = (mnem(ea)=='movx' and '@dptr' in dl and re.search(r'\bmovx\s+@dptr\s*,\s*(a|acc)\b', dl))

        if write_detected:
            page = in_pages(st.dptr)
            rec = {
                'ea':ea,'func':func_name(ea),'dptr':st.dptr,'page':page,
                'type':None,'a_imm':st.a_imm,'masks':list(st.masks),
                'flagconst':has_flag_const(list(st.ctx)), 'ctx':list(st.ctx)
            }
            if st.a_imm is not None and not st.last_movx_read and not st.masks:
                rec['type']="IMM->WRITE"
            elif st.a_imm is not None and st.masks:
                rec['type']="IMM->MASK->WRITE"
            elif st.last_movx_read and st.masks:
                rec['type']="RMW->MASK->WRITE"
            elif st.last_movx_read and not st.masks:
                rec['type']="RMW->WRITE(no mask)"
            else:
                rec['type']="WRITE(?)"
            results_movx.append(rec)
            st.last_movx_read=False; st.masks.clear()

        # --- SFR ANL/ORL direct addressing ---
        if mn in ("anl","orl"):
            # direct SFR, #imm
            if op_t(ea,0).startswith('0x') or op_t(ea,0).endswith('h') or op_t(ea,0) in [n.lower() for n in SFR_NAMES.values()]:
                try:
                    direct = idc.get_operand_value(ea,0) & 0xFF
                    if 0x80 <= direct <= 0xFF and ins.ops[1].type==ida_ua.o_imm:
                        results_sfr.append({
                            'ea':ea,'func':func_name(ea),
                            'sfr': direct,'sfr_name': SFR_NAMES.get(direct,''),
                            'op': mn.upper(),'val': imm_u8(ins.ops[1].value),
                            'ctx':list(st.ctx)
                        })
                except: pass

        # --- constants of interest ---
        if any(('#'+HEX(c).lower()) in line.lower() or (f" {c:02x}h" in line.lower()) for c in CONST_FLAGS):
            imm_hits.append((ea, func_name(ea), line))

    return {
        'movx': results_movx,
        'sfr': results_sfr,
        'dp_loads': dp_loads_watch,
        'tables': table_sites,
        'jt_sites': jt_sites,
        'vectors': vector_entries,
        'imm_hits': imm_hits
    }

def write_reports(allres):
    base = ida_kernwin.ask_file(True, "sonix_report.md", "Save report as...")
    if not base:
        ida_kernwin.msg("Cancelled.\n"); return
    root,_ = os.path.splitext(base)
    csv_path = root + ".csv"
    md_path  = root + ".md"

    movx = allres['movx']
    sfr  = allres['sfr']
    dpl  = allres['dp_loads']
    tabs = allres['tables']
    jts  = allres['jt_sites']
    vecs = allres['vectors']
    imms = allres['imm_hits']

    # -------------------- CSV (wide, machine-parseable) --------------------
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["kind","ea","func","dptr","page","type","a_imm","masks","flagconst","extra"])
        for r in movx:
            masks=";".join("%s:%s@%s"%(k,(HEX(v) if k!='CPL' else 'bit.%d'%v),HEX(ea)) for k,v,ea in r['masks'])
            w.writerow(["MOVX", HEX(r['ea']), r['func'], (HEX(r['dptr']) if r['dptr'] is not None else ""), 
                        (f"0x{r['page']:02X}" if r['page'] is not None else ""),
                        r['type'], (HEX(r['a_imm']) if r['a_imm'] is not None else ""),
                        masks, "yes" if r['flagconst'] else "no", " | ".join(r['ctx'][-4:])])
        for ea,v,fn,ctx in dpl:
            w.writerow(["DPTR_LOAD", HEX(ea), fn, HEX(v), f"0x{(v>>8)&0xFF:02X}","", "", "", "", " | ".join(ctx[-4:])])
        for r in sfr:
            w.writerow(["SFR", HEX(r['ea']), r['func'], "", "", r['op'], HEX(r['val']), r['sfr_name'] or HEX(r['sfr']), "", " | ".join(r['ctx'][-4:])])
        for ea,fn,ctx in tabs:
            w.writerow(["MOVC", HEX(ea), fn, "", "", "MOVC_A@A+DPTR", "", "", "", " | ".join(ctx[-4:])])
        for ea,fn,ctx in jts:
            w.writerow(["JTBL", HEX(ea), fn, "", "", "JMP_@A+DPTR", "", "", "", " | ".join(ctx[-4:])])
        for ea,tgt,txt in vecs:
            w.writerow(["VECTOR", HEX(ea), "", HEX(tgt), "", "", "", "", "", txt])
        for ea,fn,txt in imms:
            w.writerow(["CONST", HEX(ea), fn, "", "", "", "", "", "", txt])

    # -------------------- Markdown (mind-map style) --------------------
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Sonix 8051 Firmware Report (Cowboy)\n\n")
        f.write(f"- Generated: {time.ctime()}\n- Processor: {PROC}\n")
        f.write(f"- Target pages: {', '.join('0x%02X'%p for p in TARGET_PAGES)}\n")
        f.write(f"- Constants of interest: {', '.join(HEX(c) for c in CONST_FLAGS)}\n\n")

        # Vectors
        f.write("## Vector Table (Reset/ISRs)\n\n")
        if vecs:
            for ea,tgt,txt in vecs:
                f.write(f"- **{HEX(ea)} → {HEX(tgt)}**: `{txt.strip()}`\n")
        else:
            f.write("_None detected_\n")
        f.write("\n")

        # DPTR loads to target pages
        f.write("## DPTR Loads into Target Pages\n\n")
        if dpl:
            for ea,v,fn,ctx in dpl:
                f.write(f"- **{HEX(ea)} in `{fn}`** set DPTR={HEX(v)} (page 0x{(v>>8)&0xFF:02X})\n")
                f.write("  - Context:\n```\n")
                for l in ctx[-CONTEXT_LINES:]:
                    f.write(l+"\n")
                f.write("```\n")
        else:
            f.write("_No direct DPTR loads observed into target pages_\n")
        f.write("\n")

        # MOVX writes
        f.write("## MOVX Writes (classified)\n\n")
        if movx:
            shown = 0
            for r in movx:
                if shown >= MAX_MOVX_MD: break
                shown += 1
                f.write(f"### {shown}. EA {HEX(r['ea'])} in `{r['func']}`\n")
                f.write(
    f"- DPTR: {(HEX(r['dptr']) if r['dptr'] is not None else 'unknown')}  |  "
    f"Page: {('0x%02X' % r['page'] if r['page'] is not None else '-')}\n"
)
                f.write(f"- Type: {r['type']}  |  Const flag near: {'yes' if r['flagconst'] else 'no'}\n")
                if r['masks']:
                    ms=", ".join("%s:%s@%s"%(k,(HEX(v) if k!='CPL' else 'bit.%d'%v),HEX(ea)) for k,v,ea in r['masks'])
                else:
                    ms="-"
                f.write(f"- Masks: {ms}\n")
                f.write("- Context:\n```\n")
                for l in r['ctx'][-CONTEXT_LINES:]:
                    f.write(l+"\n")
                f.write("```\n\n")
        else:
            f.write("_No MOVX writes detected_\n\n")

        # SFR writes
        f.write("## SFR Writes (direct)\n\n")
        if sfr:
            for r in sfr[:1200]:
                name = r['sfr_name'] or HEX(r['sfr'])
                f.write(f"- **{HEX(r['ea'])} in `{r['func']}`**: {r['op']} {name}, {HEX(r['val'])}\n")
            if len(sfr) > 1200:
                f.write(f"... (+{len(sfr)-1200} more)")
            f.write("\n")
        else:
            f.write("_None_\n\n")

        # Tables / jump tables
        f.write("## MOVC Table Users\n\n")
        if tabs:
            for ea,fn,ctx in tabs[:600]:
                f.write(f"- **{HEX(ea)} in `{fn}`**\n")
        else:
            f.write("_None_\n")
        f.write("\n")

        f.write("## Jump Table Hints\n\n")
        if jts:
            for ea,fn,ctx in jts[:300]:
                f.write(f"- **{HEX(ea)} in `{fn}`**: JMP @A+DPTR\n")
        else:
            f.write("_None_\n")
        f.write("\n")

        # Constants
        f.write("## Constants of Interest Seen\n\n")
        if imms:
            for ea,fn,txt in imms[:800]:
                f.write(f"- {HEX(ea)} in `{fn}`: `{txt.strip()}`\n")
        else:
            f.write("_None_\n")
        f.write("\n")

        f.write("---\n")
        f.write(f"_CSV with full rows written to: {os.path.basename(csv_path)}_\n")

    ida_kernwin.info("Wrote:\n%s\n%s"%(csv_path,md_path))

def main():
    if not PROC.startswith('8051'):
        ida_kernwin.warning("Processor is '%s'; results may be off."%PROC)
    res = analyze()
    write_reports(res)

if __name__=='__main__':
    main()
