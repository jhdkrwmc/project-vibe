# Emit a hardened IDA 9.1 script (v2) with:
# - No writes to /mnt/data
# - Prompts only for output path (writes .md/.csv next to chosen name)
# - Logs *all* MOVX writes (even when DPTR unknown)
# - Tracks DPTR via MOV DPTR,#imm, split DPH/DPL, and simple arithmetic: INC/DEC DPTR/DPL/DPH, ADD A,#imm then MOV DPL/A->DPH, XCH A,DPL/DPH
# - Dumps separate sections:
#     1) MOVX @DPTR,A to 0x0B00–0x0BFF (strict)
#     2) All MOVX @DPTR,A (anywhere) with current DPTR guess + context
#     3) DPTR loads where DPH==0x0B (any DPL)
#     4) Any immediates 0x0B70–0x0B7F, 0x86, plus MOVC A,@A+DPTR sites
# - Adds a small config block at top to adjust target high byte (default 0x0B)
# ida_sonix_osd_probe_v2.py (IDA 9.1)
# Sonix/8051 MOVX writer mapper with broadened DPTR tracking.
# Run inside IDA. Writes .md and .csv after prompting for a base filename.

import idaapi, idc, idautils
import ida_bytes, ida_ua, ida_funcs, ida_kernwin, ida_lines, ida_ida

from collections import deque
import csv, os, re, time

# --- Config ---
TARGET_DPH   = 0x0B   # high byte for the suspected OSD/config page
WINDOW_LOW   = 0x00   # DPL low bound (inclusive)
WINDOW_HIGH  = 0xFF   # DPL high bound (inclusive)

HEX = lambda x: ("0x%X" % (x,))
PROC = ida_ida.inf_get_procname().lower()

# --- Helpers ---
def dis(ea):
    try:
        return ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS) or ""
    except Exception:
        try:
            return idc.GetDisasm(ea) or ""
        except Exception:
            return ""

def mnem(ea): 
    try: return idc.print_insn_mnem(ea).lower()
    except: return ""

def op_t(ea,n):
    try: return idc.print_operand(ea,n).lower()
    except: return ""

def decode(ea):
    ins = ida_ua.insn_t()
    return ins if ida_ua.decode_insn(ins, ea) else None

def op_is_imm(ins,n):
    return ins.ops[n].type == ida_ua.o_imm

def imm_u8(v): return v & 0xFF

def has_imm86(ctx):
    blob = ("\n".join(ctx)).lower()
    return ('#0x86' in blob) or (' 86h' in blob) or re.search(r'[#\s]86[\s,]', blob)

def in_target_range(dptr):
    if dptr is None: return False
    return ((dptr>>8)&0xFF)==TARGET_DPH and WINDOW_LOW <= (dptr&0xFF) <= WINDOW_HIGH

def is_movx_r(ea): return (mnem(ea)=="movx" and op_t(ea,0)=="a" and "@dptr" in op_t(ea,1))
def is_movx_w(ea): return (mnem(ea)=="movx" and "@dptr" in op_t(ea,0) and op_t(ea,1)=="a")
def is_movc(ea):   return (mnem(ea)=="movc" and op_t(ea,0)=="a" and "@a+dptr" in op_t(ea,1))

# --- State ---
class State:
    def __init__(self):
        self.dpl=None; self.dph=None; self.dptr=None
        self.a_imm=None
        self.last_movx_read=False
        self.masks=[]             # (kind,val,ea)
        self.ctx=deque(maxlen=10)
    def upd(self):
        if self.dpl is not None and self.dph is not None:
            self.dptr=((self.dph&0xFF)<<8)|(self.dpl&0xFF)

# --- Analysis ---
def analyze():
    idaapi.auto_wait()
    st=State()
    results_target=[]   # MOVX writes into target range
    results_all=[]      # All MOVX writes
    dp_loads_0B=[]      # DPTR loads with DPH==TARGET_DPH
    table_sites=[]      # MOVC A,@A+DPTR
    imm_hits=[]         # 0x0B70..0x0B7F and 0x86 immediates seen anywhere (by text)

    start=ida_ida.inf_get_min_ea()
    end=ida_ida.inf_get_max_ea()

    for ea in idautils.Heads(start,end):
        line=f"{ea:08X}: {dis(ea)}"
        f=ida_funcs.get_func(ea)
        if f and f.start_ea==ea: st=State()
        st.ctx.append(line)

        ins=decode(ea)
        if not ins: continue
        mn=mnem(ea)

        # MOVC table
        if is_movc(ea): table_sites.append((ea,list(st.ctx)))

        # DPTR writes / builds
        if mn=="mov":
            ot0=op_t(ea,0); ot1=op_t(ea,1)
            if ot0=="dptr" and op_is_imm(ins,1):
                v=imm_u8(ins.ops[1].value)|((imm_u8(ins.ops[1].value>>8))<<8) # IDA packs full imm
                st.dptr=v&0xFFFF; st.dpl=st.dptr&0xFF; st.dph=(st.dptr>>8)&0xFF
                if st.dph==TARGET_DPH: dp_loads_0B.append((ea,st.dptr,list(st.ctx)))
            elif ot0=="dph" and op_is_imm(ins,1):
                st.dph=imm_u8(ins.ops[1].value); st.upd()
                if st.dph==TARGET_DPH: dp_loads_0B.append((ea,st.dptr,list(st.ctx)))
            elif ot0=="dpl" and op_is_imm(ins,1):
                st.dpl=imm_u8(ins.ops[1].value); st.upd()
            elif ot0=="dpl" and ot1=="a":
                st.dpl = st.a_imm if st.a_imm is not None else st.dpl; st.upd()
            elif ot0=="dph" and ot1=="a":
                st.dph = st.a_imm if st.a_imm is not None else st.dph; st.upd()
            elif ot0=="a" and op_is_imm(ins,1):
                st.a_imm=imm_u8(ins.ops[1].value); st.last_movx_read=False; st.masks.clear()
        elif mn in ("inc","dec"):
            t=op_t(ea,0)
            if t=="dptr":  st.dptr=(0 if st.dptr is None else (st.dptr+ (1 if mn=="inc" else -1)) ) &0xFFFF; st.dpl=st.dptr&0xFF; st.dph=(st.dptr>>8)&0xFF
            elif t=="dpl": st.dpl=(0 if st.dpl is None else ((st.dpl+ (1 if mn=="inc" else -1)) &0xFF)); st.upd()
            elif t=="dph": st.dph=(0 if st.dph is None else ((st.dph+ (1 if mn=="inc" else -1)) &0xFF)); st.upd()
        elif mn=="xch":
            if op_t(ea,0)=="a" and op_t(ea,1)=="dpl":
                tmp=st.a_imm; st.a_imm=st.dpl; st.dpl=tmp if tmp is not None else st.dpl; st.upd()
            if op_t(ea,0)=="a" and op_t(ea,1)=="dph":
                tmp=st.a_imm; st.a_imm=st.dph; st.dph=tmp if tmp is not None else st.dph; st.upd()
        elif mn=="anl" and op_t(ea,0)=="a" and ins.ops[1].type==ida_ua.o_imm:
            st.masks.append(("ANL",imm_u8(ins.ops[1].value),ea))
        elif mn=="orl" and op_t(ea,0)=="a" and ins.ops[1].type==ida_ua.o_imm:
            st.masks.append(("ORL",imm_u8(ins.ops[1].value),ea))
        elif mn=="cpl" and op_t(ea,0).startswith("acc."):
            bit=int(op_t(ea,0).split(".")[1]); st.masks.append(("CPL",bit,ea))
        elif is_movx_r(ea):
            st.last_movx_read=True; st.a_imm=None; st.masks.clear()

        # MOVX write capture
        if is_movx_w(ea):
            rec = {
                'ea':ea,'dptr':st.dptr,'in_target':in_target_range(st.dptr),
                'type':None,'a_imm':st.a_imm,'masks':list(st.masks),
                'imm86':has_imm86(list(st.ctx)), 'ctx':list(st.ctx)
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
            results_all.append(rec)
            if rec['in_target']: results_target.append(rec)
            st.last_movx_read=False; st.masks.clear()

        # text-level immediates of interest
        txt=dis(ea).lower()
        if re.search(r'#\s*0x0b7[0-9a-f]|0b7[0-9a-f]h', txt) or '#0x86' in txt or ' 86h' in txt:
            imm_hits.append((ea,txt))

    return results_target, results_all, dp_loads_0B, table_sites, imm_hits

def write_reports(results_target, results_all, dp_loads_0B, table_sites, imm_hits):
    base = ida_kernwin.ask_file(True, "osd_probe_report.md", "Save report as...")
    if not base:
        ida_kernwin.msg("Cancelled.\n"); return
    root,_=os.path.splitext(base)
    csv_path=root+".csv"; md_path=root+".md"

    # CSV (all MOVX writes, easiest to filter in Excel)
    with open(csv_path,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["ea","dptr","in_target","type","a_imm","masks","imm86","ctx_tail"])
        for r in results_all:
            masks=";".join("%s:%s@%s"%(k,(HEX(v) if k!='CPL' else "bit.%d"%v),HEX(ea)) for k,v,ea in r['masks'])
            w.writerow([HEX(r['ea']), (HEX(r['dptr']) if r['dptr'] is not None else ""),
                        "yes" if r['in_target'] else "no", r['type'],
                        (HEX(r['a_imm']) if r['a_imm'] is not None else ""),
                        masks, "yes" if r['imm86'] else "no",
                        " | ".join(r['ctx'][-4:])])

    # MD (human summary)
    with open(md_path,"w",encoding="utf-8") as f:
        f.write(f"# Sonix 8051 Probe v2 (IDA 9.1)\n\n")
        f.write(f"- Generated: {time.ctime()}\n- Processor: {PROC}\n")
        f.write(f"- Target DPH: 0x{TARGET_DPH:02X} (window {WINDOW_LOW:#04x}-{WINDOW_HIGH:#04x})\n\n")
        f.write("## Summary\n")
        f.write(f"- All MOVX @DPTR,A seen: **{len(results_all)}**\n")
        f.write(f"- In target page (DPH==0x{TARGET_DPH:02X}): **{len(results_target)}**\n")
        f.write(f"- DPTR loads with DPH==0x{TARGET_DPH:02X}: **{len(dp_loads_0B)}**\n")
        f.write(f"- MOVC sites: **{len(table_sites)}**\n")
        f.write(f"- Immediates of interest (0x0B7x / 0x86): **{len(imm_hits)}**\n\n")

        def emit_ctx(ctx):
            f.write("```\n"); [f.write(l+"\n") for l in ctx[-10:]]; f.write("```\n\n")

        f.write("## MOVX writes in target page\n\n")
        for r in results_target:
            f.write(f"**EA {HEX(r['ea'])} | DPTR {HEX(r['dptr']) if r['dptr'] is not None else 'unknown'}**\n")
            f.write(f"- Type: {r['type']} | 0x86 near: {'yes' if r['imm86'] else 'no'}\n")
            if r['masks']:
                ms=", ".join("%s:%s@%s"%(k,(HEX(v) if k!='CPL' else 'bit.%d'%v),HEX(ea)) for k,v,ea in r['masks'])
            else:
                ms="-"
            f.write(f"- Masks: {ms}\n- Context:\n"); emit_ctx(r['ctx'])

        f.write("## All MOVX writes (any page)\n\n")
        for r in results_all[:800]:
            f.write(f"**EA {HEX(r['ea'])} | DPTR {HEX(r['dptr']) if r['dptr'] is not None else 'unknown'} | {'TARGET' if r['in_target'] else 'other'}**\n")
            f.write(f"- Type: {r['type']} | Aimm: {(HEX(r['a_imm']) if r['a_imm'] is not None else '-')}\n")
            if r['masks']:
                ms=", ".join("%s:%s@%s"%(k,(HEX(v) if k!='CPL' else 'bit.%d'%v),HEX(ea)) for k,v,ea in r['masks'])
            else:
                ms="-"
            f.write(f"- Masks: {ms}\n- Context:\n"); emit_ctx(r['ctx'])

        f.write("## DPTR loads where DPH==target\n\n")
        for ea,dptr,ctx in dp_loads_0B:
            f.write(f"**EA {HEX(ea)} | DPTR {HEX(dptr)}**\n"); emit_ctx(ctx)

        f.write("## MOVC A,@A+DPTR sites\n\n")
        for ea,ctx in table_sites:
            f.write(f"**EA {HEX(ea)}**\n"); emit_ctx(ctx)

        f.write("## Immediates of interest (text-level)\n\n")
        for ea,txt in imm_hits[:500]:
            f.write(f"- {HEX(ea)}: {txt}\n")

    ida_kernwin.info("Wrote:\n%s\n%s"%(csv_path,md_path))

def main():
    if not PROC.startswith('8051'):
        ida_kernwin.warning("Processor is '%s'; results may be off."%PROC)
    rt, ra, dl, tabs, imms = analyze()
    write_reports(rt, ra, dl, tabs, imms)

if __name__=='__main__':
    main()