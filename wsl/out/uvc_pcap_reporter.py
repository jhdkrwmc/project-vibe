#!/usr/bin/env python3
# UVC/USB control extractor with tshark field auto-detection (Windows/Linux)
# - Multi-file input (CLI or tiny Tk picker)
# - Stitches control submit/completion via usb.urb_id
# - Decodes UVC CS/channel/entity/interface (wValue/wIndex)
# - Exports HTML (interactive), JSON, CSV

import argparse, csv, json, os, shutil, subprocess, sys
from collections import defaultdict
from datetime import datetime

# -------- utils --------

def which(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

def split_csv_line(line: str) -> list[str]:
    row, cur, inq = [], [], False
    for ch in line:
        if ch == '"': inq = not inq; continue
        if ch == ',' and not inq: row.append(''.join(cur)); cur=[]; continue
        cur.append(ch)
    row.append(''.join(cur))
    return row

def parse_int(x: str|None) -> int|None:
    if not x: return None
    for base in (0,10,16):
        try:
            return int(x, base) if base else int(x, 0)
        except Exception:
            pass
    return None

# -------- tshark field negotiation --------

# Canonical names we want, with ordered fallbacks per Wireshark build
FIELD_FALLBACKS = {
    "usb_status":                ["usb.status", "usb.urb_status"],
    "usb_endpoint":              ["usb.endpoint_number", "usb.endpoint_address", "usb.endpoint_number.endpoint"],
    "usb_bRequest":              ["usb.bRequest", "usb.control.bRequest", "usb.setup.bRequest"],
    "usb_wValue":                ["usb.wValue", "usb.control.wValue", "usb.setup.wValue"],
    "usb_wIndex":                ["usb.wIndex", "usb.control.wIndex", "usb.setup.wIndex"],
    "usb_capdata":               ["usb.capdata", "usb.setup.raw_data", "usb.data_fragment", "frame.payload"],
    "usb_data_len":              ["usb.data_len", "usb.data_length", "usb.len"],
    # these are usually stable, but keep here in case
    "usb_bus_id":                ["usb.bus_id"],
    "usb_dev_addr":              ["usb.device_address"],
    "usb_urb_type":              ["usb.urb_type"],
    "usb_urb_id":                ["usb.urb_id"],
    "usb_transfer_type":         ["usb.transfer_type"],
    "usb_bmReq_dir":             ["usb.bmRequestType.direction"],
    "usb_bmReq_type":            ["usb.bmRequestType.type"],
    "frame_time_epoch":          ["frame.time_epoch"],
    "frame_time_relative":       ["frame.time_relative"],
    "frame_number":              ["frame.number"],
}

def detect_field_map() -> dict:
    # Build a set of available field names from tshark
    try:
        out = run(["tshark", "-G", "fields"]).stdout.splitlines()
    except Exception as e:
        raise SystemExit(f"tshark not found or -G failed: {e}")
    avail = set()
    for line in out:
        # lines look like: F\t<name>\t<desc>\t...
        parts = line.split("\t")
        if len(parts) > 2 and parts[0] == "F":
            avail.add(parts[1])
    fmap = {}
    missing = []
    for canon, opts in FIELD_FALLBACKS.items():
        for o in opts:
            if o in avail:
                fmap[canon] = o
                break
        if canon not in fmap:
            missing.append(canon)
    # we can live without capdata/endpoint sometimes
    for opt in ("usb_capdata", "usb_data_len"):
        if opt in missing: missing.remove(opt)
    if missing:
        # Still run, but warn (printed once)
        sys.stderr.write("[!] tshark missing some USB fields: " + ", ".join(missing) + "\n")
    return fmap

# -------- tshark extraction --------

def run_tshark_fields(pcap: str, display_filter: str, fields: list[str]) -> list[list[str]]:
    cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for f in fields: cmd += ["-e", f]
    cmd += ["-E", "separator=,", "-E", "quote=d", "-E", "header=y"]
    try:
        cp = run(cmd)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"tshark failed on {pcap}: {e.stderr.strip()}")
    lines = cp.stdout.splitlines()
    if not lines: return []
    return [split_csv_line(line) for line in lines[1:]]

def decode_uvc(wValue: int|None, wIndex: int|None):
    if wValue is None or wIndex is None:
        return None, None, None, None
    cs  = (wValue >> 8) & 0xFF
    ch  =  wValue       & 0xFF
    ent = (wIndex >> 8) & 0xFF
    ifn =  wIndex       & 0xFF
    return cs, ch, ent, ifn

BREQUEST_NAMES = {
    0x81:"GET_CUR", 0x82:"GET_MIN", 0x83:"GET_MAX", 0x84:"GET_RES",
    0x85:"GET_LEN", 0x86:"GET_INFO",0x87:"GET_DEF", 0x01:"SET_CUR",
    0x00:"GET_STATUS",0x01|0x80:"GET_STATUS",0x03:"SET_FEATURE",
    0x06:"GET_DESCRIPTOR",0x07:"SET_DESCRIPTOR",
    0x08:"GET_CONFIGURATION",0x09:"SET_CONFIGURATION",
    0x0A:"GET_INTERFACE",0x0B:"SET_INTERFACE",
}

def brequest_name(v: int|None) -> str:
    if v is None: return ""
    return BREQUEST_NAMES.get(v, f"0x{v:02x}")

def gather_transactions(pcap: str, tag: str, fmap: dict) -> list[dict]:
    # only control transfers (submit+complete)
    df = "usb.transfer_type == 0"
    base_fields = [
        fmap["frame_number"], fmap["frame_time_epoch"], fmap["frame_time_relative"],
        fmap["usb_bus_id"], fmap["usb_dev_addr"], fmap["usb_urb_type"],
        fmap["usb_urb_id"], fmap["usb_transfer_type"],
        fmap["usb_bmReq_dir"], fmap["usb_bmReq_type"],
        fmap.get("usb_endpoint") or "",             # may be missing
        fmap.get("usb_status") or "",               # for completion rows
        fmap.get("usb_data_len") or "",
        fmap.get("usb_capdata") or "",
        fmap.get("usb_bRequest") or "",
        fmap.get("usb_wValue") or "",
        fmap.get("usb_wIndex") or "",
    ]
    # remove empties (tshark chokes on unknown/empty fields)
    fields = [f for f in base_fields if f]
    rows = run_tshark_fields(pcap, df, fields)

    # map field -> index
    idx = {f:i for i,f in enumerate(fields)}
    # convenience getters (return empty if missing)
    def sget(r, key): 
        fi = fmap.get(key); 
        return r[idx[fi]] if fi in idx else ""

    submit, complete = {}, {}
    for r in rows:
        urb_type = (sget(r,"usb_urb_type") or "").strip().upper()
        urb_id   = sget(r,"usb_urb_id")
        if not urb_id: 
            continue
        (submit if urb_type == "S" else complete).setdefault(urb_id, []).append(r)

    txs = []
    for urb_id, s_rows in submit.items():
        s = s_rows[0]
        c = (complete.get(urb_id) or [None])[0]

        def cget(key):
            if c is None: return ""
            fi = fmap.get(key)
            return c[idx[fi]] if fi in idx else ""

        t_epoch = float(sget(s,"frame_time_epoch") or 0.0)
        t_rel   = float(sget(s,"frame_time_relative") or 0.0)

        bus     = parse_int(sget(s,"usb_bus_id"))
        dev     = parse_int(sget(s,"usb_dev_addr"))
        ep      = parse_int(sget(s,"usb_endpoint"))
        reqdir  = parse_int(sget(s,"usb_bmReq_dir"))
        reqtype = parse_int(sget(s,"usb_bmReq_type"))
        breq    = parse_int(sget(s,"usb_bRequest"))
        wval    = parse_int(sget(s,"usb_wValue"))
        wind    = parse_int(sget(s,"usb_wIndex"))
        dlen_s  = parse_int(sget(s,"usb_data_len"))
        data_s  = (sget(s,"usb_capdata") or "").lower()

        status  = parse_int(cget("usb_status"))
        dlen_c  = parse_int(cget("usb_data_len"))
        data_c  = (cget("usb_capdata") or "").lower()

        cs,ch,ent,ifn = decode_uvc(wval, wind)
        txs.append({
            "file": tag,
            "urb_id": urb_id,
            "time_epoch": t_epoch,
            "time_rel": t_rel,
            "bus": bus, "dev": dev, "ep": ep,
            "dir": reqdir, "type": reqtype,
            "bRequest": breq, "bRequest_name": brequest_name(breq),
            "wValue": wval, "wIndex": wind,
            "cs": cs, "channel": ch, "entity_id": ent, "interface": ifn,
            "s_data_len": dlen_s, "s_data": data_s,
            "c_status": status, "c_data_len": dlen_c, "c_data": data_c,
        })

    txs.sort(key=lambda t: (t["time_epoch"], t["urb_id"]))
    return txs

# -------- outputs --------

def write_csv(path: str, txs: list[dict]):
    cols = ["file","time_rel","bus","dev","dir","type","bRequest_name","bRequest",
            "cs","channel","entity_id","interface","wValue","wIndex",
            "s_data_len","c_status","c_data_len","urb_id"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for t in txs: w.writerow({k:t.get(k,"") for k in cols})

def compare_stats(txs: list[dict]):
    perfile = defaultdict(lambda: defaultdict(int))
    for t in txs:
        key = (t.get("entity_id"), t.get("cs"), t.get("bRequest_name"))
        perfile[t["file"]][key] += 1
    all_keys = sorted(set().union(*perfile.values()))
    files = sorted(perfile.keys())
    matrix = []
    for k in all_keys:
        row = {"entity_id": k[0], "cs": k[1], "bRequest": k[2]}
        for f in files: row[f] = perfile[f].get(k, 0)
        matrix.append(row)
    return {"files": files, "matrix": matrix}

HTML_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>UVC USB Control Report</title>
<style>
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 1rem; }
summary { cursor: pointer; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { border: 1px solid #ddd; padding: 6px; }
th { background: #f0f0f0; position: sticky; top: 0; }
tr:nth-child(even) { background: #fafafa; }
input[type="text"], select { padding: 6px; margin: 0 6px 6px 0; }
.badge { display:inline-block; padding:2px 6px; border-radius:12px; background:#eee; margin-right:6px; }
</style>
</head><body>
<h2>UVC / USB Control Report</h2>
<div id="meta"></div>

<details open>
<summary><b>Filters</b></summary>
<input id="q" type="text" placeholder="search (file, req, cs, entity, data)"/>
<select id="file"></select>
<select id="dir">
  <option value="">dir (any)</option>
  <option value="0">SET (Host→Device)</option>
  <option value="1">GET (Device→Host)</option>
</select>
<select id="onlyclass">
  <option value="">type (any)</option>
  <option value="1">class only</option>
</select>
</details>

<div style="margin:8px 0;"><span class="badge" id="count"></span></div>

<div style="overflow:auto; max-height:72vh;">
<table id="tbl">
  <thead><tr id="hdr"></tr></thead>
  <tbody id="rows"></tbody>
</table>
</div>

<details>
<summary><b>Per-file compare</b></summary>
<div id="compare"></div>
</details>

<script>
const DATA = /*__DATA_JSON__*/;
const COLS = ["file","time_rel","bus","dev","dir","type","bRequest_name","bRequest","cs","channel","entity_id","interface","wValue","wIndex","s_data_len","c_status","c_data_len","urb_id","s_data","c_data"];
const HDR  = ["file","t_rel","bus","dev","dir","type","req","req(hex)","CS","ch","ent","if","wVal","wIdx","s_len","status","c_len","urb_id","s_data","c_data"];
const el = id => document.getElementById(id);
function fmtDir(d){ return d===1||d==="1" ? "GET" : (d===0||d==="0" ? "SET" : ""); }
function renderOptions(){
  const files=[...new Set(DATA.txs.map(t=>t.file))].sort();
  el("file").innerHTML = "<option value=''>file (any)</option>" + files.map(f=>`<option>${f}</option>`).join("");
  el("meta").innerHTML = `<div>files: ${files.map(f=>`<span class='badge'>${f}</span>`).join("")}</div>`;
}
function passFilters(t){
  const q = el("q").value.toLowerCase();
  const f = el("file").value, dir = el("dir").value, onlyc = el("onlyclass").value;
  if (f && t.file!==f) return false;
  if (dir!=="" && String(t.dir)!==dir) return false;
  if (onlyc!=="" && String(t.type)!==onlyc) return false;
  if (!q) return true;
  const hay = [t.file, t.bRequest_name, t.cs, t.entity_id, t.channel, t.interface, t.s_data, t.c_data].join(" ").toLowerCase();
  return hay.includes(q);
}
let sortKey="time_rel", sortAsc=true;
function sortBy(k){ if (sortKey===k) sortAsc=!sortAsc; else { sortKey=k; sortAsc=true; } renderTable(); }
function renderTable(){
  const rows = DATA.txs.filter(passFilters).sort((a,b)=>{
    const x=a[sortKey], y=b[sortKey];
    if (x==null && y==null) return 0; if (x==null) return 1; if (y==null) return -1;
    return (x<y?-1:x>y?1:0)*(sortAsc?1:-1);
  });
  el("count").textContent = `${rows.length} transactions`;
  el("hdr").innerHTML = HDR.map((h,i)=>`<th onclick="sortBy('${COLS[i]}')">${h}${sortKey===COLS[i]?(sortAsc?" ▲":" ▼"):""}</th>`).join("");
  const cells = r => [
    r.file, r.time_rel?.toFixed?.(6) ?? r.time_rel, r.bus, r.dev, fmtDir(r.dir), r.type,
    r.bRequest_name, r.bRequest!=null?("0x"+(+r.bRequest).toString(16).padStart(2,"0")):"",
    r.cs, r.channel, r.entity_id, r.interface, r.wValue, r.wIndex,
    r.s_data_len, r.c_status, r.c_data_len, r.urb_id,
    (r.s_data||"").slice(0,64), (r.c_data||"").slice(0,64)
  ].map(x=>x==null?"":x);
  el("rows").innerHTML = rows.map(r=>"<tr>"+cells(r).map(v=>`<td>${v}</td>`).join("")+"</tr>").join("");
}
function renderCompare(){
  const s = DATA.stats; if (!s || !s.files) return;
  const cols = ["entity_id","cs","bRequest", ...s.files];
  const header = "<tr>"+cols.map(h=>`<th>${h}</th>`).join("")+"</tr>";
  const body = s.matrix.map(row=>"<tr>"+cols.map(k=>`<td>${row[k]??""}</td>`).join("")+"</tr>").join("");
  el("compare").innerHTML = `<table><thead>${header}</thead><tbody>${body}</tbody></table>`;
}
["q","file","dir","onlyclass"].forEach(id=>el(id).addEventListener("input", renderTable));
renderOptions(); renderCompare(); renderTable();
</script>
</body></html>
"""

def write_html(path: str, txs: list[dict], stats: dict):
    payload = {"txs": txs, "stats": stats}
    html = HTML_TEMPLATE.replace("/*__DATA_JSON__*/", json.dumps(payload))
    with open(path, "w", encoding="utf-8") as f: f.write(html)

def write_json(path: str, txs: list[dict], stats: dict):
    out = {"created": datetime.utcnow().isoformat()+"Z", "transactions": txs, "stats": stats}
    with open(path, "w", encoding="utf-8") as f: json.dump(out, f, indent=2)

def write_csv(path: str, txs: list[dict]):
    cols = ["file","time_rel","bus","dev","dir","type","bRequest_name","bRequest",
            "cs","channel","entity_id","interface","wValue","wIndex",
            "s_data_len","c_status","c_data_len","urb_id"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for t in txs: w.writerow({k:t.get(k,"") for k in cols})

def tiny_gui_select():
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception:
        return []
    root = tk.Tk(); root.withdraw()
    paths = filedialog.askopenfilenames(title="Select pcapng files", filetypes=[("pcapng","*.pcapng"),("All files","*.*")])
    return list(paths)

def main():
    if not which("tshark"):
        sys.exit("ERROR: tshark not found. Install via winget Wireshark or run in WSL.")
    ap = argparse.ArgumentParser(description="Extract UVC/USB control transactions and build HTML/CSV/JSON report.")
    ap.add_argument("pcaps", nargs="*", help="pcapng files")
    ap.add_argument("-o","--out", default=os.getcwd(), help="output directory (default: cwd)")
    args = ap.parse_args()

    pcaps = args.pcaps or tiny_gui_select()
    if not pcaps: sys.exit("No input files provided.")

    outdir = os.path.abspath(args.out); os.makedirs(outdir, exist_ok=True)
    fmap = detect_field_map()

    all_txs = []
    for p in pcaps:
        p = os.path.abspath(p); tag = os.path.basename(p)
        print(f"[+] parsing {tag} ...")
        try:
            tx = gather_transactions(p, tag, fmap)
            print(f"    {len(tx)} control transactions")
            all_txs.extend(tx)
        except Exception as e:
            print(f"[!] {tag}: {e}", file=sys.stderr)

    if not all_txs: sys.exit("No control transactions found.")

    stats = compare_stats(all_txs)
    html_path = os.path.join(outdir, "uvc_report.html")
    json_path = os.path.join(outdir, "uvc_report.json")
    csv_path  = os.path.join(outdir, "uvc_report.csv")
    write_html(html_path, all_txs, stats)
    write_json(json_path, all_txs, stats)
    write_csv(csv_path, all_txs)
    print(f"[OK] wrote:\n  {html_path}\n  {json_path}\n  {csv_path}")

if __name__ == "__main__":
    main()
