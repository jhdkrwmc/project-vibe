#!/usr/bin/env python3
"""
SN9C292B Plan B Patcher (v4.1) — correct LE word‑sum @ tail + optional --recalc-only

Plan B:
- LJMP from a small padding window → code-cave stub → LJMP back.
- Stub clears XDATA 0xE24.. (N bytes) then returns.
- Footer is a two’s‑complement of the LE 16‑bit word‑sum of the body (all bytes except the last two).

This version fixes the quoting bug that caused a SyntaxError on Windows.
"""

import argparse, json, sys, hashlib
from pathlib import Path

def sum16_words_le(buf: bytes) -> int:
    """Little-endian 16-bit word sum over the whole buffer (wrap at 0x10000)."""
    n = len(buf) & ~1  # even length
    s = 0
    for i in range(0, n, 2):
        s = (s + buf[i] + (buf[i+1] << 8)) & 0xFFFF
    if len(buf) & 1:  # odd length: add last byte
        s = (s + buf[-1]) & 0xFFFF
    return s

def hexdump_slice(data: bytes, off: int, length: int) -> str:
    s = data[off:off+length]
    return " ".join(f"{b:02x}" for b in s)

def parse_int(x): 
    return int(str(x), 0)

def build_stub(return_addr: int, clear_n: int) -> bytes:
    if clear_n < 1 or clear_n > 4:
        raise ValueError("clear-count must be 1..4")
    out = bytearray()
    out += bytes.fromhex("c0e0 c082 c083".replace(" ",""))   # push acc,dpl,dph
    out += bytes.fromhex("90 0e 24")                          # mov dptr,#0x0E24
    out += b"\xE4"                                            # clr a
    for i in range(clear_n):
        if i: out += b"\xA3"                                  # inc dptr
        out += b"\xF0"                                        # movx @dptr,a
    out += bytes.fromhex("d083 d082 d0e0".replace(" ",""))    # pop dph,dpl,acc
    out += bytes([0x02, (return_addr>>8)&0xFF, return_addr&0xFF])  # ljmp return_addr
    return bytes(out)

def write_tail_checksum(data: bytearray) -> int:
    """Compute LE word-sum over body (excluding last two bytes) and write two's complement at tail."""
    if len(data) < 2:
        raise ValueError("image too small for footer")
    tail = len(data) - 2
    body = data[:tail]
    fix = (-sum16_words_le(body)) & 0xFFFF
    data[tail]   = fix & 0xFF
    data[tail+1] = (fix >> 8) & 0xFF
    return fix

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--inject-addr", default="0x0A516")
    ap.add_argument("--inject-run-len", default="4")
    ap.add_argument("--inject-pad-byte", default="0x00")
    ap.add_argument("--cave-addr", default="0x00BFA8")
    ap.add_argument("--return-addr", default="0x0A51A")
    ap.add_argument("--clear-count", default="2")
    ap.add_argument("--force", default="no", choices=["yes","no"], help="allow non-padding windows/caves (not recommended)")
    ap.add_argument("--recalc-only", default="no", choices=["yes","no"], help="only recompute & write footer checksum")
    ap.add_argument("--dry-run", default="no", choices=["yes","no"])  # for patch mode
    args = ap.parse_args()

    inj      = parse_int(args.inject_addr)
    run_len  = parse_int(args.inject_run_len)
    pad_b    = parse_int(args.inject_pad_byte)
    cave     = parse_int(args.cave_addr)
    ret      = parse_int(args.return_addr)
    clear_n  = parse_int(args.clear_count)
    force    = (args.force == "yes")
    recalc   = (args.recalc_only == "yes")
    dry      = (args.dry_run == "yes")

    data = bytearray(Path(args.input).read_bytes())
    size = len(data)

    sha_before = hashlib.sha256(data).hexdigest()
    pre_sum_all = sum16_words_le(data)

    summary = {
        "input": str(Path(args.input)),
        "output": str(Path(args.output)),
        "size_bytes": size,
        "plan": "Plan B (late-clear stub; LJMP from padding → cave; dynamic SUM16 footer fix)",
        "parameters": {},
        "bytes_written": {},
        "checksum": {
            "pre_sum16_all": pre_sum_all
        },
        "hashes": {
            "sha256_before": sha_before
        }
    }

    if recalc:
        fix = write_tail_checksum(data)
        post_sum_all = sum16_words_le(data)
        summary["parameters"]["checksum_fix_at"] = f"0x{size-2:05x} (last 2 bytes)"
        summary["checksum"]["fix_value_le"] = fix
        summary["checksum"]["post_sum16_all"] = post_sum_all
    else:
        # sanity ranges
        if inj+run_len > size or cave+22 > size or ret >= size:
            print("[FAIL] address out of range", file=sys.stderr); sys.exit(2)
        # verify injection window is padding (unless --force)
        win = bytes(data[inj:inj+run_len])
        if not all(b==pad_b for b in win) and not force:
            print(f"[FAIL] inj window not all {pad_b:02x}: {hexdump_slice(win,0,len(win))}", file=sys.stderr); sys.exit(2)

        # build stub & validate cave
        stub = build_stub(ret, clear_n)
        cave_span = bytes(data[cave:cave+len(stub)])
        if not all(b in (0x00,0xFF) for b in cave_span) and not force:
            print(f"[FAIL] cave not clean padding: {hexdump_slice(cave_span,0,min(32,len(stub)))}", file=sys.stderr); sys.exit(2)

        # apply patch
        data[cave:cave+len(stub)] = stub
        data[inj:inj+3] = bytes([0x02, (cave>>8)&0xFF, cave&0xFF])
        for i in range(3, run_len):
            data[inj+i] = 0x00

        fix = write_tail_checksum(data)
        post_sum_all = sum16_words_le(data)

        summary["parameters"].update({
            "inject_addr": f"0x{inj:05x}",
            "inject_run_len": run_len,
            "inject_pad_byte": f"0x{pad_b:02x}",
            "cave_addr": f"0x{cave:05x}",
            "clear_count": clear_n,
            "return_addr": f"0x{ret:05x}",
            "checksum_fix_at": f"0x{size-2:05x} (last 2 bytes)"
        })
        summary["bytes_written"].update({
            "inject_ljmp": f"{data[inj]:02x}{data[inj+1]:02x}{data[inj+2]:02x}",
            "inj_before": hexdump_slice(win,0,len(win)),
            "inj_after": hexdump_slice(data,inj,run_len),
            "stub_len": len(stub),
            "cave_before": hexdump_slice(cave_span,0,min(32,len(stub))),
            "stub_after": hexdump_slice(data,cave,len(stub))
        })
        summary["checksum"].update({
            "fix_value_le": fix,
            "post_sum16_all": post_sum_all
        })

    sha_after = hashlib.sha256(data).hexdigest()
    summary["hashes"]["sha256_after"] = sha_after

    # persist
    Path(args.output).write_bytes(data)
    Path(str(args.output)+".json").write_text(json.dumps(summary, indent=2))

    print(json.dumps(summary, indent=2))
    print(f"[OK] Wrote {args.output} and {args.output}.json")

if __name__ == "__main__":
    sys.exit(main())
