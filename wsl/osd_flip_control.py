#!/usr/bin/env python3
# osd_flip_capture.py
"""
Run USB capture while flipping OSD via xu_headless.py.

Requires:
  - USBPcapCMD in PATH (Windows)
  - xu_headless.py in same dir or in PATH

Example:
  python osd_flip_capture.py --vid 0x0c45 --pid 0x6366 ^
    --usbpcap-dev "\\\\.\\USBPcap1" ^
    --pcap out\snx_toggle.pcapng ^
    --seq on,off,on,off --interval 2.0 ^
    --backend cmd ^
    --cmd-on  "C:\\tools\\SONiX_UVC_TestAP.exe --xu-osd=1 --vid {vid} --pid {pid}" ^
    --cmd-off "C:\\tools\\SONiX_UVC_TestAP.exe --xu-osd=0 --vid {vid} --pid {pid}"
"""
import argparse, os, re, subprocess, sys, time, signal, shutil, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

def find_usbpcap_device(vid:int, pid:int) -> str|None:
    # Parse "USBPcapCMD -L" output, try to find a device path that mentions VID/PID.
    try:
        out = subprocess.check_output(["USBPcapCMD", "-L"], text=True, errors="ignore")
    except Exception as e:
        print(f"[cap] USBPcapCMD -L failed: {e}")
        return None
    # Heuristics: search lines containing VID_xxxx & PID_xxxx or 0xVID:0xPID
    pat1 = re.compile(r"VID[_:]?0*%04X.*PID[_:]?0*%04X" % (vid, pid), re.I)
    dev = None
    current_dev = None
    for line in out.splitlines():
        m = re.match(r"\s*(\\\\\.\\USBPcap\d+)", line)
        if m:
            current_dev = m.group(1)
        if pat1.search(line):
            # Use the most recent device block name
            if current_dev:
                dev = current_dev
    return dev

def start_usbpcap(dev: str, out_file: str):
    # Start USBPcapCMD capturing this device; returns Popen
    # Note: USBPcapCMD stops on Ctrl-C/Break. We'll spawn in new process group to send CTRL_BREAK_EVENT.
    cmd = ["USBPcapCMD", "-d", dev, "-o", out_file]
    print(f"[cap] start: {' '.join(cmd)}")
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    p = subprocess.Popen(cmd, creationflags=creationflags)
    # Give it a moment to init the file
    time.sleep(1.0)
    return p

def stop_usbpcap(proc: subprocess.Popen):
    print("[cap] stopping capture...")
    try:
        # Try to send CTRL_BREAK on Windows
        if os.name == "nt":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            try:
                proc.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception as e:
        print(f"[cap] stop error: {e}")

def run_xu(backend:str, vid:int, pid:int, state:str, cmd_on=None, cmd_off=None, py_mod=None, py_func=None):
    exe = shutil.which("python") or sys.executable
    args = [exe, os.path.join(HERE, "xu_headless.py"),
            "--backend", backend, "--vid", f"0x{vid:04x}", "--pid", f"0x{pid:04x}", "--set", state]
    if backend == "cmd":
        if cmd_on:  args += ["--cmd-on",  cmd_on]
        if cmd_off: args += ["--cmd-off", cmd_off]
    else:
        if py_mod:  args += ["--py-mod",  py_mod]
        if py_func: args += ["--py-func", py_func]
    print(f"[xu] {' '.join(args)}")
    cp = subprocess.run(args)
    if cp.returncode != 0:
        raise RuntimeError(f"xu_headless failed with {cp.returncode}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vid", type=lambda s:int(s,0), required=True)
    ap.add_argument("--pid", type=lambda s:int(s,0), required=True)
    ap.add_argument("--pcap", required=True, help="Output PCAP/PCAPNG path")
    ap.add_argument("--usbpcap-dev", default=None, help=r'Override USBPcap device path, e.g. "\\.\USBPcap1"')
    ap.add_argument("--seq", default="on,off,on,off", help="Comma-separated sequence: on/off")
    ap.add_argument("--interval", type=float, default=1.0, help="Seconds between flips")

    # xu backend passthrough
    ap.add_argument("--backend", choices=["cmd","py"], required=True)
    ap.add_argument("--cmd-on", default=None)
    ap.add_argument("--cmd-off", default=None)
    ap.add_argument("--py-mod", default=None)
    ap.add_argument("--py-func", default=None)

    args = ap.parse_args()

    usb_dev = args.usbpcap_dev or find_usbpcap_device(args.vid, args.pid)
    if not usb_dev:
        print("[cap] Could not auto-detect USBPcap device. Use --usbpcap-dev", file=sys.stderr)
        sys.exit(2)

    os.makedirs(os.path.dirname(os.path.abspath(args.pcap)), exist_ok=True)
    cap = start_usbpcap(usb_dev, args.pcap)
    try:
        time.sleep(1.0)
        for token in [t.strip().lower() for t in args.seq.split(",") if t.strip()]:
            if token not in ("on","off"):
                raise ValueError(f"Bad token in --seq: {token}")
            run_xu(args.backend, args.vid, args.pid, token,
                   cmd_on=args.cmd_on, cmd_off=args.cmd_off,
                   py_mod=args.py_mod, py_func=args.py_func)
            time.sleep(args.interval)
        # small tail so last transfers flush
        time.sleep(1.0)
    finally:
        stop_usbpcap(cap)
        print(f"[cap] saved: {args.pcap}")

if __name__ == "__main__":
    main()