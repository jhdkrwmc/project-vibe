#!/usr/bin/env python3
# osd_flip_control.py — unified (Windows USBPcap + Linux usbmon)
import argparse, os, re, subprocess, sys, time, signal, shutil, platform, shlex

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------- Windows helpers (USBPcap) ----------
def _win_find_usbpcap_device(vid:int, pid:int)->str|None:
    try:
        out = subprocess.check_output(["USBPcapCMD","-L"], text=True, errors="ignore")
    except Exception as e:
        print(f"[cap] USBPcapCMD -L failed: {e}")
        return None
    pat = re.compile(rf"VID[_:]?0*{vid:04X}.*PID[_:]?0*{pid:04X}", re.I)
    dev, cur = None, None
    for line in out.splitlines():
        m = re.match(r"\s*(\\\\\\.\\USBPcap\d+)", line)
        if m: cur = m.group(1)
        if pat.search(line) and cur: dev = cur
    return dev

def _win_start_usbpcap(dev:str, out_file:str):
    cmd = ["USBPcapCMD","-d",dev,"-o",out_file]
    creation = getattr(subprocess,"CREATE_NEW_PROCESS_GROUP",0)
    print(f"[cap] start: {' '.join(cmd)}")
    p = subprocess.Popen(cmd, creationflags=creation)
    time.sleep(1.0)
    return p

# ---------- Linux helpers (usbmon) ----------
def _linux_lsusb_pick(vid:int, pid:int):
    try:
        out = subprocess.check_output(["lsusb"], text=True)
    except Exception as e:
        print("[cap] lsusb failed:", e); return None, None, None
    bus, dev = None, None
    for line in out.splitlines():
        if f"{vid:04x}:{pid:04x}" in line.lower():
            # "Bus 001 Device 006: ID 0c45:6366 ..."
            m = re.search(r"Bus\s+(\d+)\s+Device\s+(\d+)", line)
            if m: bus, dev = m.group(1), m.group(2)
            break
    video = os.environ.get("VIDEO","/dev/video0")
    return bus, dev, video

def _linux_start_usbmon(bus:str, out_file:str):
    iface = f"usbmon{int(bus)}"
    tshark = shutil.which("tshark") or shutil.which("dumpcap")
    if not tshark: raise RuntimeError("tshark/dumpcap not found")
    cmd = ["sudo", tshark, "-i", iface, "-w", out_file]
    print(f"[cap] start: {' '.join(cmd)}")
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    return p

def _linux_start_stream(video:str, tool:str="cheese"):
    if tool == "cheese":
        p = subprocess.Popen(["cheese", video], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif tool == "ffplay":
        p = subprocess.Popen(["ffplay","-loglevel","error","-f","video4linux2","-i",video],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        p = None
    time.sleep(1.0)
    return p

def _linux_stop(proc:subprocess.Popen):
    if not proc: return
    try:
        proc.terminate(); proc.wait(timeout=5)
    except Exception:
        try: proc.kill()
        except Exception: pass

# ---------- common ----------
def _stop_capture(proc:subprocess.Popen):
    print("[cap] stopping capture...")
    try:
        if platform.system()=="Windows":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            proc.wait(timeout=5)
        else:
            proc.terminate()
            proc.wait(timeout=5)
    except Exception:
        try: proc.kill()
        except Exception: pass

def _run_xu_sonix_linux(vid:int,pid:int,osd_on:bool, tool:str):
    flag = "1" if osd_on else "0"
    cmd = [tool, "--vid", f"0x{vid:04x}", "--pid", f"0x{pid:04x}", f"--xu-osd={flag}"]
    print("[xu]"," ".join(cmd))
    cp = subprocess.run(cmd, text=True)
    if cp.returncode != 0: print(f"[xu] tool returned {cp.returncode}")

def _run_xu_windows_cmd(template:str, vid:int, pid:int):
    cmd = template.format(vid=f"0x{vid:04x}", pid=f"0x{pid:04x}")
    print("[xu]", cmd)
    return subprocess.run(shlex.split(cmd)).returncode

def main():
    ap = argparse.ArgumentParser(description="Capture XU OSD flips while streaming (Windows or Linux).")
    ap.add_argument("--vid", type=lambda s:int(s,0), required=True)
    ap.add_argument("--pid", type=lambda s:int(s,0), required=True)
    ap.add_argument("--pcap", required=True, help="Output .pcap/.pcapng")
    ap.add_argument("--seq", default="off", help="Comma tokens: on/off (default: off)")
    ap.add_argument("--interval", type=float, default=1.0)

    # Windows cmd backend
    ap.add_argument("--cmd-on", default=None, help="Windows: command template for OSD ON")
    ap.add_argument("--cmd-off", default=None, help="Windows: command template for OSD OFF")

    # Linux specifics
    ap.add_argument("--linux-tool", default="~/Desktop/project-vibe/C1_SONIX_Test_AP/SONiX_UVC_TestAP",
                    help="Path to SONiX tool")
    ap.add_argument("--streamer", choices=["cheese","ffplay","none"], default="cheese")

    args = ap.parse_args()
    os.makedirs(os.path.dirname(os.path.abspath(args.pcap)), exist_ok=True)

    system = platform.system()
    cap_proc = None
    stream_proc = None
    try:
        if system == "Windows":
            dev = _win_find_usbpcap_device(args.vid, args.pid)
            if not dev:
                print("[cap] Could not find USBPcap device; pass --usbpcap-dev (not implemented here).", file=sys.stderr)
                sys.exit(2)
            cap_proc = _win_start_usbpcap(dev, args.pcap)
            # (optional) user handles preview on Windows
        else:
            bus, dev, video = _linux_lsusb_pick(args.vid, args.pid)
            if not bus:
                print("[cap] Camera not found via lsusb", file=sys.stderr)
                sys.exit(2)
            stream_proc = _linux_start_stream(video, args.streamer)
            cap_proc = _linux_start_usbmon(bus, args.pcap)

        time.sleep(1.0)
        tokens = [t.strip().lower() for t in args.seq.split(",") if t.strip()]
        for t in tokens:
            if t not in ("on","off"): raise ValueError(f"bad token: {t}")
            if system == "Windows":
                template = args.cmd_on if t=="on" else args.cmd_off
                if not template:
                    raise SystemExit("Missing --cmd-on/--cmd-off template for Windows")
                _run_xu_windows_cmd(template, args.vid, args.pid)
            else:
                tool = os.path.expanduser(args.linux_tool)
                _run_xu_sonix_linux(args.vid, args.pid, t=="on", tool)
            time.sleep(args.interval)
        time.sleep(1.0)
    finally:
        if cap_proc: _stop_capture(cap_proc)
        if stream_proc: _linux_stop(stream_proc)
        print(f"[cap] saved: {args.pcap}")

if __name__ == "__main__":
    main()


