#!/usr/bin/env bash
set -euo pipefail

# Detect WSL
is_wsl() { grep -qi microsoft /proc/version; }

mkdir -p ~/Desktop/project-vibe/{captures,intel,logs,wsl}

if [ "${SKIP_APT:-0}" != "1" ]; then
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y usbutils tshark wireshark \
                          v4l-utils ffmpeg python3-pip python3-tk \
                          git build-essential
fi

# Ensure usbmon is loaded where supported
if is_wsl; then
  echo "[*] WSL detected: skipping usbmon (module not in WSL kernel)"
else
  echo "[*] Enabling usbmon"
  sudo modprobe usbmon || true
fi

lsusb | tee ~/Desktop/project-vibe/logs/lsusb.txt
BUS=$(lsusb | awk '/0c45:6366/ {print $2}')
DEV=$(lsusb | awk '/0c45:6366/ {print $4}' | tr -d :)
echo "BUS=$BUS DEV=$DEV"

v4l2-ctl --list-devices | tee ~/Desktop/project-vibe/logs/v4l2-list.txt || sudo v4l2-ctl --list-devices | tee -a ~/Desktop/project-vibe/logs/v4l2-list.txt || true
VIDEO=$(v4l2-ctl --list-devices | awk '/Sonix|SN9|Webcam/{getline; print $1; exit}')
[ -z "$VIDEO" ] && VIDEO=/dev/video0
echo "VIDEO=$VIDEO"

cd ~/Desktop/project-vibe
[ -d C1_SONIX_Test_AP ] || git clone https://github.com/Kurokesu/C1_SONIX_Test_AP.git
cd C1_SONIX_Test_AP
make || true
cd - >/dev/null 2>&1 || true

# Start usbmon capture (skipped on WSL)
PCAP=~/Desktop/project-vibe/captures/osd_off_usbmon.pcapng
VIDFILE=~/Desktop/project-vibe/captures/osd_toggle.mkv
BEFORE=~/Desktop/project-vibe/captures/osd_before.png
AFTER=~/Desktop/project-vibe/captures/osd_after.png

# Convert BUS like 001 -> 1 for interface name
# Use arithmetic expansion to strip leading zeros reliably
BUS_NUM=$((10#$BUS))
IFACE="usbmon${BUS_NUM}"
if is_wsl; then
  echo "[*] WSL detected: skipping usbmon capture (no usbmon interface)"
  TSHARK_PID=""
else
  sudo -n true 2>/dev/null || echo "[note] tshark may prompt for sudo password."
  sudo tshark -i "$IFACE" -w "$PCAP" >/tmp/tshark.log 2>&1 &
  TSHARK_PID=$!
  sleep 1
fi

# Record short clip and toggle OSD OFF mid-recording
sudo ffmpeg -nostdin -hide_banner -loglevel error -y -f video4linux2 -i "$VIDEO" -t 6 "$VIDFILE" >/tmp/ffmpeg.log 2>&1 &
FFMPEG_PID=$!
sleep 2

# Flip OSD OFF while recording
TOOL=~/Desktop/project-vibe/C1_SONIX_Test_AP/SONiX_UVC_TestAP
"$TOOL" --vid 0x0c45 --pid 0x6366 --xu-osd=0 || true

wait $FFMPEG_PID || true

# Stop usb capture
if [ -n "${TSHARK_PID:-}" ]; then
  sudo kill "$TSHARK_PID" || true
  sleep 1
fi

# Parse to CSV and JSON
CSV=~/Desktop/project-vibe/intel/xu_osd_off.csv
JSON=~/Desktop/project-vibe/intel/xu_osd_off.json

sudo tshark -r "$PCAP" \
  -Y 'usb.setup.bmRequestType == 0x21 && usb.setup.bRequest == 0x01' \
  -T fields \
  -e frame.number -e frame.time_epoch \
  -e usb.bus_id -e usb.device_address \
  -e usb.setup.bmRequestType -e usb.setup.bRequest \
  -e usb.setup.wValue -e usb.setup.wIndex -e usb.setup.wLength \
  -e usb.capdata | tee "$CSV" || true

python3 - <<'PY'
import csv, json, os
csv_path=os.path.expanduser('~/Desktop/project-vibe/intel/xu_osd_off.csv')
rows=[]
with open(csv_path) as f:
    for line in f:
        row=line.rstrip('\n').split('\t')
        if not row or row==['']: continue
        row += [None]*10
        num, t, bus, dev, bmrt, breq, wval, widx, wlen, data = row[:10]
        try:
            frame=int(num)
            t=float(t)
        except Exception:
            continue
        rows.append(dict(frame=frame, t=t, bus=bus, dev=dev, bmRequestType=bmrt, bRequest=breq, wValue=wval, wIndex=widx, wLength=wlen, data_hex=data))
out=os.path.expanduser('~/Desktop/project-vibe/intel/xu_osd_off.json')
with open(out,'w') as f: json.dump(rows, f, indent=2)
print('[ok] wrote', out)
PY

# Extract screenshots (before/after)
ffmpeg -nostdin -hide_banner -loglevel error -y -ss 1.0 -i "$VIDFILE" -frames:v 1 "$BEFORE" || true
ffmpeg -nostdin -hide_banner -loglevel error -y -ss 5.0 -i "$VIDFILE" -frames:v 1 "$AFTER" || true

# Report
TS=$(date +%Y%m%d-%H%M%S)
LOG=~/Desktop/project-vibe/logs/${TS}_xu_osd_off.md
{
  echo "# XU Capture — OSD OFF ($TS)"
  echo "- PCAP: $PCAP"
  echo "- CSV : $CSV"
  echo "- JSON: $JSON"
  echo "- BEFORE PNG: $BEFORE"
  echo "- AFTER  PNG: $AFTER"
  echo
  echo "## Device"
  lsusb | sed -n '/0c45:6366/p'
  echo
  echo "## tshark - top lines"
  tshark -r "$PCAP" -c 5 -V | sed -n '1,80p'
  echo
  echo "## tshark -D (interfaces)"
  tshark -D | sed -n '1,120p'
  echo
  echo "## tshark.log"
  sed -n '1,200p' /tmp/tshark.log 2>/dev/null || true
  echo
  echo "## ffmpeg.log"
  sed -n '1,120p' /tmp/ffmpeg.log 2>/dev/null || true
} > "$LOG"
echo "[done] Log at $LOG"

# Mirror artifacts to Windows side as well
WIN_ROOT="/mnt/c/Users/arnax/Desktop/project-vibe"
mkdir -p "$WIN_ROOT/captures" "$WIN_ROOT/intel" "$WIN_ROOT/logs"
cp -f "$PCAP" "$WIN_ROOT/captures/" 2>/dev/null || true
cp -f "$VIDFILE" "$WIN_ROOT/captures/" 2>/dev/null || true
cp -f "$BEFORE" "$WIN_ROOT/captures/" 2>/dev/null || true
cp -f "$AFTER" "$WIN_ROOT/captures/" 2>/dev/null || true
cp -f "$CSV" "$WIN_ROOT/intel/" 2>/dev/null || true
cp -f "$JSON" "$WIN_ROOT/intel/" 2>/dev/null || true
cp -f "$LOG" "$WIN_ROOT/logs/" 2>/dev/null || true
echo "[done] Mirrored artifacts under $WIN_ROOT"


