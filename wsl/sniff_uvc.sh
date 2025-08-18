#!/usr/bin/env bash
# Re-exec under bash if invoked via /bin/sh
[ -n "$BASH_VERSION" ] || exec bash "$0" "$@"
set -euo pipefail

VID="${VID:-0c45}"
PID="${PID:-6366}"
OUTDIR="${OUTDIR:-/mnt/c/Users/arnax/Desktop/project-vibe/wsl}"
TS="$(date +%Y%m%d_%H%M%S)"
BASE="$OUTDIR/usb_${VID}_${PID}_${TS}.pcapng"

log(){ echo "[sniff] $*"; }

command -v tshark >/dev/null || { echo "tshark not found (sudo apt install -y tshark)"; exit 1; }
sudo -v >/dev/null || { echo "need sudo rights"; exit 1; }

log "loading usbip client + uvc + usbmon and mounting debugfs"
sudo modprobe vhci-hcd 2>/dev/null || true
sudo modprobe uvcvideo 2>/dev/null || true
sudo modprobe usbmon
sudo mount -t debugfs none /sys/kernel/debug 2>/dev/null || true

CAM_LINE="$(lsusb -d ${VID}:${PID} | head -n1 || true)"
if [[ -z "$CAM_LINE" ]]; then
  echo "camera ${VID}:${PID} not found in WSL. attach it from Windows:"
  echo "  usbipd list"
  echo "  usbipd attach --wsl --busid <BUSID> --auto-attach"
  exit 1
fi
BUS="$(sed -E 's/^Bus[[:space:]]+0*([0-9]+).*/\1/' <<<"$CAM_LINE")"
DEV="$(sed -E 's/.*Device[[:space:]]+0*([0-9]+):.*/\1/' <<<"$CAM_LINE")"
IF="usbmon${BUS}"; [[ -e "/sys/kernel/debug/usb/usbmon/${BUS}u" ]] || IF="usbmon0"

mkdir -p "$OUTDIR"
log "found ${VID}:${PID} on Bus=$BUS Dev=$DEV"
log "capturing on $IF  ->  $BASE (ring: 10 x 50MB)"
sudo tshark -i "$IF" -b filesize:50 -b files:10 -w "$BASE" &
CAP_PID=$!
log "tshark PID=$CAP_PID — press ENTER to stop"
read -r _
sudo kill "$CAP_PID" 2>/dev/null || true
wait "$CAP_PID" 2>/dev/null || true
sync

log "done. recent files:"
ls -lh "${BASE%*.pcapng}"* 2>/dev/null | tail -n 10

echo "Wireshark filters:"
echo "  usb.bus_id == $BUS && usb.device_address == $DEV && usb.transfer_type == 0"
echo "  usb.transfer_type == 0 && usb.bmRequestType.type == 1"
