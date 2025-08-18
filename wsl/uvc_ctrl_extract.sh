#!/usr/bin/env bash
# Extract UVC class-control (XU) traffic from a pcapng, decode wValue/wIndex, and copy to Windows.

set -euo pipefail

PCAP_RAW="${1:-/root/usb_sniff/20250813-193219/cam_00534_20250813193250.pcapng}"
OUTDIR="$(dirname "$PCAP_RAW")"
PCAP_CTRL="$OUTDIR/cam_control_only.pcapng"
CSV_RAW="$OUTDIR/cam_control_raw.csv"
CSV_DEC="$OUTDIR/cam_control_decoded.csv"

WIN_DIR="/mnt/c/Users/arnax/Desktop/project-vibe"

echo "[*] Source: $PCAP_RAW"
command -v tshark >/dev/null || { echo "tshark missing. sudo apt install -y tshark"; exit 1; }

# 1) Filter to ONLY class control transfers (UVC GET/SET live here)
echo "[*] Writing control-only pcap: $PCAP_CTRL"
tshark -r "$PCAP_RAW" \
  -Y 'usb.transfer_type == 0 && usb.bmRequestType.type == 1' \
  -w "$PCAP_CTRL"

# 2) Dump useful fields to CSV (direction, bRequest, wValue, wIndex, data)
echo "[*] Writing raw CSV: $CSV_RAW"
tshark -r "$PCAP_CTRL" -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e usb.bus_id \
  -e usb.device_address \
  -e usb.bmRequestType.direction \
  -e usb.bRequest \
  -e usb.wValue \
  -e usb.wIndex \
  -e usb.data_len \
  -e usb.capdata \
  -E header=y -E separator=, -E quote=d \
  > "$CSV_RAW"

# 3) Decode XU pieces:
#    wValue:  high=ControlSelector (CS),  low=Channel
#    wIndex:  high=EntityID,             low=InterfaceNumber
echo "[*] Decoding XU fields -> $CSV_DEC"
awk -F',' 'BEGIN{OFS=","}
NR==1{
  print $0,"cs","channel","entity_id","interface";
  next
}
{
  # columns (1-based): 1=frame,2=time,3=bus,4=dev,5=dir,6=bReq,7=wValue,8=wIndex,9=len,10=capdata
  wV = ($7==""?0:$7)+0;
  wI = ($8==""?0:$8)+0;
  cs = int(wV/256);      ch = wV%256;
  ent = int(wI/256);     ifn = wI%256;
  print $0,cs,ch,ent,ifn;
}' "$CSV_RAW" > "$CSV_DEC"

# 4) Copy to Windows
echo "[*] Copying to Windows: $WIN_DIR"
sudo mkdir -p "$WIN_DIR"
sudo cp -f "$PCAP_CTRL" "$CSV_RAW" "$CSV_DEC" "$WIN_DIR/"

echo "[*] Done."
echo "    Open in Windows:"
echo "      $WIN_DIR/$(basename "$PCAP_CTRL")"
echo "      $WIN_DIR/$(basename "$CSV_DEC")"
echo
echo "Wireshark display filters you’ll actually use:"
echo "  usb.transfer_type == 0 && usb.bmRequestType.type == 1                         # all class controls"
echo "  usb.bus_id == <B> && usb.device_address == <D> && usb.transfer_type == 0      # your device only"
echo "  usb.bmRequestType.direction == 0   # SET_* (Host→Device)"
echo "  usb.bmRequestType.direction == 1   # GET_* (Device→Host)"
