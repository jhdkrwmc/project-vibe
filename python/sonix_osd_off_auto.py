# sonix_osd_off_auto.py
# Windows: auto-find Sonix UVC cam and switch off OSD via XU controls.
# Requires: pyusb, WinUSB driver bound to the VC interface (MI_00) via Zadig.

import sys, usb.core, usb.util, time

# Identifiers that don't change across your units (from your USB tree)
VID = 0x0C45  # Sonix
PID = 0x6366  # Product
PRODUCT_MATCH = "292A-IPC-OV2710"  # product string fingerprint

# UVC request constants
REQ_SET_CUR = 0x01
REQ_GET_CUR = 0x81
BMREQ_SET   = 0x21  # Class | Interface | Host-to-Device
BMREQ_GET   = 0xA1  # Class | Interface | Device-to-Host

# We’ll probe these XUs based on your descriptor (stable):
# Unit 3: bControlSize=3, many controls
# Unit 4: bControlSize=2, 16 controls
CANDIDATE_XUS = [
    {"unit_id": 3, "ctrl_size": 3, "ctrl_sel_range": range(1, 25)},  # 1..24
    {"unit_id": 4, "ctrl_size": 2, "ctrl_sel_range": range(1, 17)},  # 1..16
]

# Values to try for "OSD OFF" – safest first (all zeros), then a couple of common patterns
CANDIDATE_PAYLOADS = [
    None,               # auto: zeros of ctrl_size
    bytes([0x00, 0x00]),
    bytes([0x00, 0x00, 0x00]),
    bytes([0x00, 0x01]),           # some firmwares use boolean flip
    bytes([0x00, 0x00, 0x01]),     # ditto, 3-byte
]

def find_device():
    devs = list(usb.core.find(find_all=True, idVendor=VID, idProduct=PID))
    if not devs:
        print("[!] No 0x%04X:0x%04X devices found." % (VID, PID))
        sys.exit(1)

    for d in devs:
        try:
            # Strings can fail without WinUSB; best-effort
            prod = usb.util.get_string(d, d.iProduct) or ""
        except Exception:
            prod = ""
        if PRODUCT_MATCH.lower() in prod.lower():
            return d

    # fallback: first VID/PID match
    return devs[0]

def get_vc_interface_number(dev):
    # VC is the VideoControl interface (class 0x0E, subclass 0x01). Usually #0.
    cfg = dev.get_active_configuration()
    for intf in cfg:
        if intf.bInterfaceClass == 0x0E and intf.bInterfaceSubClass == 0x01:
            return intf.bInterfaceNumber
    # fallback to 0
    return 0

def xu_set_cur(dev, intf, unit_id, cs, payload):
    # UVC: wValue = (CS << 8) | 0
    #      wIndex = (UnitID << 8) | Interface
    wValue = (cs << 8) | 0x00
    wIndex = ((unit_id & 0xFF) << 8) | (intf & 0xFF)
    bmReq  = BMREQ_SET
    try:
        dev.ctrl_transfer(bmReq, REQ_SET_CUR, wValue, wIndex, payload, timeout=500)
        return True
    except usb.core.USBError as e:
        return False

def xu_get_cur(dev, intf, unit_id, cs, length):
    wValue = (cs << 8) | 0x00
    wIndex = ((unit_id & 0xFF) << 8) | (intf & 0xFF)
    bmReq  = BMREQ_GET
    try:
        return dev.ctrl_transfer(bmReq, REQ_GET_CUR, wValue, wIndex, length, timeout=500)
    except usb.core.USBError:
        return None

def main():
    dev = find_device()
    try:
        dev.set_configuration()
    except usb.core.USBError:
        pass

    # Try to detach any kernel driver on VC interface (some stacks need this)
    intf = get_vc_interface_number(dev)
    try:
        if dev.is_kernel_driver_active(intf):
            dev.detach_kernel_driver(intf)
    except Exception:
        pass

    print(f"[+] Using device: VID={VID:04X} PID={PID:04X}, VC interface={intf}")

    hits = []
    for xu in CANDIDATE_XUS:
        uid = xu["unit_id"]
        size = xu["ctrl_size"]
        print(f"[*] Probing XU unit {uid} (size={size})...")
        for cs in xu["ctrl_sel_range"]:
            # Decide payload
            for p in CANDIDATE_PAYLOADS:
                if p is None:
                    payload = bytes([0x00] * size)
                else:
                    if len(p) != size:
                        continue
                    payload = p

                ok = xu_set_cur(dev, intf, uid, cs, payload)
                if not ok:
                    continue

                # Small settle delay then read back (if supported)
                time.sleep(0.01)
                cur = xu_get_cur(dev, intf, uid, cs, size)
                curhex = cur.tobytes().hex() if cur is not None else "NA"
                print(f"    [+] SET_CUR ok: XU={uid} CS=0x{cs:02X} payload={payload.hex()} GET_CUR={curhex}")
                hits.append((uid, cs, payload))

                # Heuristic: stop after the first SET that “sticks” (GET returns same zeros) on 2–3 tries
                if cur is not None and (cur == payload or all(b == 0 for b in cur)):
                    print("    [✓] Candidate OSD-OFF found; keeping it.")
                    print("        If OSD still visible, re-run to try more selectors.")
                    print()
                    return 0

    if not hits:
        print("[!] No XU control accepted SET_CUR. Check WinUSB binding on VC interface (MI_00) via Zadig.")
        return 2

    print("[*] Tried multiple XU/CS combos but can’t confirm OSD state via GET_CUR. Check camera feed.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
