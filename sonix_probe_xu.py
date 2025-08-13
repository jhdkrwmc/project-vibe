# sonix_probe_xu.py - Probe Sonix UVC XU endpoints on Windows (WinUSB/libusbK)
# Finds working Unit ID and selectors by trying GET_CUR with small lengths.
import time, usb.core, usb.util

VID, PID = 0x0C45, 0x6366
CANDIDATE_UNITS     = [0x0A, 0x09, 0x0B, 0x0C]  # common Sonix XU unit IDs
CANDIDATE_SELECTORS = [0x0E, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16]
LENS_BY_SEL = {0x0E:2, 0x10:2, 0x11:2, 0x12:1, 0x13:2, 0x14:3, 0x15:3, 0x16:2}
RETRIES = 15

def open_dev():
    for _ in range(RETRIES):
        dev = usb.core.find(idVendor=VID, idProduct=PID)
        if dev: break
        time.sleep(0.2)
    if dev is None:
        raise SystemExit("Device not found. Ensure MI_00 is bound to WinUSB or libusbK.")
    try:
        dev.set_configuration()
    except Exception:
        pass
    return dev

def vc_interface(dev):
    for cfg in dev:
        for intf in cfg:
            if intf.bInterfaceClass == 0x0E and intf.bInterfaceSubClass == 0x01:
                return intf.bInterfaceNumber
    return 0

def xu_get(dev, vc_if, unit, selector, length, timeout=1000):
    bm, req = 0xA1, 0x81  # Dev->Host, Class, Interface; GET_CUR
    wValue = ((selector & 0xFF) << 8) | (unit & 0xFF)
    wIndex = vc_if & 0xFF
    return dev.ctrl_transfer(bm, req, wValue, wIndex, length, timeout=timeout)

def main():
    dev = open_dev()
    vc = vc_interface(dev)
    usb.util.claim_interface(dev, vc)
    print(f"[+] VC interface: {vc}")
    try:
        for unit in CANDIDATE_UNITS:
            for sel in CANDIDATE_SELECTORS:
                length = LENS_BY_SEL.get(sel, 2)
                try:
                    data = bytes(xu_get(dev, vc, unit, sel, length))
                    print(f"OK  unit=0x{unit:02X} sel=0x{sel:02X} len={length} -> {list(data)}")
                except Exception as e:
                    # Uncomment to see failures:
                    # print(f"NG  unit=0x{unit:02X} sel=0x{sel:02X} len={length} : {e}")
                    pass
    finally:
        try: usb.util.release_interface(dev, vc)
        except Exception: pass

if __name__ == "__main__":
    main()
'''

kill_code = r'''#!/usr/bin/env python3
# osd_kill_snx.py - Try the Ubuntu-proven OSD kill on Sonix (OE [0,1]), then fallbacks.
import time, usb.core, usb.util

VID, PID = 0x0C45, 0x6366
UNITS_TRY = [0x0A, 0x09, 0x0B]  # try these unit IDs in order
SEL_OE, SEL_OAS, SEL_TIMER = 0x0E, 0x10, 0x12

def open_dev():
    dev = None
    for _ in range(15):
        dev = usb.core.find(idVendor=VID, idProduct=PID)
        if dev: break
        time.sleep(0.2)
    if dev is None:
        raise SystemExit("Device not found. Ensure MI_00 is on WinUSB/libusbK and no app uses the cam.")
    try:
        dev.set_configuration()
    except Exception:
        pass
    return dev

def vc_interface(dev):
    for cfg in dev:
        for intf in cfg:
            if intf.bInterfaceClass == 0x0E and intf.bInterfaceSubClass == 0x01:
                return intf.bInterfaceNumber
    return 0

def xu_set(dev, vc_if, unit, selector, payload, timeout=1000):
    bm, req = 0x21, 0x01  # Host->Dev, Class, Interface; SET_CUR
    wValue = ((selector & 0xFF) << 8) | (unit & 0xFF)
    wIndex = vc_if & 0xFF
    return dev.ctrl_transfer(bm, req, wValue, wIndex, payload, timeout=timeout)

def try_sequence(dev, vc, unit):
    # First try the Ubuntu-observed pattern: OE=[0,1]
    # (line=0, block=1), then OAS=[0,0], TIMER=[0]
    try:
        xu_set(dev, vc, unit, SEL_OE,    bytes([0,1])); time.sleep(0.05)
        xu_set(dev, vc, unit, SEL_OAS,   bytes([0,0])); time.sleep(0.05)
        xu_set(dev, vc, unit, SEL_TIMER, bytes([0]))
        return True, f"unit=0x{unit:02X} used with OE=[0,1]"
    except Exception as e1:
        # fallback 1: OE=[0,0]
        try:
            xu_set(dev, vc, unit, SEL_OE,    bytes([0,0])); time.sleep(0.05)
            xu_set(dev, vc, unit, SEL_OAS,   bytes([0,0])); time.sleep(0.05)
            xu_set(dev, vc, unit, SEL_TIMER, bytes([0]))
            return True, f"unit=0x{unit:02X} used with OE=[0,0]"
        except Exception as e2:
            return False, f"unit=0x{unit:02X} failed: {e1}; fallback: {e2}"

def main():
    dev = open_dev()
    vc = vc_interface(dev)
    usb.util.claim_interface(dev, vc)
    try:
        for unit in UNITS_TRY:
            ok, msg = try_sequence(dev, vc, unit)
            if ok:
                print("[+] OSD-off sent:", msg)
                return
            else:
                print("[!] Try next:", msg)
        print("[-] All attempts failed. Run sonix_probe_xu.py to discover the correct unit/selector IDs.")
    finally:
        try: usb.util.release_interface(dev, vc)
        except Exception: pass

if __name__ == "__main__":
    main()
