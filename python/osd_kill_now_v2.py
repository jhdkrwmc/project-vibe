# osd_kill_now_v2.py
import time, usb.core, usb.util

VID = 0x0C45
PID = 0x6366
XU_UNIT_ID = 0x0A
SEL_OE, SEL_OAS, SEL_TIMER = 0x0E, 0x10, 0x12

def open_dev():
    dev = None
    # retry a few times in case PnP is still settling
    for _ in range(10):
        dev = usb.core.find(idVendor=VID, idProduct=PID)
        if dev: break
        time.sleep(0.2)
    if dev is None:
        raise SystemExit("Device not found. Is MI_00 bound to libusbK on THIS PC?")
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
    bm, req = 0x21, 0x01
    wValue = ((selector & 0xFF) << 8) | (unit & 0xFF)
    wIndex = vc_if & 0xFF
    dev.ctrl_transfer(bm, req, wValue, wIndex, payload, timeout=timeout)

def main():
    dev = open_dev()
    vc = vc_interface(dev)
    usb.util.claim_interface(dev, vc)
    try:
        xu_set(dev, vc, XU_UNIT_ID, SEL_OE,    bytes([0,0]))
        time.sleep(0.05)
        xu_set(dev, vc, XU_UNIT_ID, SEL_OAS,   bytes([0,0]))
        time.sleep(0.05)
        xu_set(dev, vc, XU_UNIT_ID, SEL_TIMER, bytes([0]))
        print("OSD off sent.")
    finally:
        try: usb.util.release_interface(dev, vc)
        except Exception: pass

if __name__ == "__main__":
    main()
