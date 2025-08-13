import usb.core
import usb.util
import sys

# Hard-wired Sonix device details (adjust if needed)
VID = 0x0C45
PID = 0x6366
INTERFACE = 0  # VideoControl interface (MI_00)

# Sonix UVC Extension Unit constants (commonly used IDs)
XU_UNIT_ID = 0x0A
SEL_OE     = 0x0E  # OSD Show (Line/Block)
SEL_OAS    = 0x10  # OSD AutoShow?
SEL_TIMER  = 0x12  # OSD Timer

def send_xu(dev, selector, data):
    """Send UVC Extension Unit control data via SET_CUR"""
    request_type = usb.util.build_request_type(
        usb.util.CTRL_OUT,
        usb.util.CTRL_TYPE_CLASS,
        usb.util.CTRL_RECIP_INTERFACE
    )
    # UVC SET_CUR = 0x01
    dev.ctrl_transfer(
        request_type,
        0x01,  # SET_CUR
        (selector << 8) | XU_UNIT_ID,
        INTERFACE,
        data
    )

def main():
    # Find device
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        sys.exit(f"Device {VID:04X}:{PID:04X} not found. Make sure libusbK is bound to MI_00.")

    # Detach kernel driver if necessary
    if dev.is_kernel_driver_active(INTERFACE):
        dev.detach_kernel_driver(INTERFACE)

    usb.util.claim_interface(dev, INTERFACE)

    print("[*] Sending OSD disable sequence...")
    send_xu(dev, SEL_OE,    [0, 0])  # Disable OSD (Line=0, Block=0)
    send_xu(dev, SEL_OAS,   [0, 0])  # Disable AutoShow
    send_xu(dev, SEL_TIMER, [0])     # Disable Timer

    print("[+] OSD should now be gone.")

    usb.util.release_interface(dev, INTERFACE)
    dev.attach_kernel_driver(INTERFACE)
    print("[*] Done.")

if __name__ == "__main__":
    main()

