#!/usr/bin/env python3
"""
Verify firmware files to identify corruption issues
"""

def verify_firmware():
    # Check original firmware
    with open('firmware_backup - Copy (4).bin', 'rb') as f:
        original = f.read()
    
    print(f"Original firmware size: {len(original):#x}")
    print(f"Original firmware first 16 bytes: {' '.join(f'{b:02X}' for b in original[:16])}")
    print(f"Original firmware last 16 bytes: {' '.join(f'{b:02X}' for b in original[-16:])}")
    
    # Check OSD patterns in original
    print("\nOSD patterns in original firmware:")
    print(f"0x04D0-0x04D5: {' '.join(f'{original[i]:02X}' for i in range(0x04D0, 0x04D6))}")
    print(f"0x0AC4-0x0AC9: {' '.join(f'{original[i]:02X}' for i in range(0x0AC4, 0x0ACA))}")
    print(f"0x0AFE-0x0B03: {' '.join(f'{original[i]:02X}' for i in range(0x0AFE, 0x0B04))}")
    print(f"0x4522-0x4527: {' '.join(f'{original[i]:02X}' for i in range(0x4522, 0x4528))}")
    
    # Check generated variant
    try:
        with open('out/fw_single_flip_04D4.bin', 'rb') as f:
            patched = f.read()
        
        print(f"\nPatched firmware size: {len(patched):#x}")
        print(f"Patched firmware first 16 bytes: {' '.join(f'{b:02X}' for b in patched[:16])}")
        print(f"Patched firmware last 16 bytes: {' '.join(f'{b:02X}' for b in patched[-16:])}")
        
        print("\nOSD patterns in patched firmware:")
        print(f"0x04D0-0x04D5: {' '.join(f'{patched[i]:02X}' for i in range(0x04D0, 0x04D6))}")
        print(f"0x0AC4-0x0AC9: {' '.join(f'{patched[i]:02X}' for i in range(0x0AC4, 0x0ACA))}")
        print(f"0x0AFE-0x0B03: {' '.join(f'{patched[i]:02X}' for i in range(0x0AFE, 0x0B04))}")
        print(f"0x4522-0x4527: {' '.join(f'{patched[i]:02X}' for i in range(0x4522, 0x4528))}")
        
        # Check if patches were applied
        print(f"\nPatch verification:")
        print(f"0x04D4: original={original[0x04D4]:02X}, patched={patched[0x04D4]:02X}")
        print(f"0x0AC8: original={original[0x0AC8]:02X}, patched={patched[0x0AC8]:02X}")
        print(f"0x0B02: original={original[0x0B02]:02X}, patched={patched[0x0B02]:02X}")
        print(f"0x4526: original={original[0x4526]:02X}, patched={patched[0x4526]:02X}")
        
    except FileNotFoundError:
        print("Patched firmware not found")

if __name__ == "__main__":
    verify_firmware() 