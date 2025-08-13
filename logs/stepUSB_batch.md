# Step USB Batch Results
Date: 2025-01-27

## Variants Tested

- fw_osd_off.bin: Device enumerates as 0C45:6366, Code 10. Current Config = 0. Not configured. Tail untouched.
- fw_osd_off_bypass.bin: Device enumerates as 0C45:6366, Code 10. Looks closer to stock: full descriptors visible, still not configured.
- fw_osd_off_crc_fixed.bin: Device enumerates as 0C45:6366, Code 10. Footer checksum written (5F 3C LE). No improvement.

## Observations (from USB dumps)
- Both patched variants show High-Speed, UVC 1.00, and full VC/VS descriptors.
- Windows flags UVC 1.0 descriptor inconsistencies (Frame-Based/H264 not allowed for UVC 1.0). Stock may tolerate similar quirks.
- Current Configuration remains 0 (host did not SetConfiguration), consistent with CM_PROB_FAILED_START.

## Interpretation
- OSD-only and footer checksum changes do not impact USB start; integrity gating likely still active.
- Bypass variant improves enumeration (descriptors visible) but host still refuses configuration; further runtime checks likely trip later.

## Next Investigation Steps
- Trace early integrity flow (0x01C0..0x0220) and failure LJMP target at 0xA4BD to identify later compare/branch gates.
- Enumerate additional compare sites (cjne/subb → jz/jnz) across code; prioritize those reading 0x0B75/0x0B76/0x0B77/0x0BA5.
- Prepare Stage-2 bypass targeting the later gate if confirmed, with minimal 1–2 byte flips.

## Recovery Mode (SPI flash held to ground)
- USB VID:PID = 0x0C45:0x6362 (recovery/bootloader-like)
- Config loads, descriptors present, shows a single uncompressed 640x480 mode
- Windows Camera app: No image despite mode listing
- Interpretation: ROM ISP mode enumerates but does not stream; usable for reflashing only

## USB dumps this round
- usbtree stage2_bypass_only_crc_fixed.txt: 0C45:6366, Code 10, Config=0 (no image)
- usbtree fw_late_clear_crc_fixed.txt: 0C45:6366, Code 10, Config=0 (no image)
- usbdevicetreeview after fw_osd_off flash .txt: 0C45:6366, Code 10, Config=0
- usbdevicetreeV6_BYPASS_ONLY.txt: 0C45:6366, Code 10, Config=0
- usbdevicetree.fw_osd_off_bypass.txt: 0C45:6366, Code 10, descriptors richer but still not configured
- usbtreeview with stock fw.txt: baseline OK (enumerates and functions)
- usbdevicetree recovery mode with spi flash to ground.txt: 0x0C45:0x6362 recovery, enumerates, no image (reflash path only)
- usbtree fw_v7_early_bypass_crc_fixed.txt: 0C45:6366, Code 10, Config=0, Device Address 0x31
- usbtree fw_integrity_bypass_no_checksum.txt: 0C45:6366, Code 10, Config=0, Device Address 0x37

## Results Summary

**V7_EARLY_BYPASS (fw_v7_early_bypass_crc_fixed.bin)**:
- **Strategy**: OSD disable + early compare site bypass (0x0245, 0x025F, 0x0289)
- **Patches Applied**: 7 bytes total (4 OSD + 3 early conditional flips)
- **Result**: Code 10, Config=0 - same failure pattern as other variants
- **Device Address**: 0x31 (49) - different from previous tests
- **Analysis**: Early conditional bypass at 0x023E/0x025A/0x0283 did not resolve the issue

**INTEGRITY_BYPASS (fw_integrity_bypass_no_checksum.bin)**:
- **Strategy**: OSD disable + integrity check logic bypass (0x0244, 0x0260)
- **Patches Applied**: 6 bytes total (4 OSD + 2 integrity check value changes)
- **Result**: Code 10, Config=0 - same failure pattern as all variants
- **Device Address**: 0x37 (55) - different from previous tests
- **Analysis**: Bypassing the integrity check logic itself did not resolve the issue

**Pattern Analysis**:
- All variants (OSD-only, bypass, stage2, late-clear, early-bypass, integrity-bypass) result in Code 10
- Device enumerates but fails to configure (Config=0)
- Stock firmware works, recovery mode works
- Issue appears to be deeper than the integrity checks we've identified

**Critical Finding**: Even bypassing the integrity check logic itself (changing expected values from 0x01/0x84 to 0x00) did not resolve the Code 10 error. This suggests there are additional integrity validation mechanisms beyond what we've analyzed.
