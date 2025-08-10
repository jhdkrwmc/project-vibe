# SN9C292B Firmware OSD Enable Instruction Analysis

## Notes
- Target: Sonix SN9C292B webcam SoC (8032), 128 KiB firmware.
- OSD control window: XDATA at 0x0B75–0x0B77; boot code sets to 0x01.
- Search for exact byte sequences (MOV DPTR, MOV A, MOVX @DPTR,A) for addresses 0x0B75, 0x0B76, 0x0B77.
- Only locate and confirm instructions; do not modify firmware.
- Four expected sites: 0x4D0, 0xAC4, 0xAFE, 0x4522.

## Task List
- [ ] Locate the SN9C292B firmware binary file.
- [ ] Search for each OSD enable instruction sequence in the binary.
- [ ] For each hit, report file offset, EA, target, bytes, function/context, and init-path.
- [ ] Cross-check if A is loaded with 0x01 immediately before MOVX and not altered.
- [ ] De-duplicate aliases and list unique sites.
- [ ] Confirm presence of expected sites or explain any differences.
- [ ] Deliver findings in a compact table and short notes to Untitled-1.

## Current Goal
Locate the firmware binary file.