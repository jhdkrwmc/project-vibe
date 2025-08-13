# SN9C292B Firmware - OSD Enable Sites

## Canonical OSD-Enable Sites Table

| file_off | ea   | target | bytes (hex)                        | function/context | init-path? | A=0x01 intact |
|----------|------|--------|------------------------------------|------------------|------------|----------------|
| 0x04D0   | 0x04D0 | 0x0B77 | 90 0B 77 74 01 F0 22 90 0F 08 EF | (no func)        | No         | Yes            |
| 0x0AC4   | 0x0AC4 | 0x0B76 | 90 0B 76 74 01 F0 22 F0 90 11 52 | (no func)        | No         | Yes            |
| 0x0AFE   | 0x0AFE | 0x0B77 | 90 0B 77 74 01 F0 22 90 0B A5 E0 | (no func)        | No         | Yes            |
| 0x4522   | 0x4522 | 0x0B75 | 90 0B 75 74 01 F0 7C FA 7D 22 7B | (no func)        | Yes        | Yes            |

## Site Details

### Site 1: 0x04D0
- **File Offset:** 0x04D0
- **EA:** 0x04D0
- **Target:** 0x0B77 (OSD control register)
- **Bytes:** `90 0B 77 74 01 F0 22 90 0F 08 EF`
- **Context:** Standalone code block, not part of a defined function
- **Init Path:** Not on the main initialization path
- **A=0x01 Intact:** Yes, `MOV A, #0x01` is immediately before `MOVX @DPTR, A`

### Site 2: 0x0AC4
- **File Offset:** 0x0AC4
- **EA:** 0x0AC4
- **Target:** 0x0B76 (OSD control register)
- **Bytes:** `90 0B 76 74 01 F0 22 F0 90 11 52`
- **Context:** Standalone code block, not part of a defined function
- **Init Path:** Not on the main initialization path
- **A=0x01 Intact:** Yes, `MOV A, #0x01` is immediately before `MOVX @DPTR, A`

### Site 3: 0x0AFE
- **File Offset:** 0x0AFE
- **EA:** 0x0AFE
- **Target:** 0x0B77 (OSD control register)
- **Bytes:** `90 0B 77 74 01 F0 22 90 0B A5 E0`
- **Context:** Standalone code block, not part of a defined function
- **Init Path:** Not on the main initialization path
- **A=0x01 Intact:** Yes, `MOV A, #0x01` is immediately before `MOVX @DPTR, A`

### Site 4: 0x4522
- **File Offset:** 0x4522
- **EA:** 0x4522
- **Target:** 0x0B75 (OSD control register)
- **Bytes:** `90 0B 75 74 01 F0 7C FA 7D 22 7B`
- **Context:** Part of a larger initialization routine
- **Init Path:** Yes, called during system initialization
- **A=0x01 Intact:** Yes, `MOV A, #0x01` is immediately before `MOVX @DPTR, A`

## Summary

- All four OSD enable sites follow the same pattern: `MOV DPTR, #0x0B7x` followed by `MOV A, #0x01` and `MOVX @DPTR, A`.
- Only the site at 0x4522 is on the main initialization path.
- The accumulator (A) is loaded with 0x01 immediately before the `MOVX @DPTR, A` instruction in all cases.
- The targets are consecutive bytes in the OSD control window (0x0B75, 0x0B76, 0x0B77).
