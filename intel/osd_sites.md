# OSD Sites - Confirmed OSD Enable Sequences

## Pattern: 90 0B ?? 74 01 F0 (MOVX @DPTR, A)

| File Offset | EA | Target | 32B Context | Function | Reset Path |
|-------------|----|---------|-------------|----------|------------|
| 0x04D0 | 0x04D0 | 0x0B77 | 90 0B 77 74 01 F0 22 90 0F 08 EF F0 90 0F 08 E0 | (no func) | unknown |
| 0x0AC4 | 0x0AC4 | 0x0B76 | 90 0B 76 74 01 F0 22 F0 90 11 52 E0 75 F0 10 A4 | (no func) | unknown |
| 0x0AFE | 0x0AFE | 0x0B77 | 90 0B 77 74 01 F0 22 90 0B A5 E0 54 90 22 CE A2 | (no func) | unknown |
| 0x4522 | 0x4522 | 0x0B75 | 90 0B 75 74 01 F0 7C FA 7D 22 7B FA 7A 00 7F 04 | code_C01C | unknown |

## Analysis Notes

- **Total Sites Found**: 4
- **Pattern Confirmed**: All sites follow the exact sequence `90 0B ?? 74 01 F0`
- **Targets**: 0x0B75, 0x0B76, 0x0B77 (XDATA memory locations)
- **Function Coverage**: Only 0x4522 is within a function (code_C01C)
- **Reset Path**: Not yet analyzed - requires cross-reference analysis

## Next Steps

1. Analyze cross-references to determine reset path reachability
2. Examine the early code window 0x0190-0x0320 for multi-stage checks
3. Proceed to CRC/compare hunt for integrity bypass candidates
