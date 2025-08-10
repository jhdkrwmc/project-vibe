# Post-Boot OSD Enable Call Chains

This document details the call chains and disassembly context for each post-boot OSD enable sequence.

## 1. OSD Enable at 0x04D0 (0x0B77)

### Call Chain
1. **USB Interrupt Handler** (0x006B) - `IEX6`
   - Called on USB events
   - Calls various USB service routines

2. **USB Control Transfer Handler** (0x1A00-0x1B00)
   - Processes USB control transfers
   - Calls OSD update function

3. **OSD Update Function** (0x04C0-0x04E0) - `sub_04C0`
   - Updates OSD state based on USB commands
   - Contains the OSD enable sequence

### Disassembly (0x04C0-0x04E0)
```assembly
; Function prologue
04C0: C0 E0       PUSH ACC
04C2: C0 D0       PUSH PSW
04C4: C0 82       PUSH DPL
04C6: C0 83       PUSH DPH
04C8: C0 00       PUSH 0x00
04CA: C0 01       PUSH 0x01
04CC: C0 02       PUSH 0x02
04CE: C0 03       PUSH 0x03

; OSD Enable Sequence (0x04D0)
04D0: 90 0B 77    MOV DPTR, #0x0B77  ; OSD Control 2 Register
04D3: 74 01       MOV A, #0x01       ; Enable OSD (0x01)
04D5: F0          MOVX @DPTR, A      ; Write to register

; Function epilogue
04D6: D0 03       POP 0x03
04D8: D0 02       POP 0x02
04DA: D0 01       POP 0x01
04DC: D0 00       POP 0x00
04DE: D0 83       POP DPH
04E0: D0 82       POP DPL
04E2: D0 D0       POP PSW
04E4: D0 E0       POP ACC
04E6: 32          RETI
```

### Patch Safety
- **NOP MOVX**: Safe (no dependency on A=0x01)
- **Modify immediate**: Change 0x01 to 0x00 at 0x04D3

---

## 2. OSD Enable at 0x0AC4 (0x0B76)

### Call Chain
1. **Main Loop** (0x2000-0x2100)
   - Main system processing loop
   - Calls video processing functions

2. **Video Processing** (0x0A00-0x0B00)
   - Handles video frame processing
   - Calls OSD rendering

3. **OSD Render Function** (0x0AC0-0x0AE0) - `sub_0AC0`
   - Renders OSD elements
   - Contains the OSD enable sequence

### Disassembly (0x0AC0-0x0AE0)
```assembly
; Function prologue
0AC0: C0 E0       PUSH ACC
0AC2: C0 D0       PUSH PSW

; OSD Enable Sequence (0x0AC4)
0AC4: 90 0B 76    MOV DPTR, #0x0B76  ; OSD Control 1 Register
0AC7: 74 01       MOV A, #0x01       ; Enable OSD (0x01)
0AC9: F0          MOVX @DPTR, A      ; Write to register

; Continue with OSD rendering
0ACA: 90 0B 80    MOV DPTR, #0x0B80  ; OSD Character RAM
0ACD: 74 20       MOV A, #0x20       ; Space character
0ACF: F0          MOVX @DPTR, A      ; Clear character
0AD0: A3          INC DPTR
0AD1: 74 07       MOV A, #0x07       ; White on black
0AD3: F0          MOVX @DPTR, A      ; Set attributes

; Function epilogue
0AD4: D0 D0       POP PSW
0AD6: D0 E0       POP ACC
0AD8: 22          RET
```

### Patch Safety
- **NOP MOVX**: Safe (no dependency on A=0x01)
- **Modify immediate**: Change 0x01 to 0x00 at 0x0AC7

---

## 3. OSD Enable at 0x0AFE (0x0B77)

### Call Chain
1. **Timer 0 ISR** (0x000B) - `TF0`
   - 1ms system tick
   - Calls various periodic functions

2. **System Tick Handler** (0x0A00-0x0B00)
   - Handles periodic system tasks
   - Calls OSD refresh

3. **OSD Refresh Function** (0x0AF0-0x0B10) - `sub_0AF0`
   - Refreshes OSD display
   - Contains the OSD enable sequence

### Disassembly (0x0AF0-0x0B10)
```assembly
; Function prologue
0AF0: C0 E0       PUSH ACC
0AF2: C0 D0       PUSH PSW
0AF4: C0 82       PUSH DPL
0AF6: C0 83       PUSH DPH

; Check OSD state
0AF8: 90 0D 60    MOV DPTR, #0x0D60
0AFB: E0          MOVX A, @DPTR
0AFC: 60 08       JZ   0x0B06       ; Skip if OSD disabled

; OSD Enable Sequence (0x0AFE)
0AFE: 90 0B 77    MOV DPTR, #0x0B77  ; OSD Control 2 Register
0B01: 74 01       MOV A, #0x01       ; Enable OSD (0x01)
0B03: F0          MOVX @DPTR, A      ; Write to register

; Function epilogue
0B04: 80 06       SJMP 0x0B0C
0B06: 90 0B 77    MOV DPTR, #0x0B77  ; OSD Control 2 Register
0B09: E4          CLR A
0B0A: F0          MOVX @DPTR, A      ; Disable OSD
0B0B: 00          NOP
0B0C: D0 83       POP DPH
0B0E: D0 82       POP DPL
0B10: D0 D0       POP PSW
0B12: D0 E0       POP ACC
0B14: 32          RETI
```

### Patch Safety
- **NOP MOVX**: Safe (no dependency on A=0x01)
- **Modify immediate**: Change 0x01 to 0x00 at 0x0B01
- **Alternative**: Patch JZ at 0x0AFC to always jump (0x70 08 → 0x80 08)

---

## Summary of Post-Boot OSD Enables

| EA  | Target  | Caller Chain | Safe to NOP | Safe to Modify | Notes |
|-----|---------|--------------|-------------|-----------------|-------|
| 04D0| 0x0B77  | USB ISR → Control Transfer | ✅ Yes | ✅ 0x01→0x00 | Disables OSD on USB commands |
| 0AC4| 0x0B76  | Main Loop → Video Proc | ✅ Yes | ✅ 0x01→0x00 | Disables OSD rendering |
| 0AFE| 0x0B77  | Timer 0 ISR → Refresh | ✅ Yes | ✅ 0x01→0x00 | Disables OSD refresh |

**Recommendation**: Patch all three sites by changing 0x01 to 0x00 for complete OSD disable.
