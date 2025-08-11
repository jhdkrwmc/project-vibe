# Post-Boot OSD Write Side Effects Analysis

## 1. OSD Write at 0x04D0 (USB ISR Path)

### Disassembly Context
```assembly
04C0: FF          MOV  R7,A
04C1: 12 C6 41    LCALL 0xC641          ; Call to USB handler
04C4: 90 10 0E    MOV  DPTR,#0x100E
04C7: E0          MOVX A,@DPTR
04C8: 44 08       ORL  A,#0x08
04CA: F0          MOVX @DPTR,A          ; Set bit 3 at 0x100E
04CB: 7F 01       MOV  R7,#0x01
04CD: 12 C5 6A    LCALL 0xC56A          ; Another USB-related call
04D0: 90 0B 77    MOV  DPTR,#0x0B77     ; OSD Control 2 Register
04D3: 74 01       MOV  A,#0x01
04D5: F0          MOVX @DPTR,A          ; OSD Enable Write
04D6: 22          RETI                  ; Return from interrupt
```

### Register Usage After OSD Write
- **A (Accumulator)**: 0x01 (not used after write)
- **DPTR**: 0x0B77 (not used after write)
- **R7**: 0x01 (from 0x04CB, used in LCALL at 0x04CD)

### Side Effect Analysis
- **A is not used** after the OSD write before being clobbered by RETI
- **DPTR is not used** after the OSD write
- **Safe to NOP** the MOVX instruction (0xF0) at 0x04D5

---

## 2. OSD Write at 0x0AC4 (Video Processing Path)

### Disassembly Context
```assembly
0AC0: C0 E0       PUSH ACC
0AC2: C0 D0       PUSH PSW
0AC4: 90 0B 76    MOV  DPTR,#0x0B76     ; OSD Control 1 Register
0AC7: 74 01       MOV  A,#0x01
0AC9: F0          MOVX @DPTR,A          ; OSD Enable Write
0ACA: 90 0B 80    MOV  DPTR,#0x0B80     ; OSD Character RAM
0ACD: 74 20       MOV  A,#0x20          ; Space character
0ACF: F0          MOVX @DPTR,A          ; Clear character
0AD0: A3          INC  DPTR
0AD1: 74 07       MOV  A,#0x07          ; White on black
0AD3: F0          MOVX @DPTR,A          ; Set attributes
0AD4: D0 D0       POP  PSW
0AD6: D0 E0       POP  ACC
0AD8: 22          RET
```

### Register Usage After OSD Write
- **A (Accumulator)**: 0x01 (immediately overwritten at 0x0ACD)
- **DPTR**: 0x0B76 (immediately overwritten at 0x0ACA)

### Side Effect Analysis
- **A is immediately overwritten** at 0x0ACD with 0x20
- **DPTR is immediately overwritten** at 0x0ACA with 0x0B80
- **Safe to NOP** the MOVX instruction (0xF0) at 0x0AC9

---

## 3. OSD Write at 0x0AFE (Timer ISR Path)

### Disassembly Context
```assembly
0AF0: C0 E0       PUSH ACC
0AF2: C0 D0       PUSH PSW
0AF4: C0 82       PUSH DPL
0AF6: C0 83       PUSH DPH
0AF8: 90 0D 60    MOV  DPTR,#0x0D60     ; OSD State Flag
0AFB: E0          MOVX A,@DPTR          ; Read OSD state
0AFC: 60 08       JZ   0x0B06           ; Skip if OSD disabled
0AFE: 90 0B 77    MOV  DPTR,#0x0B77     ; OSD Control 2 Register
0B01: 74 01       MOV  A,#0x01
0B03: F0          MOVX @DPTR,A          ; OSD Enable Write
0B04: 80 06       SJMP 0x0B0C
0B06: 90 0B 77    MOV  DPTR,#0x0B77     ; OSD Control 2 Register
0B09: E4          CLR  A
0B0A: F0          MOVX @DPTR,A          ; OSD Disable Write
0B0B: 00          NOP
0B0C: D0 83       POP  DPH
0B0E: D0 82       POP  DPL
0B10: D0 D0       POP  PSW
0B12: D0 E0       POP  ACC
0B14: 32          RETI
```

### Register Usage After OSD Write (0x0B03)
- **A (Accumulator)**: 0x01 (not used before being popped from stack)
- **DPTR**: 0x0B77 (not used before being popped from stack)

### Side Effect Analysis
- **A is not used** after the OSD write before being restored from stack
- **DPTR is not used** after the OSD write before being restored from stack
- **Safe to NOP** the MOVX instruction (0xF0) at 0x0B03

## Summary of Side Effects

| EA  | Register | Used After Write | Safe to NOP | Notes |
|-----|----------|-------------------|-------------|-------|
|04D5 | A        | No                | ✅ Yes      | Not used before RETI |
|04D5 | DPTR     | No                | ✅ Yes      | Not used before RETI |
|0AC9 | A        | No (immediate clobber) | ✅ Yes | Overwritten at 0x0ACD |
|0AC9 | DPTR     | No (immediate clobber) | ✅ Yes | Overwritten at 0x0ACA |
|0B03 | A        | No                | ✅ Yes      | Not used before stack restore |
|0B03 | DPTR     | No                | ✅ Yes      | Not used before stack restore |

**Conclusion**: All three OSD write sites are safe to patch by NOP'ing the MOVX instruction (0xF0) as the A and DPTR registers are either not used afterward or are immediately clobbered.
