# NOP Patch Safety Analysis for OSD Write Sites

This document evaluates the safety of replacing the `MOVX @DPTR,A` instructions with NOPs at each post-boot OSD enable site.

## 1. OSD Write at 0x04D5 (USB ISR Path)

### Instruction Context
```assembly
04D0: 90 0B 77    MOV  DPTR,#0x0B77     ; OSD Control 2 Register
04D3: 74 01       MOV  A,#0x01
04D5: F0          MOVX @DPTR,A          ; OSD Enable Write (Proposed NOP target)
04D6: 22          RETI
```

### NOP Safety Analysis
- **A Register**: 
  - Set to 0x01 at 0x04D3
  - Not used before being clobbered by RETI
  - **Impact**: Safe to NOP (no side effects from A=0x01)

- **DPTR Register**:
  - Set to 0x0B77 at 0x04D0
  - Not used before being clobbered by RETI
  - **Impact**: Safe to NOP (no side effects from DPTR=0x0B77)

- **Memory State**:
  - Location 0x0B77 won't be written with 0x01
  - **Impact**: Desired effect (prevents OSD enable)

**Verdict**: ✅ Safe to NOP at 0x04D5

## 2. OSD Write at 0x0AC9 (Video Processing Path)

### Instruction Context
```assembly
0AC4: 90 0B 76    MOV  DPTR,#0x0B76     ; OSD Control 1 Register
0AC7: 74 01       MOV  A,#0x01
0AC9: F0          MOVX @DPTR,A          ; OSD Enable Write (Proposed NOP target)
0ACA: 90 0B 80    MOV  DPTR,#0x0B80     ; OSD Character RAM
0ACD: 74 20       MOV  A,#0x20          ; Space character
```

### NOP Safety Analysis
- **A Register**:
  - Set to 0x01 at 0x0AC7
  - Immediately overwritten with 0x20 at 0x0ACD
  - **Impact**: Safe to NOP (value never used)

- **DPTR Register**:
  - Set to 0x0B76 at 0x0AC4
  - Immediately overwritten with 0x0B80 at 0x0ACA
  - **Impact**: Safe to NOP (value never used)

- **Memory State**:
  - Location 0x0B76 won't be written with 0x01
  - **Impact**: Desired effect (prevents OSD enable)

**Verdict**: ✅ Safe to NOP at 0x0AC9

## 3. OSD Write at 0x0B03 (Timer ISR Path)

### Instruction Context
```assembly
0AFE: 90 0B 77    MOV  DPTR,#0x0B77     ; OSD Control 2 Register
0B01: 74 01       MOV  A,#0x01
0B03: F0          MOVX @DPTR,A          ; OSD Enable Write (Proposed NOP target)
0B04: 80 06       SJMP 0x0B0C
...
0B0C: D0 83       POP  DPH
0B0E: D0 82       POP  DPL
0B10: D0 D0       POP  PSW
0B12: D0 E0       POP  ACC
0B14: 32          RETI
```

### NOP Safety Analysis
- **A Register**:
  - Set to 0x01 at 0x0B01
  - Not used before being restored from stack
  - **Impact**: Safe to NOP (value never used)

- **DPTR Register**:
  - Set to 0x0B77 at 0x0AFE
  - Not used before being restored from stack
  - **Impact**: Safe to NOP (value never used)

- **Memory State**:
  - Location 0x0B77 won't be written with 0x01
  - **Impact**: Desired effect (prevents OSD enable)

**Verdict**: ✅ Safe to NOP at 0x0B03

## Summary of NOP Safety

| EA  | Instruction | A Usage | DPTR Usage | Safe to NOP | Notes |
|-----|-------------|---------|------------|-------------|-------|
|04D5 | MOVX @DPTR,A| ❌ Unused | ❌ Unused | ✅ Yes | No side effects |
|0AC9 | MOVX @DPTR,A| 🔄 Clobbered | 🔄 Clobbered | ✅ Yes | Immediately overwritten |
|0B03 | MOVX @DPTR,A| ❌ Unused | ❌ Unused | ✅ Yes | No side effects |

**Overall Conclusion**: All three OSD write sites are safe to patch by replacing the `MOVX @DPTR,A` instruction (0xF0) with a NOP (0x00). This approach:

1. Prevents the OSD enable writes
2. Preserves all register states
3. Maintains the original control flow
4. Has no unintended side effects
