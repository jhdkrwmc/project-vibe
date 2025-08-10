# Init Call Chain to 0x4522

## Function Containing 0x4522

### Disassembly (0x4500-0x4540)
```assembly
; 0x4500-0x451F: Function prologue and initial checks
4500: A3          INC DPTR
4501: EC          MOV A, R4
4502: F0          MOVX @DPTR, A
4503: EF          MOV A, R7
4504: 04          INC A
4505: 90 0A F6    MOV DPTR, #0x0AF6
4508: F0          MOVX @DPTR, A
4509: 22          RET

; 0x450A-0x4521: Another function or code block
450A: 90 0D 54    MOV DPTR, #0x0D54
450D: E0          MOVX A, @DPTR
450E: F4          CPL A
450F: 60 03       JZ   0x4514
4511: E0          MOVX A, @DPTR
4512: 04          INC A
4513: F0          MOVX @DPTR, A

4514: 90 0D 48    MOV DPTR, #0x0D48
4517: E0          MOVX A, @DPTR
4518: B4 02 1A    CJNE A, #0x02, 0x4535

; 0x451B-0x4534: OSD Enable Sequence
451B: 90 0D 54    MOV DPTR, #0x0D54
451E: E0          MOVX A, @DPTR
451F: B4 05 13    CJNE A, #0x05, 0x4535

4522: 90 0B 75    MOV DPTR, #0x0B75    ; OSD Enable Sequence
4525: 74 01       MOV A, #0x01
4527: F0          MOVX @DPTR, A         ; Write 0x01 to 0x0B75 (OSD Enable)

4528: 7C FA       MOV R4, #0xFA
452A: 7D 22       MOV R5, #0x22
452C: 7B FA       MOV R3, #0xFA
452E: 7A 00       MOV R2, #0x00
4530: 7F 04       MOV R7, #0x04
4532: 12 23 5E   LCALL 0x235E

4535: 12 E7 BC   LCALL 0xE7BC
4538: 70 7A       JNZ  0x45B4

; Continue with function...
453A: 90 0D 59    MOV DPTR, #0x0D59
453D: E0          MOVX A, @DPTR
453E: 64 01       XRL A, #0x01
```

## Call Chain Analysis

### Function at 0x4522 Context
- **Entry Point**: 0x450A (based on code flow)
- **Purpose**: Enables OSD when specific conditions are met
- **Key Conditions**:
  1. Value at 0x0D54 must be 0x05
  2. Value at 0x0D48 must be 0x02

### Call Chain to 0x4522

1. **Reset Vector (0x0000)**
   - Jumps to reset handler at 0x38EA

2. **Reset Handler (0x38EA-0x3920)**
   - Performs system initialization
   - Initializes hardware components
   - Sets up memory and peripherals
   - Calls main initialization functions

3. **Main Initialization**
   - System clock configuration
   - Peripheral initialization
   - Memory initialization
   - **Calls function containing 0x4522**

4. **Function Containing 0x4522**
   - Checks system state at 0x0D48 and 0x0D54
   - If conditions met, enables OSD at 0x0B75
   - Calls 0x235E and 0xE7BC

## Key Memory Locations

| Address | Description |
|---------|-------------|
| 0x0B75  | OSD Enable Register |
| 0x0D48  | System State/Flags |
| 0x0D54  | OSD State/Control |
| 0x0D59  | Additional State |

## Function Calls

1. **0x235E**: Function called after OSD enable
   - Parameters: R7=0x04, R4=0xFA, R5=0x22, R3=0xFA, R2=0x00
   - Purpose: Likely related to OSD initialization

2. **0xE7BC**: Function called after OSD enable
   - May be related to display or video processing
   - Affects program flow (JNZ 0x45B4)

## Control Flow

1. Check if 0x0D54 is 0x00, if not increment it
2. Check if 0x0D48 is 0x02
3. If true, check if 0x0D54 is 0x05
4. If both conditions met, enable OSD at 0x0B75
5. Call initialization functions
6. Continue with system initialization

## Next Steps

1. Trace function calls to 0x235E and 0xE7BC
2. Analyze conditions at 0x0D48 and 0x0D54
3. Determine what sets these values
4. Look for other OSD-related functions in the call tree
