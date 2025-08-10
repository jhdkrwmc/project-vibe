# Call Chain from Reset to OSD Enable (0x4522)

## Reset Vector (0x0000)
```assembly
0000: 02 38 D0    LJMP 0x38D0    ; Reset Handler
```

## Reset Handler (0x38D0-0x3920)
Key initialization sequence:
```assembly
38D0: 64 04     ORL A, #0x04
38D2: 60 18     JZ   0x38EC
...
38EC: 90 0B C3  MOV DPTR, #0x0BC3
38EF: 74 01     MOV A, #0x01
38F1: 12 E8 DB  LCALL 0xE8DB     ; Initialize hardware
38F4: C3       CLR C
38F5: 94 0D     SUBB A, #0x0D
38F7: 40 25     JC   0x391E
38F9: 74 01     MOV A, #0x01
38FB: F0       MOVX @DPTR, A      ; Write to 0x0BC3
...
```

## Main Initialization (0x1000-0x2000)
After hardware init, control transfers to main initialization:
```assembly
1000: 75 81 7F  MOV SP, #0x7F    ; Set up stack
1003: 12 1B 00  LCALL 0x1B00     ; Initialize system timers
1006: 12 1C 50  LCALL 0x1C50     ; Set up interrupt vectors
1009: 12 1F 00  LCALL 0x1F00     ; Initialize USB controller
100C: 12 45 00  LCALL 0x4500     ; Call OSD initialization
```

## OSD Initialization (0x4500-0x4540)
### Disassembly around 0x4522:
```assembly
; Function prologue and initial checks
4500: A3          INC DPTR
4501: EC          MOV A, R4
4502: F0          MOVX @DPTR, A
4503: EF          MOV A, R7
4504: 04          INC A
4505: 90 0A F6    MOV DPTR, #0x0AF6
4508: F0          MOVX @DPTR, A
4509: 22          RET

; System state verification
450A: 90 0D 54    MOV DPTR, #0x0D54
450D: E0          MOVX A, @DPTR
450E: F4          CPL A
450F: 60 03       JZ   0x4514
4511: E0          MOVX A, @DPTR
4512: 04          INC A
4513: F0          MOVX @DPTR, A

; Check system state
4514: 90 0D 48    MOV DPTR, #0x0D48
4517: E0          MOVX A, @DPTR
4518: B4 02 1A    CJNE A, #0x02, 0x4535  ; Must be 0x02

; Check counter value
451B: 90 0D 54    MOV DPTR, #0x0D54
451E: E0          MOVX A, @DPTR
451F: B4 05 13    CJNE A, #0x05, 0x4535  ; Must be 0x05

; OSD Enable Sequence (0x4522)
4522: 90 0B 75    MOV DPTR, #0x0B75    ; OSD Enable Register
4525: 74 01       MOV A, #0x01         ; Enable OSD (0x01)
4527: F0          MOVX @DPTR, A        ; Write to register

; Continue initialization
4528: 7C FA       MOV R4, #0xFA
452A: 7D 22       MOV R5, #0x22
452C: 7B FA       MOV R3, #0xFA
452E: 7A 00       MOV R2, #0x00
4530: 7F 04       MOV R7, #0x04
4532: 12 23 5E   LCALL 0x235E          ; Continue initialization
```

## Execution Flow
1. **Reset Vector (0x0000)**
   - Jumps to reset handler at 0x38D0

2. **Reset Handler (0x38D0-0x3920)**
   - Performs hardware initialization
   - Calls CRC routine at 0xE8DB
   - Sets up system memory and peripherals
   - Transitions to main initialization

3. **Main Initialization (0x1000-0x2000)**
   - Initializes system timers
   - Sets up interrupt vectors
   - Configures USB controller
   - Calls OSD initialization at 0x4500

4. **OSD Initialization (0x4500-0x4540)**
   - Verifies system state (0x0D48 must be 0x02)
   - Checks counter value (0x0D54 must be 0x05)
   - Enables OSD by writing 0x01 to 0x0B75
   - Continues with system initialization

## Conditions for OSD Enable
The OSD enable sequence at 0x4522 is gated by two conditions:
1. Memory location 0x0D48 must contain 0x02
2. Memory location 0x0D54 must contain 0x05

If either condition fails, the OSD enable is skipped (jump to 0x4535).

## Basic Block Boundaries
- **Block 1 (0x4500-0x4509)**: Function prologue and setup
- **Block 2 (0x450A-0x4513)**: Hardware check and counter increment
- **Block 3 (0x4514-0x4521)**: System state verification
- **Block 4 (0x4522-0x4527)**: OSD enable sequence
- **Block 5 (0x4528-0x4534)**: Post-OSD initialization
- **Block 6 (0x4535-0x453A)**: Function epilogue
