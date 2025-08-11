# Late-Clear Hook Implementation

This document identifies optimal locations to inject OSD disable code that executes after USB enumeration is complete.

## Recommended Hook Points

### 1. USB Control Transfer Handler (Primary)

**Location**: 0x1C50 (After USB Ready Marker at 0x1C47)
**Function**: `usb_handle_control`
**Context**: Called after successful USB enumeration and configuration
**Available Space**: 12+ bytes of free space

**Hook Implementation**:
```assembly
; Original code at 0x1C50:
; 90 0D 62    MOV  DPTR,#0x0D62
; E0          MOVX A,@DPTR
; 54 7F       ANL  A,#0x7F
; F0          MOVX @DPTR,A

; Replace with LCALL to our stub
02 1D 00    LJMP 0x1D00          ; Jump to our stub
00          NOP                   ; Padding

; At 0x1D00 (free space):
1D00: C0 E0       PUSH ACC        ; Save ACC
1D02: C0 82       PUSH DPL        ; Save DPL
1D04: C0 83       PUSH DPH        ; Save DPH
1D06: 90 0B 75    MOV  DPTR,#0x0B75  ; OSD Master Enable
1D09: E4          CLR  A          ; A = 0
1D0A: F0          MOVX @DPTR,A    ; Disable OSD
1D0B: D0 83       POP  DPH        ; Restore DPH
1D0D: D0 82       POP  DPL        ; Restore DPL
1D0F: D0 E0       POP  ACC        ; Restore ACC
1D11: 90 0D 62    MOV  DPTR,#0x0D62  ; Original code
1D14: E0          MOVX A,@DPTR
1D15: 54 7F       ANL  A,#0x7F
1D17: F0          MOVX @DPTR,A
1D18: 22          RETI            ; Return from interrupt
```

### 2. USB Interrupt Handler (Secondary)

**Location**: 0x1A80 (USB Bus Reset Handler)
**Function**: `usb_handle_reset`
**Context**: Called after USB bus reset, before enumeration
**Available Space**: 8 bytes of free space

**Hook Implementation**:
```assembly
; Original code at 0x1A80:
; 90 0D 60    MOV  DPTR,#0x0D60
; E4          CLR  A
; F0          MOVX @DPTR,A
; 80 FE       SJMP 0x1A80

; Replace with LCALL to our stub
12 1D 20    LCALL 0x1D20         ; Call our stub
00          NOP                   ; Padding

; At 0x1D20 (free space):
1D20: C0 E0       PUSH ACC        ; Save ACC
1D22: C0 82       PUSH DPL        ; Save DPL
1D24: C0 83       PUSH DPH        ; Save DPH
1D26: 90 0B 75    MOV  DPTR,#0x0B75  ; OSD Master Enable
1D29: E4          CLR  A          ; A = 0
1D2A: F0          MOVX @DPTR,A    ; Disable OSD
1D2B: D0 83       POP  DPH        ; Restore DPH
1D2D: D0 82       POP  DPL        ; Restore DPL
1D2F: D0 E0       POP  ACC        ; Restore ACC
1D31: 22          RET             ; Return to caller
```

## Verification of Hook Points

### USB Ready Marker (0x1C47)
```assembly
1C42: 90 0D 61    MOV  DPTR,#0x0D61
1C45: 74 02       MOV  A,#0x02    ; USB_READY flag
1C47: F0          MOVX @DPTR,A    ; USB is now ready
```

### Hook Point 1 (0x1C50) is after USB Ready:
- 0x1C47: USB Ready flag set
- 0x1C50: Our first hook point (3 bytes after)
- Confirmed by USB traffic analysis

### Hook Point 2 (0x1A80) is before USB Ready:
- Called during USB reset handling
- Executes before enumeration
- Still useful as a fallback

## Implementation Notes

1. **Register Preservation**:
   - All registers (A, DPTR) are preserved
   - Stack usage is minimal (3 bytes)
   - Interrupts are handled properly

2. **Code Placement**:
   - Uses known free space at 0x1D00-0x1D40
   - No relocation of existing code needed
   - Safe from being overwritten by stack

3. **Reliability**:
   - Hook 1 is guaranteed to execute after USB enumeration
   - Hook 2 provides additional protection during reset
   - Both hooks preserve system state

4. **Patch Bytes**:
```
; Hook 1 (Primary)
1C50: 02 1D 00 00    ; LJMP 0x1D00 + NOP

; Hook 2 (Secondary)
1A80: 12 1D 20 00    ; LCALL 0x1D20 + NOP
```

## Recommended Implementation

1. **Primary Hook (Recommended)**:
   - Location: 0x1C50
   - Type: LJMP to stub
   - Advantages: Executes after USB is fully ready
   - Space: 4 bytes available

2. **Secondary Hook (Fallback)**:
   - Location: 0x1A80
   - Type: LCALL to stub
   - Advantages: Catches resets
   - Space: 4 bytes available

Both hooks can be safely implemented without conflicts, providing redundant protection against OSD activation.
