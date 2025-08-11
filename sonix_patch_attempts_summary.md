# Sonix Firmware Patching — Attempts Summary (from 3 TXT files)

> Scope: This file extracts only the information relevant to **attempts at patching the firmware** from three notes:  
> `previouse attempts.txt`, `prev attempts 2.txt`, and `prev attemts 3.txt`. It is meant to serve as a compact, structured base for the next iteration of patching.

---

## 1) Goal (as stated in notes)
- **Disable OSD permanently at boot** (overlay/date resets to 2013 after power cycle).
- Secondary: be able to **unbrick** devices if a patch goes wrong.
- Convenience: get a **Windows-native read** path for SPI flash (no WSL).

## 2) Tools / Inputs already used
- **IDA Pro** (8051/8032) — firmware disassembly and code/ASM dumps.
- **Kurokesu C1_SONIX_Test_AP** — used to read SPI via `--sf-r` and to toggle OSD via XU controls.
- **USB Tree Viewer** reports compared with UltraCompare (working vs bricked units).
- **Known-good firmware dump** exists (baseline for patching & recovery).
- Reference repos mentioned:
  - `Kurokesu/C1_SONIX_Test_AP` (UVC/XU + SPI read utility).
  - `jhdkrwmc/sonix_flasher` (reverse of Windows flasher; ROM bootloader path).
  - `SonixQMK/sonix-flasher` (keyboard MCUs; noted as likely not applicable).

## 3) Confirmed patch candidates (from notes)
Purpose: neutralize boot-time OSD enable by changing the immediate written to 0x0B7x registers.

- Pattern in firmware: `90 0B 7x 74 01 F0`  
  (= `MOV DPTR,#0x0B7x ; MOV A,#0x01 ; MOVX @DPTR,A`)

- Four sites captured (flip **01** → **00** only):

| File offset (hex) | Target reg | Original bytes                 | Patched bytes                 |
|-------------------|------------|--------------------------------|-------------------------------|
| 0x000004D0        | 0x0B77     | `90 0B 77 74 01 F0`            | `90 0B 77 74 00 F0`           |
| 0x00000AC4        | 0x0B76     | `90 0B 76 74 01 F0`            | `90 0B 76 74 00 F0`           |
| 0x00000AFE        | 0x0B77     | `90 0B 77 74 01 F0`            | `90 0B 77 74 00 F0`           |
| 0x00004522        | 0x0B75     | `90 0B 75 74 01 F0`            | `90 0B 75 74 00 F0`           |

Notes:
- These are boot-time writes into the **0x0B75–0x0B77** block (OSD control cluster).
- Other writes near 0x0B77 (e.g., values like 0x19/0x1A/0x1B) appear to be runtime mode values; not required to change for “OSD off by default.”

## 4) Results / Observations from past attempts
- **Bricking events occurred** after flashing patched binaries; USB enumerations differed vs working units (seen in USB Tree Viewer compares).  
- Changing immediates in the **0x1400–0x14FF** area was noted to **brick** the device.  
- Touching the **0x0B77** write in the wrong context sometimes led to **partial/USB init issues** (“half-brick”).  
- Working baseline (`firmware_backup.bin`) and patched variants were kept; hashing/verification was flagged as important for clean reads/writes.

## 5) Known working controls (runtime, not persistent)
- OSD can be disabled **at runtime** with XU:
  - `--xuset-os 0 0` and `--xuset-oe 0 0` (but **reverts after power cycle**).
- SPI flash can be **read** in chunks using `--sf-r` (used to produce dumps).

## 6) Constraints / Risks captured
- Patching literal pools / init blocks in the **0x1400–0x14FF** region is dangerous; avoid unless fully mapped.
- Mis-flashed images led to descriptor/USB issues (Code 10 style), hence the emphasis on:
  - **Byte-exact size** (128 KiB).
  - **Repeatable hashes** for dumps and post-flash readback.
- Some units ended in a recoverable state (bootloader likely present), indicating recovery is feasible via the official flasher or direct SPI.

## 7) Open items (for next plan)
- Validate whether **only** the four 01→00 flips are sufficient on all units (cross-test against multiple cams).
- If bricks persist, capture **USB enumeration** after failed flash to confirm bootloader vs garbled runtime.
- For Windows-only workflow: finish/confirm a **native SPI read** path (UVC XU or ROM bootloader).

## 8) Minimal patch set to try next (from notes)
- Apply **only** the four immediate flips listed in section 3 to a clean, hash-verified dump.
- Flash, power-cycle, and verify:
  - OSD stays off after boot,
  - Device enumerates with correct VID/PID and UVC interfaces,
  - Post-flash **readback** equals patched file byte-for-byte.

---

*Prepared automatically from the three note files; no extra sources added here.*
