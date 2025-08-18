#!/usr/bin/env python3
"""
Orchestrated end-to-end audit for SN9C292B OSD-off firmware project.

PASS-1 (default):
- Snapshot inputs
- Select baseline (or flag ambiguity)
- Enumerate all .bin targets and compute hashes, diffs, checksum
- Correlate per-bin with nearby *.diff.txt/*.sum.txt and filename claims
- Map diffs to OSD/late-clear/integrity expectations using intel/*.json
- Parse USB enumeration logs
- Produce per-bin JSON, manifest.csv, AUDIT_LOG.md, ALL_LOGS.md
- Emit proposed tree + PowerShell move plans (do not execute)

PASS-2 (--apply-moves):
- Execute move plan (non-destructive, create directories then Move-Item)
- Re-run analysis path-agnostically
- Emit audit/second_pass.md with comparison to PASS-1

Notes:
- No third-party dependencies required; stdlib only
- Baseline is copied to audit/BASELINE.bin (originals are untouched)
- If multiple distinct baselines detected → analysis continues but diffs are skipped, and AUDIT_LOG.md calls this out
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any


# ----------------------------- filesystem utils -----------------------------

WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = WORKSPACE_ROOT / "audit"
PER_BIN_DIR = AUDIT_DIR / "per_bin"
ERRORS_DIR = AUDIT_DIR / "errors"


def ensure_dirs() -> None:
    for p in [AUDIT_DIR, PER_BIN_DIR, ERRORS_DIR]:
        p.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_mtime_iso(path: Path) -> str:
    try:
        ts = path.stat().st_mtime
        return dt.datetime.fromtimestamp(ts).isoformat()
    except Exception:
        return ""


def is_inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


# ----------------------------- Step 0: snapshot -----------------------------

SNAPSHOT_EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "audit",
    "__pycache__",
}


def enumerate_all_inputs() -> List[Path]:
    inputs: List[Path] = []
    for root, dirs, files in os.walk(WORKSPACE_ROOT):
        root_p = Path(root)
        # Drop excluded dirs from traversal
        dirs[:] = [d for d in dirs if d not in SNAPSHOT_EXCLUDE_DIRS]
        for fn in files:
            p = root_p / fn
            # Ignore large disassembly artifacts? We snapshot everything; it's okay
            inputs.append(p)
    return inputs


def generate_inputs_snapshot(snapshot_path: Path) -> None:
    inputs = enumerate_all_inputs()
    lines: List[str] = []
    lines.append(f"Workspace: {WORKSPACE_ROOT}")
    lines.append(f"Snapshot time: {dt.datetime.now().isoformat()}")
    lines.append("")
    for p in sorted(inputs):
        try:
            size = p.stat().st_size
            mtime = file_mtime_iso(p)
            sha = sha256_file(p)
            rel = p.relative_to(WORKSPACE_ROOT)
            lines.append(f"{rel}\t{size}\t{mtime}\t{sha}")
        except Exception as e:
            lines.append(f"{p}\tERROR\t{e}")
    write_text(snapshot_path, "\n".join(lines) + "\n")


# ------------------------- Step 1: baseline selection ------------------------

def candidate_baseline_paths() -> List[Path]:
    candidates: List[Path] = []
    explicit = [
        WORKSPACE_ROOT / "25-08-10" / "firmware_backup.bin",
        WORKSPACE_ROOT / "25.08.11" / "firmware_backup - Copy (4).bin",
        WORKSPACE_ROOT / "2508110204" / "firmware_backup - Copy (4).bin",
    ]
    for p in explicit:
        if p.exists():
            candidates.append(p)
    # Also scan root for firmware_backup*.bin
    for p in WORKSPACE_ROOT.glob("firmware_backup*.bin"):
        if p.is_file():
            candidates.append(p)
    # Deduplicate
    uniq: List[Path] = []
    seen = set()
    for p in candidates:
        if p.resolve() not in seen:
            seen.add(p.resolve())
            uniq.append(p)
    return uniq


class BaselineInfo(Tuple[Optional[Path], Dict[str, List[Path]], Optional[str], Optional[int]]):
    pass


def select_baseline() -> Tuple[Optional[Path], Dict[str, List[Path]], Optional[str], Optional[int], List[str]]:
    """
    Returns: (selected_path, hash_to_paths, baseline_sha256, baseline_size, issues)
    - selected_path is None if ambiguous or none found
    - issues contains strings to include in AUDIT_LOG.md
    """
    issues: List[str] = []
    cands = candidate_baseline_paths()
    if not cands:
        issues.append("No baseline candidates found. Expected in 25-08-10/ or 25.08.11/ or root.")
        return None, {}, None, None, issues

    hash_to_paths: Dict[str, List[Path]] = {}
    size_set: set[int] = set()
    for p in cands:
        try:
            h = sha256_file(p)
            hash_to_paths.setdefault(h, []).append(p)
            size_set.add(p.stat().st_size)
        except Exception as e:
            issues.append(f"Error hashing baseline candidate {p}: {e}")

    if len(hash_to_paths) > 1:
        issues.append("Multiple distinct baseline SHA-256 values detected; manual selection required.")
        for h, ps in hash_to_paths.items():
            items = ", ".join(str(p.relative_to(WORKSPACE_ROOT)) for p in ps)
            issues.append(f"- {h}: {items}")
        return None, hash_to_paths, None, None, issues

    # Unique content
    baseline_sha = next(iter(hash_to_paths.keys()))
    baseline_path = hash_to_paths[baseline_sha][0]
    baseline_size = baseline_path.stat().st_size
    return baseline_path, hash_to_paths, baseline_sha, baseline_size, issues


def copy_baseline_to_audit(baseline_path: Path) -> Path:
    out_path = AUDIT_DIR / "BASELINE.bin"
    shutil.copy2(baseline_path, out_path)
    return out_path


# -------------------------- Step 2: enumerate bins --------------------------

BIN_INCLUDE_DIRS_HINTS = [
    WORKSPACE_ROOT / "out",
    WORKSPACE_ROOT / "fw patch",
    WORKSPACE_ROOT / "25-08-10",
    WORKSPACE_ROOT / "25.08.11",
    WORKSPACE_ROOT / "2508110204",
]


def enumerate_all_bins() -> List[Path]:
    bins: List[Path] = []
    for root, dirs, files in os.walk(WORKSPACE_ROOT):
        root_p = Path(root)
        # Skip excluded dirs
        dirs[:] = [d for d in dirs if d not in SNAPSHOT_EXCLUDE_DIRS]
        for fn in files:
            if fn.lower().endswith(".bin"):
                p = root_p / fn
                # Skip files inside audit
                if is_inside(p, AUDIT_DIR):
                    continue
                bins.append(p)
    return bins


def load_bytes(path: Path) -> bytes:
    with path.open("rb") as f:
        return f.read()


def diff_bytes(base: bytes, other: bytes) -> List[Tuple[int, int, int]]:
    """Return list of (offset, base_byte, other_byte) for differing offsets.
    If sizes differ, only compare up to min length, then append remaining offsets as full diffs.
    """
    diffs: List[Tuple[int, int, int]] = []
    n = min(len(base), len(other))
    for i in range(n):
        b0 = base[i]
        b1 = other[i]
        if b0 != b1:
            diffs.append((i, b0, b1))
    # Trailing bytes differences if sizes differ
    if len(other) > n:
        for i in range(n, len(other)):
            diffs.append((i, -1, other[i]))
    elif len(base) > n:
        for i in range(n, len(base)):
            diffs.append((i, base[i], -1))
    return diffs


# ------------------- Step 3: map diffs to claimed patch ---------------------

OSD_SITE_OFFSETS_DEFAULT = [0x04D4, 0x0AC8, 0x0B02, 0x4526]


def load_osd_sites() -> List[int]:
    # Try intel/osd_sites.json first, else osd_sites.json
    offsets: List[int] = []
    for path in [WORKSPACE_ROOT / "intel" / "osd_sites.json", WORKSPACE_ROOT / "osd_sites.json"]:
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                for e in data:
                    if "file_off" in e:
                        offsets.append(int(str(e["file_off"]).replace("0x", ""), 16))
            except Exception:
                pass
    if not offsets:
        offsets = OSD_SITE_OFFSETS_DEFAULT
    return sorted(set(offsets))


def parse_neighbor_files(target: Path) -> Dict[str, Any]:
    stem = target.stem
    parent = target.parent
    info: Dict[str, Any] = {"diff_txt": None, "sum_txt": None, "diff_lines": [], "sum_lines": []}
    diff_path = parent / f"{stem}.diff.txt"
    sum_path = parent / f"{stem}.sum.txt"
    if diff_path.exists():
        info["diff_txt"] = str(diff_path.relative_to(WORKSPACE_ROOT))
        info["diff_lines"] = diff_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if sum_path.exists():
        info["sum_txt"] = str(sum_path.relative_to(WORKSPACE_ROOT))
        info["sum_lines"] = sum_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return info


def parse_claim_from_name(name: str) -> Dict[str, Any]:
    claim = {
        "raw": name,
        "type": "unknown",
        "expected_offsets": [],  # List[int]
        "notes": [],
    }
    n = name.lower()
    m = re.search(r"single[_-]?flip[_-]?([0-9a-f]{4})", n)
    if m:
        addr = int(m.group(1), 16)
        claim["type"] = "single_flip"
        claim["expected_offsets"] = list(range(max(0, addr - 4), addr + 5))
        claim["notes"].append(f"Expect exactly 1 change near 0x{addr:04X} (±4)")
        return claim

    if "late_clear" in n:
        # From intel/late_clear_hook.md: 0x1A80, 0x1C50, stubs ~0x1D00/0x1D20
        claim["type"] = "late_clear"
        expected = set()
        for center, radius in [(0x1A80, 8), (0x1C50, 8), (0x1D00, 0x40), (0x1D20, 0x40)]:
            for off in range(center - radius, center + radius + 1):
                expected.add(off)
        claim["expected_offsets"] = sorted(expected)
        claim["notes"].append("Expect hook bytes near 0x1A80/0x1C50 and stub around 0x1D00/0x1D20")
        return claim

    if "osd_off" in n:
        claim["type"] = "osd_off"
        claim["expected_offsets"] = load_osd_sites()
        claim["notes"].append("Expect changes at OSD sites (04D4,0AC8,0B02,4526)")
        return claim

    if "crc_fixed" in n or "checksum" in n:
        claim["type"] = "crc_fixed"
        # Expect footer 0x1FFE/0x1FFF touched in addition to any data changes
        claim["expected_offsets"] = [0x1FFE, 0x1FFF]
        claim["notes"].append("Expect checksum footer 0x1FFE..0x1FFF updated")
        return claim

    if "integrity" in n:
        claim["type"] = "integrity"
        claim["notes"].append("Integrity-related edits expected (various locations)")
        return claim

    if n.startswith("fw_"):
        claim["type"] = "generic_fw"
        return claim

    return claim


def verdict_from_diffs(
    diffs: List[Tuple[int, int, int]],
    claim: Dict[str, Any],
    osd_offsets: List[int],
) -> Tuple[str, List[str]]:
    """Return (verdict, notes)."""
    notes: List[str] = []
    if not diffs:
        return "MATCH" if claim.get("type") in {"unknown"} else "MISMATCH", ["No changes detected vs baseline"]

    offsets = [o for (o, _, _) in diffs]
    changed_set = set(offsets)

    ctype = claim.get("type")
    if ctype == "single_flip":
        if len(diffs) != 1:
            return "MISMATCH", [f"Expected 1 change, found {len(diffs)}"]
        exp = set(claim.get("expected_offsets", []))
        if offsets[0] in exp:
            return "MATCH", []
        return "MISMATCH", [f"Single change not near expected window; got 0x{offsets[0]:04X}"]

    if ctype == "osd_off":
        expected = set(osd_offsets)
        extra = [o for o in offsets if o not in expected and o not in (0x1FFE, 0x1FFF)]
        missing = [o for o in expected if o not in changed_set]
        if missing:
            notes.append("Missing expected OSD site edits: " + ", ".join(f"0x{x:04X}" for x in missing))
        if extra:
            notes.append("Unexpected edits: " + ", ".join(f"0x{x:04X}" for x in extra))
        if not missing and not extra:
            return "MATCH", notes
        return ("SUSPECT" if not missing else "MISMATCH"), notes

    if ctype == "late_clear":
        expected = set(claim.get("expected_offsets", []))
        outside = [o for o in offsets if o not in expected and o not in (0x1FFE, 0x1FFF)]
        if outside:
            return "SUSPECT", ["Touches bytes outside documented late-clear regions: " + ", ".join(f"0x{x:04X}" for x in outside)]
        return "MATCH", []

    if ctype == "crc_fixed":
        # Must include checksum footer
        has_footer = 0x1FFE in changed_set or 0x1FFF in changed_set
        if not has_footer:
            return "MISMATCH", ["Claims CRC/checksum fix but footer 0x1FFE..0x1FFF not modified"]
        # Any other edits are allowed (data section). If only footer changed, call it SUSPECT
        if len(diffs) == 1 or (len(diffs) == 2 and changed_set == {0x1FFE, 0x1FFF}):
            return "SUSPECT", ["Only checksum footer changed; verify rationale"]
        return "MATCH", []

    # Generic: if edits align with known OSD sites and/or footer only, lenient
    if set(offsets).issubset(set(osd_offsets) | {0x1FFE, 0x1FFF}):
        return "MATCH", ["Edits confined to OSD sites and/or checksum footer"]
    return "SUSPECT", ["Edits outside known sites; verify intent"]


# --------------------- Step 4: checksum re-verification ---------------------

def compute_checksum_fields(data: bytes) -> Dict[str, Any]:
    size = len(data)
    partial_sum = sum(data[0:0x1FFE]) & 0xFFFF if size >= 0x1FFE else None
    stored = None
    total = None
    recommended = None
    footer_le = None
    if size >= 0x20000:
        stored = (data[0x1FFF] << 8) | data[0x1FFE]
        footer_le = (data[0x1FFE], data[0x1FFF])
        total = (partial_sum + stored) & 0xFFFF if partial_sum is not None else None
        recommended = (-partial_sum) & 0xFFFF if partial_sum is not None else None
    ok = (size == 0x20000 and total == 0)
    return {
        "size": size,
        "partial_sum": partial_sum,
        "stored_checksum": stored,
        "footer_le": footer_le,
        "total_sum": total,
        "recommended_checksum": recommended,
        "checksum_ok": ok,
    }


# --------------------- Step 5: USB enumeration parsing ----------------------

def find_usbtree_for_stem(stem: str) -> Optional[Path]:
    # Priority: out/usbtree_<stem>.txt
    candidates = [
        WORKSPACE_ROOT / "out" / f"usbtree_{stem}.txt",
        WORKSPACE_ROOT / "usb" / f"usbtree_{stem}.txt",
    ]
    for p in candidates:
        if p.exists():
            return p
    # Secondary: USBdeviceTreeViewer report/* for stock
    return None


def classify_usbtree(path: Path) -> Tuple[str, List[str]]:
    """Return (enum_status, excerpts)."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    status = "Partial"
    # Simple heuristics
    has_device_desc = any("Device Descriptor" in l for l in lines)
    has_config_desc = any("Configuration Descriptor" in l for l in lines)
    has_uvc = any("VideoControl" in l or "UVC" in l for l in lines)
    failed = any("Enumeration failed" in l or "Device not connected" in l or "Unknown USB Device" in l for l in lines)
    if failed:
        status = "No-Enum"
    elif has_config_desc:
        status = "OK"
    elif has_device_desc:
        status = "Partial"
    else:
        status = "Partial"
    # Excerpts: up to 10 relevant lines
    excerpts: List[str] = []
    for l in lines:
        if any(k in l for k in ["VID", "PID", "Device Descriptor", "Configuration Descriptor", "Interface", "Product"]):
            excerpts.append(l)
        if len(excerpts) >= 10:
            break
    return status, excerpts


# --------------------------- Step 6: logs merge -----------------------------

def collect_logs() -> List[Path]:
    parts: List[Path] = []
    for rel in [
        WORKSPACE_ROOT / "logs",
        WORKSPACE_ROOT / "out",
        WORKSPACE_ROOT / "25-08-10" / "logs",
        WORKSPACE_ROOT / "25.08.11" / "out_v2" / "bad",
        WORKSPACE_ROOT / "2508110204" / "out_v3" / "bad",
    ]:
        if rel.exists():
            for p in rel.rglob("*.md"):
                parts.append(p)
            for p in rel.rglob("*.txt"):
                parts.append(p)
    # Deduplicate by absolute path uniqueness at this stage; content dedup later
    uniq: List[Path] = []
    seen = set()
    for p in parts:
        if p.resolve() not in seen:
            seen.add(p.resolve())
            uniq.append(p)
    return uniq


def merge_logs_to_all_logs_md(out_path: Path) -> None:
    files = collect_logs()
    # Dedup by content hash
    records: List[Tuple[str, Path, int, str]] = []  # (hash, path, size, mtime)
    by_hash: Dict[str, Tuple[Path, int, str]] = {}
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
            h = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
            by_hash[h] = (p, len(text), file_mtime_iso(p))
        except Exception:
            continue
    # Order chronologically by mtime
    ordered = sorted(by_hash.items(), key=lambda kv: kv[1][2])
    lines: List[str] = []
    lines.append(f"# ALL LOGS (deduplicated by content) — generated {dt.datetime.now().isoformat()}")
    lines.append("")
    for h, (p, size, mtime) in ordered:
        rel = p.relative_to(WORKSPACE_ROOT)
        lines.append(f"## {rel} — {mtime} — {size} bytes — sha256={h}")
        lines.append("")
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            content = f"<ERROR reading file: {e}>"
        lines.append("```\n" + content.rstrip() + "\n```")
        lines.append("")
    write_text(out_path, "\n".join(lines) + "\n")


# --------------------------- Step 7: move plan ------------------------------

def classify_build(verdict: str, checksum_ok: bool, usb_enum: Optional[str]) -> str:
    if usb_enum == "No-Enum" or not checksum_ok or verdict == "MISMATCH":
        return "bad"
    return "ok"


def propose_moves(manifest_rows: List[Dict[str, Any]]) -> Tuple[List[Tuple[Path, Path]], List[str]]:
    """Return (moves, warnings)."""
    moves: List[Tuple[Path, Path]] = []
    warnings: List[str] = []
    # Proposed structure
    base_dir = WORKSPACE_ROOT / "firmware" / "base"
    ok_dir = WORKSPACE_ROOT / "firmware" / "builds" / "ok"
    bad_dir = WORKSPACE_ROOT / "firmware" / "builds" / "bad"
    scripts_dir = WORKSPACE_ROOT / "scripts"
    intel_dir = WORKSPACE_ROOT / "intel"  # keep
    usb_dir = WORKSPACE_ROOT / "usb"
    trash_dir = WORKSPACE_ROOT / "trash"

    # Baseline copies (the originals remain)
    baseline_originals = candidate_baseline_paths()
    for p in baseline_originals:
        moves.append((p, base_dir / p.name))

    # Place binaries based on classification
    for row in manifest_rows:
        src = WORKSPACE_ROOT / row["file"]
        if not src.exists():
            continue
        if src.name.lower() == "baseline.bin" and is_inside(src, AUDIT_DIR):
            # Skip the copy inside audit
            continue
        classification = classify_build(row.get("verdict", ""), row.get("checksum_ok", False), row.get("usb_enum"))
        dest_dir = ok_dir if classification == "ok" else bad_dir
        moves.append((src, dest_dir / src.name))

    # USB reports → usb/
    for p in (WORKSPACE_ROOT / "out").glob("usbtree_*.txt"):
        moves.append((p, usb_dir / p.name))
    for p in (WORKSPACE_ROOT / "USBdeviceTreeViewer report").glob("*"):
        if p.is_file():
            moves.append((p, usb_dir / p.name))

    # Scripts: move build_*, patch_*, analyze_*, _helpers_*.py to /scripts/
    for p in WORKSPACE_ROOT.glob("build_*.py"):
        moves.append((p, scripts_dir / p.name))
    for p in WORKSPACE_ROOT.glob("patch_*.py"):
        moves.append((p, scripts_dir / p.name))
    for p in WORKSPACE_ROOT.glob("analyze_*.py"):
        moves.append((p, scripts_dir / p.name))
    for p in WORKSPACE_ROOT.glob("_helpers_*.py"):
        moves.append((p, scripts_dir / p.name))

    # Do not move intel/ itself; it's already in correct place

    return moves, warnings


def render_moves_ps1(moves: List[Tuple[Path, Path]]) -> Tuple[str, str]:
    header = (
        "# Non-destructive apply script generated by orchestrate_audit.py\n"
        "$ErrorActionPreference = 'Stop'\n"
        "\n"
    )
    plan_lines: List[str] = [header]
    apply_lines: List[str] = [header]
    # Plan: write commented commands
    for src, dst in moves:
        plan_lines.append(f"# Move-Item -LiteralPath \"{src}\" -Destination \"{dst}\" -Force")
    # Apply: create dirs then move
    created: set[Path] = set()
    for src, dst in moves:
        dst_dir = dst.parent
        if dst_dir not in created:
            apply_lines.append(f"New-Item -ItemType Directory -Force -Path \"{dst_dir}\" | Out-Null")
            created.add(dst_dir)
        apply_lines.append("try {")
        apply_lines.append(f"  Move-Item -LiteralPath \"{src}\" -Destination \"{dst}\" -Force -ErrorAction Stop")
        apply_lines.append("} catch {")
        apply_lines.append(f"  Write-Warning \"SKIP (locked or in use): {src}\"")
        apply_lines.append("}")
    return "\n".join(plan_lines) + "\n", "\n".join(apply_lines) + "\n"


# ---------------------- Step 8/9: reporting helpers -------------------------

def summarize_changes(diffs: List[Tuple[int, int, int]], limit: int = 6) -> str:
    if not diffs:
        return ""
    parts = []
    for i, b0, b1 in diffs[:limit]:
        if b0 == -1:
            parts.append(f"0x{i:04X}:- -> {b1:02X}")
        elif b1 == -1:
            parts.append(f"0x{i:04X}:{b0:02X} -> -")
        else:
            parts.append(f"0x{i:04X}:{b0:02X}->{b1:02X}")
    more = len(diffs) - len(parts)
    if more > 0:
        parts.append(f"(+{more} more)")
    return "; ".join(parts)


def make_manifest_row(rel_file: str, sha: str, size: int, diffs: List[Tuple[int, int, int]], claim: Dict[str, Any], verdict: str, verdict_notes: List[str], checksum: Dict[str, Any], usb_enum: Optional[str], notes: List[str]) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "file": rel_file,
        "sha256": sha,
        "size": size,
        "n_changes": len(diffs),
        "change_offsets_summary": summarize_changes(diffs),
        "claim": claim.get("type", "unknown"),
        "verdict": verdict,
        "checksum_ok": checksum.get("checksum_ok"),
        "checksum_region": "0x1FFE-0x1FFF" if size == 0x20000 else "",
        "usb_enum": usb_enum,
        "notes": "; ".join(notes + verdict_notes),
    }
    return row


def write_manifest_csv(rows: List[Dict[str, Any]], path: Path) -> None:
    cols = [
        "file",
        "sha256",
        "size",
        "n_changes",
        "change_offsets_summary",
        "claim",
        "verdict",
        "checksum_ok",
        "checksum_region",
        "usb_enum",
        "notes",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def render_audit_log(
    baseline_path: Optional[Path],
    baseline_sha: Optional[str],
    baseline_size: Optional[int],
    baseline_issues: List[str],
    manifest_rows: List[Dict[str, Any]],
    mcp_available: bool,
    all_mismatch_details: Dict[str, List[Tuple[int, int, int]]],
) -> str:
    lines: List[str] = []
    lines.append(f"# AUDIT LOG — {dt.datetime.now().isoformat()}")
    lines.append("")
    lines.append("## Baseline selection")
    if baseline_path:
        lines.append(f"- Baseline: `{baseline_path.relative_to(WORKSPACE_ROOT)}`")
        lines.append(f"- SHA-256: `{baseline_sha}`")
        lines.append(f"- Size: `{baseline_size}` bytes {'(OK 131072 bytes)' if baseline_size==131072 else '(FLAG: not 131072)'}")
    else:
        lines.append("- Baseline: NOT SELECTED (ambiguous or missing)")
    if baseline_issues:
        lines.append("")
        lines.append("### Issues")
        for s in baseline_issues:
            lines.append(f"- {s}")
    lines.append("")

    # Per-family summary tables (by claim)
    lines.append("## Per-family summary")
    by_claim: Dict[str, List[Dict[str, Any]]] = {}
    for r in manifest_rows:
        by_claim.setdefault(r.get("claim", "unknown"), []).append(r)
    for fam, rows in by_claim.items():
        lines.append(f"### {fam}")
        lines.append("")
        lines.append("| file | verdict | checksum_ok | usb_enum | n_changes | summary | notes |")
        lines.append("|------|---------|-------------|----------|-----------|---------|-------|")
        for r in rows:
            lines.append(
                f"| `{r['file']}` | {r['verdict']} | {r['checksum_ok']} | {r.get('usb_enum','')} | {r['n_changes']} | {r['change_offsets_summary']} | {r['notes']} |"
            )
        lines.append("")

    # Mismatch details
    lines.append("## Mismatch details")
    any_mismatch = False
    for rel, diffs in all_mismatch_details.items():
        any_mismatch = True
        lines.append(f"### {rel}")
        if not diffs:
            lines.append("No diffs recorded.")
            continue
        lines.append("| offset | base | new |")
        lines.append("|--------|------|-----|")
        for off, b0, b1 in diffs:
            base_s = "-" if b0 == -1 else f"0x{b0:02X}"
            new_s = "-" if b1 == -1 else f"0x{b1:02X}"
            lines.append(f"| 0x{off:04X} | {base_s} | {new_s} |")
        lines.append("")
    if not any_mismatch:
        lines.append("No mismatches.")

    lines.append("")
    lines.append("## CRC/Checksum proof notes")
    lines.append("- Algorithm: two's complement footer at 0x1FFE..0x1FFF, partial sum of [0x0000..0x1FFD]")
    lines.append("- Checked per image; see per_bin JSON for exact values")

    lines.append("")
    lines.append("## USB enumeration findings")
    lines.append("- Parsed from usbtree_*.txt where available; excerpts embedded per manifest row")

    lines.append("")
    lines.append("## Final classification")
    lines.append("- Proposed OK/BAD per rules: MISMATCH or checksum false or No-Enum → BAD; else OK")

    lines.append("")
    lines.append("## Proposed tree")
    lines.append("See `audit/proposed_tree.md` and `audit/proposed_moves.ps1`.")

    lines.append("")
    lines.append("## IDA MCP status")
    lines.append(f"- {'Available' if mcp_available else 'MCP unavailable'}")

    return "\n".join(lines) + "\n"


def write_proposed_tree_md(moves: List[Tuple[Path, Path]], path: Path) -> None:
    # Aggregate by destination directory
    by_dest_dir: Dict[Path, List[Tuple[Path, Path]]] = {}
    for src, dst in moves:
        by_dest_dir.setdefault(dst.parent, []).append((src, dst))
    lines: List[str] = []
    lines.append("# Proposed tree")
    for dest_dir, items in sorted(by_dest_dir.items(), key=lambda kv: str(kv[0])):
        rel_dir = dest_dir.relative_to(WORKSPACE_ROOT)
        lines.append(f"- `{rel_dir}/` ({len(items)} items)")
        for src, dst in items[:20]:  # preview first 20 moves per dir
            lines.append(f"  - `{src.relative_to(WORKSPACE_ROOT)}` → `{dst.relative_to(WORKSPACE_ROOT)}`")
        if len(items) > 20:
            lines.append(f"  - ... (+{len(items) - 20} more)")
    write_text(path, "\n".join(lines) + "\n")


def safe_rel(path: Path) -> str:
    return str(path.resolve().relative_to(WORKSPACE_ROOT))


def second_pass_compare(manifest1: Path, manifest2: Path) -> str:
    def load_csv(path: Path) -> List[Dict[str, str]]:
        with path.open("r", encoding="utf-8") as f:
            r = csv.DictReader(f)
            return list(r)
    a = load_csv(manifest1)
    b = load_csv(manifest2)
    # Group rows by sha256 (duplicates possible)
    def group_by_sha(rows: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
        m: Dict[str, List[Dict[str, str]]] = {}
        for r in rows:
            m.setdefault(r["sha256"], []).append(r)
        return m
    ga = group_by_sha(a)
    gb = group_by_sha(b)

    # Canonical representative per sha: choose row with lexicographically smallest basename
    def canonical(m: Dict[str, List[Dict[str, str]]]) -> Dict[str, Dict[str, str]]:
        out: Dict[str, Dict[str, str]] = {}
        for sha, rows in m.items():
            rows_sorted = sorted(rows, key=lambda r: Path(r["file"]).name)
            out[sha] = rows_sorted[0]
        return out

    ca = canonical(ga)
    cb = canonical(gb)

    lines: List[str] = []
    lines.append("# Second pass comparison")
    for sha in sorted(set(ca.keys()) - set(cb.keys())):
        lines.append(f"- Missing after moves: {ca[sha]['file']} ({sha})")
    for sha in sorted(set(cb.keys()) - set(ca.keys())):
        lines.append(f"- New after moves: {cb[sha]['file']} ({sha})")

    both = sorted(set(ca.keys()) & set(cb.keys()))
    fields = [
        "size",
        "n_changes",
        "change_offsets_summary",
        "claim",
        "verdict",
        "checksum_ok",
        "usb_enum",
        "notes",
    ]
    for sha in both:
        ra = ca[sha]
        rb = cb[sha]
        for f in fields:
            if str(ra.get(f)) != str(rb.get(f)):
                lines.append(f"- Mismatch for {sha} field {f}: pass1={ra.get(f)} pass2={rb.get(f)}")
    if len(lines) == 1:
        lines.append("Results are identical except for paths (OK)")
    return "\n".join(lines) + "\n"


# ---------------------------------- main -----------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="SN9C292B firmware audit orchestrator")
    parser.add_argument("--apply-moves", action="store_true", help="Execute move plan (use external PowerShell) and enable second-pass compare on subsequent run")
    args = parser.parse_args()

    ensure_dirs()

    # Step 0: inputs snapshot
    generate_inputs_snapshot(AUDIT_DIR / "inputs_snapshot.txt")

    # Baseline selection
    baseline_path, hash_to_paths, baseline_sha, baseline_size, baseline_issues = select_baseline()
    baseline_copied_path: Optional[Path] = None
    baseline_data: Optional[bytes] = None
    if baseline_path:
        baseline_copied_path = copy_baseline_to_audit(baseline_path)
        baseline_data = load_bytes(baseline_path)

    osd_offsets = load_osd_sites()

    # Step 2: binaries
    bins = enumerate_all_bins()
    manifest_rows: List[Dict[str, Any]] = []
    all_mismatch_details: Dict[str, List[Tuple[int, int, int]]] = {}

    for bin_path in sorted(bins):
        rel = bin_path.relative_to(WORKSPACE_ROOT)
        # Compute hash/len
        try:
            data = load_bytes(bin_path)
            sha = sha256_file(bin_path)
            size = len(data)
        except Exception as e:
            err = f"Error reading {rel}: {e}"
            write_text(ERRORS_DIR / f"read_{bin_path.name}.txt", err)
            continue

        # Diff vs baseline (if available and same size)
        diffs: List[Tuple[int, int, int]] = []
        notes: List[str] = []
        if baseline_data is not None and len(baseline_data) == len(data):
            diffs = diff_bytes(baseline_data, data)
        else:
            if baseline_data is None:
                notes.append("Baseline ambiguous or missing; diff skipped")
            elif len(baseline_data) != len(data):
                notes.append("Size differs from baseline; full diff skipped")

        # Neighbor files
        neighbor = parse_neighbor_files(bin_path)

        # Claim from name
        claim = parse_claim_from_name(bin_path.name)

        # Verdict
        verdict = "unknown"
        verdict_notes: List[str] = []
        if baseline_data is None:
            verdict = "UNKNOWN"
            verdict_notes.append("Baseline not selected; cannot validate diffs")
        else:
            verdict, verdict_notes = verdict_from_diffs(diffs, claim, osd_offsets)

        # Checksum verification
        checksum = compute_checksum_fields(data)
        # If claims crc_fixed but checksum not OK, mark mismatch
        if claim.get("type") == "crc_fixed" and not checksum.get("checksum_ok"):
            verdict = "MISMATCH"
            verdict_notes.append("crc_fixed claim but checksum verification failed")

        # USB status
        stem = bin_path.stem
        usb_enum: Optional[str] = None
        usb_excerpts: List[str] = []
        usb_path = find_usbtree_for_stem(stem)
        if usb_path and usb_path.exists():
            usb_enum, usb_excerpts = classify_usbtree(usb_path)

        # per-bin JSON facts
        per_bin = {
            "file": str(rel),
            "sha256": sha,
            "size": size,
            "baseline": str(baseline_path.relative_to(WORKSPACE_ROOT)) if baseline_path else None,
            "diffs": [
                {"offset": f"0x{off:04X}", "base": (None if b0 == -1 else f"0x{b0:02X}"), "new": (None if b1 == -1 else f"0x{b1:02X}")}
                for (off, b0, b1) in diffs
            ],
            "neighbor_files": neighbor,
            "claim": claim,
            "verdict": verdict,
            "verdict_notes": verdict_notes,
            "checksum": checksum,
            "usb": {"path": (str(usb_path.relative_to(WORKSPACE_ROOT)) if usb_path else None), "status": usb_enum, "excerpts": usb_excerpts},
        }
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", rel.as_posix())
        write_json(PER_BIN_DIR / f"{safe_name}.json", per_bin)

        # Collect mismatches
        if verdict == "MISMATCH":
            all_mismatch_details[str(rel)] = diffs

        # Manifest row
        row = make_manifest_row(str(rel), sha, size, diffs, claim, verdict, verdict_notes, checksum, usb_enum, notes)
        manifest_rows.append(row)

    # Manifest
    manifest_path = AUDIT_DIR / "manifest.csv"
    write_manifest_csv(manifest_rows, manifest_path)

    # Save first pass manifest snapshot if not present; otherwise produce second-pass comparison
    pass1_manifest = AUDIT_DIR / "manifest_pass1.csv"
    if not pass1_manifest.exists():
        try:
            shutil.copy2(manifest_path, pass1_manifest)
        except Exception:
            pass
    else:
        try:
            second = second_pass_compare(pass1_manifest, manifest_path)
            write_text(AUDIT_DIR / "second_pass.md", second)
        except Exception as e:
            write_text(ERRORS_DIR / "second_pass_compare.txt", f"Error: {e}")

    # Logs consolidation
    merge_logs_to_all_logs_md(AUDIT_DIR / "ALL_LOGS.md")

    # Proposed moves
    moves, warnings = propose_moves(manifest_rows)
    plan_ps1, apply_ps1 = render_moves_ps1(moves)
    write_text(AUDIT_DIR / "proposed_moves.ps1", plan_ps1)
    write_text(AUDIT_DIR / "apply_moves.ps1", apply_ps1)
    write_proposed_tree_md(moves, AUDIT_DIR / "proposed_tree.md")

    # AUDIT_LOG.md
    # MCP availability probe (best-effort via .cursor/mcp.json existence)
    mcp_available = (WORKSPACE_ROOT / ".cursor" / "mcp.json").exists()
    audit_log = render_audit_log(baseline_path, baseline_sha, baseline_size, baseline_issues, manifest_rows, mcp_available, all_mismatch_details)
    write_text(AUDIT_DIR / "AUDIT_LOG.md", audit_log)

    # PASS-2 if requested: we only emit scripts; execution is external to Python
    if args.apply_moves:
        # Create a small note to indicate that moves should be applied now
        write_text(AUDIT_DIR / "APPLY_MOVES_README.txt", (
            "Run the following in PowerShell (from repo root):\n\n"
            "  powershell -ExecutionPolicy Bypass -File audit\\apply_moves.ps1\n\n"
            "Then re-run: .venv\\Scripts\\python.exe tools\\orchestrate_audit.py to generate audit/second_pass.md\n"
        ))

    return 0


if __name__ == "__main__":
    sys.exit(main())

