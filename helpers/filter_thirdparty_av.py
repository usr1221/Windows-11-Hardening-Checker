#!/usr/bin/env python3
"""
Strip CIS policies that do not apply when Microsoft Defender Antivirus is not the
active antimalware engine (client runs Cortex XDR + ESET).

Rationale
---------
When a third-party AV registers with the Windows Security Center, Defender AV drops
to passive/disabled mode. Everything that is implemented *inside* the Defender AV
engine then stops enforcing, so auditing it produces noise:

  * ASR rules                 -- require Defender AV active with real-time protection
  * Controlled Folder Access  -- same dependency
  * Real-time protection      -- the engine itself
  * Scan / MpEngine / MAPS    -- scheduled scan, cloud lookup, sample submission
  * Quarantine                -- Defender quarantine store only
  * PUA / exclusion handling   -- Defender-engine-only settings

Deliberately KEPT, because they are NOT part of the AV engine and still enforce:

  * Exploit Protection (ExploitProtectionSettings)  -- kernel mitigations (CFG/DEP/ASLR/SEHOP)
  * DisallowExploitProtectionOverride               -- Windows Security UI lockdown
  * SmartScreen (EnableSmartScreen)                 -- Explorer/Edge reputation service
  * Early Launch Antimalware / Boot-Start Driver    -- applies to the third-party ELAM driver

Usage
-----
    python3 filter_thirdparty_av.py Policy_Compliance_Report.xlsx
    python3 filter_thirdparty_av.py in.xlsx -o out.xlsx --exclusions-csv removed.csv
    python3 filter_thirdparty_av.py in.xlsx --dry-run
    python3 filter_thirdparty_av.py in.xlsx --keep-review   # keep the flagged-for-review rows
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

try:
    import openpyxl
    from openpyxl.styles import Font
except ImportError:  # pragma: no cover
    sys.exit("openpyxl is required:  pip3 install openpyxl")


# --------------------------------------------------------------------------- #
# Exclusion rules
# --------------------------------------------------------------------------- #

# Registry subkeys under ...\Policies\Microsoft\Windows Defender\  that belong to
# the AV engine.  Matched case-insensitively against the Registry Path column.
ENGINE_SUBKEYS = {
    r"windows defender\windows defender exploit guard\asr\rules":
        ("ASR rules", "Attack Surface Reduction requires Defender AV to be the active "
                      "engine with real-time protection on; inert in passive mode. "
                      "Covered by Cortex XDR behavioural prevention."),
    r"windows defender\windows defender exploit guard\controlled folder access":
        ("Controlled Folder Access", "Depends on Defender AV real-time protection; "
                                     "inert in passive mode. Covered by Cortex XDR "
                                     "anti-ransomware."),
    r"windows defender\real-time protection":
        ("Defender real-time protection", "Defender AV engine setting; engine is "
                                          "passive/disabled with ESET registered as AV."),
    r"windows defender\scan":
        ("Defender scan engine", "Defender AV scheduled/on-demand scan settings; "
                                 "scanning is performed by ESET."),
    r"windows defender\spynet":
        ("Defender MAPS / cloud", "Microsoft MAPS membership and sample submission; "
                                  "cloud lookup is performed by Cortex XDR / ESET LiveGrid."),
    r"windows defender\mpengine":
        ("Defender cloud engine", "Defender cloud-block level and extended check; "
                                  "engine is passive/disabled."),
    r"windows defender\quarantine":
        ("Defender quarantine", "Defender quarantine store is unused; quarantine is "
                                "handled by ESET."),
}

# Exact registry path (root of the Defender policy key) -> Setting Name level rules.
DEFENDER_ROOT = r"policies\microsoft\windows defender"

ROOT_SETTINGS = {
    "puaprotection":
        ("Defender PUA protection", "Defender AV engine setting; PUA detection is "
                                    "provided by ESET."),
    "disablelocaladminmerge":
        ("Defender exclusion merge", "Governs Defender AV exclusion lists only."),
    "hideexclusionsfromlocaladmins":
        ("Defender exclusion visibility", "Governs Defender AV exclusion lists only."),
    "disableroutinelytakingaction":
        ("Defender remediation", "Defender AV engine setting; remediation is performed "
                                 "by Cortex XDR / ESET."),
}

# Removed by default, but singled out in the log because it is the one setting an
# auditor will ask about: CIS wants Defender ON, the client deliberately runs a
# third-party AV instead.  --keep-review retains these rows.
REVIEW_SETTINGS = {
    "disableantispyware":
        ("Defender enable/disable", "CIS requires Defender AV enabled. Client runs "
                                    "ESET + Cortex XDR as the registered AV/EDR, so "
                                    "Defender auto-enters passive mode and this key is "
                                    "ignored under Tamper Protection. Document as a "
                                    "risk-accepted deviation with the third-party AV "
                                    "as the compensating control."),
}

# Defender-*named* settings that still enforce without the AV engine -> never removed.
KEEP_SETTINGS = {
    "exploitprotectionsettings",
    "disallowexploitprotectionoverride",
    "enablesmartscreen",
}

EXCLUSION_SHEET = "Excluded - 3rd Party AV"

COL = {  # 0-based indexes into the row tuple
    "policy": 0,
    "scope": 1,
    "path": 2,
    "registry": 3,
    "setting": 4,
}


def classify(policy: str, registry: str, setting: str):
    """Return (action, group, reason). action is 'keep', 'remove' or 'review'."""
    reg = (registry or "").lower()
    setting_l = (setting or "").strip().lower()

    if setting_l in KEEP_SETTINGS:
        return "keep", None, None

    for needle, (group, reason) in ENGINE_SUBKEYS.items():
        if needle in reg:
            return "remove", group, reason

    if reg.rstrip("\\").endswith(DEFENDER_ROOT):
        if setting_l in REVIEW_SETTINGS:
            group, reason = REVIEW_SETTINGS[setting_l]
            return "review", group, reason
        if setting_l in ROOT_SETTINGS:
            group, reason = ROOT_SETTINGS[setting_l]
            return "remove", group, reason
        # Unknown setting directly under the Defender policy key -> AV engine by default.
        return "remove", "Defender Antivirus", (
            "Setting lives under the Defender Antivirus policy key; the engine is "
            "passive/disabled with a third-party AV registered."
        )

    return "keep", None, None


def find_header(ws):
    """Locate the header row and map the columns we care about."""
    for row in ws.iter_rows(min_row=1, max_row=5):
        values = [str(c.value).strip().lower() if c.value else "" for c in row]
        if "policy name" in values and "registry path" in values:
            idx = {
                "policy": values.index("policy name"),
                "registry": values.index("registry path"),
                "setting": values.index("setting name") if "setting name" in values else None,
                "path": values.index("policy path") if "policy path" in values else None,
            }
            return row[0].row, idx
    raise SystemExit("Could not find a header row with 'Policy Name' and 'Registry Path'.")


def cell(row, idx, key):
    i = idx.get(key)
    if i is None or i >= len(row):
        return ""
    return row[i] or ""


def contiguous_groups(numbers):
    """[3,4,5,9,10] -> [(3,3),(9,2)]  (start, count), ascending."""
    out = []
    for n in sorted(numbers):
        if out and n == out[-1][0] + out[-1][1]:
            out[-1][1] += 1
        else:
            out.append([n, 1])
    return [(s, c) for s, c in out]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Remove Defender-AV-dependent CIS policies from an XLSX compliance "
                    "report (client runs Cortex XDR + ESET).")
    ap.add_argument("input", type=Path, help="source .xlsx report")
    ap.add_argument("-o", "--output", type=Path,
                    help="destination .xlsx (default: <input>_filtered.xlsx)")
    ap.add_argument("--exclusions-csv", type=Path,
                    help="also write the removed rows to a CSV")
    ap.add_argument("--keep-review", action="store_true",
                    help="keep the rows flagged for manual review (DisableAntiSpyware)")
    ap.add_argument("--no-exclusion-sheet", action="store_true",
                    help="do not append the 'Excluded - 3rd Party AV' worksheet")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would be removed and exit without writing")
    args = ap.parse_args()

    if not args.input.is_file():
        return f"Input not found: {args.input}"

    out_path = args.output or args.input.with_name(f"{args.input.stem}_filtered.xlsx")

    wb = openpyxl.load_workbook(args.input)
    total_removed = 0
    excluded_all = []

    for ws in wb.worksheets:
        if ws.title == EXCLUSION_SHEET:
            continue  # our own audit trail from a previous run
        try:
            header_row, idx = find_header(ws)
        except SystemExit:
            continue  # sheet without the expected layout -> leave untouched

        to_delete = []
        for r in range(header_row + 1, ws.max_row + 1):
            row = [c.value for c in ws[r]]
            policy = cell(row, idx, "policy")
            registry = cell(row, idx, "registry")
            setting = cell(row, idx, "setting")
            if not any((policy, registry, setting)):
                continue

            action, group, reason = classify(str(policy), str(registry), str(setting))
            if action == "keep":
                continue
            if action == "review" and args.keep_review:
                continue

            to_delete.append(r)
            excluded_all.append({
                "Sheet": ws.title,
                "Row": r,
                "Policy Name": policy,
                "Policy Path": cell(row, idx, "path"),
                "Registry Path": registry,
                "Setting Name": setting,
                "Group": group,
                "Disposition": "Review / risk-accept" if action == "review" else "Not applicable",
                "Reason": reason,
            })

        if args.dry_run:
            continue

        # Delete bottom-up so earlier row numbers stay valid.
        for start, count in reversed(contiguous_groups(to_delete)):
            ws.delete_rows(start, count)
        total_removed += len(to_delete)

    # ---------------- reporting ---------------- #
    if not excluded_all:
        print("Nothing matched the Defender-AV exclusion rules; report left unchanged.")
        return 0

    by_group = {}
    for e in excluded_all:
        by_group.setdefault(e["Group"], []).append(e)

    print(f"{'DRY RUN - would remove' if args.dry_run else 'Removed'} "
          f"{len(excluded_all)} row(s):\n")
    for group in sorted(by_group):
        rows = by_group[group]
        print(f"  {group}  ({len(rows)})")
        for e in rows:
            flag = "  [REVIEW]" if e["Disposition"].startswith("Review") else ""
            print(f"      - {e['Policy Name']}{flag}")
        print()

    if args.dry_run:
        print("Dry run: no files written.")
        return 0

    if not args.no_exclusion_sheet:
        if EXCLUSION_SHEET in wb.sheetnames:
            del wb[EXCLUSION_SHEET]
        xs = wb.create_sheet(EXCLUSION_SHEET)
        headers = ["Policy Name", "Policy Path", "Registry Path", "Setting Name",
                   "Group", "Disposition", "Reason"]
        xs.append(headers)
        for c in xs[1]:
            c.font = Font(bold=True)
        for e in excluded_all:
            xs.append([e[h] for h in headers])
        for col, width in zip("ABCDEFG", (60, 80, 64, 45, 30, 22, 90)):
            xs.column_dimensions[col].width = width
        xs.freeze_panes = "A2"

    wb.save(out_path)
    print(f"Wrote filtered report: {out_path}")

    if args.exclusions_csv:
        with args.exclusions_csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(excluded_all[0].keys()))
            w.writeheader()
            w.writerows(excluded_all)
        print(f"Wrote exclusions CSV:  {args.exclusions_csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
