# helpers — regenerating the CIS, VDI and Windows Server policy sets

These scripts rebuild the policy sets in `policies/` from the source documents
in `sources/` (see `sources/README.md` for what goes there): `Policies-CIS.json`,
`Policies-VDI.json` and `Policies-VDI-Decisions.csv` from the CIS-CAT HTML
report and the CIS benchmark PDF, and the `Policies-CIS-Server*.json` sets from
the Windows Server benchmark PDFs alone (see *Windows Server sets* below).

Nothing in the audit tool depends on them — they exist so the policy sets can be
regenerated when CIS publishes a new benchmark revision, instead of being
hand-edited.

## Running the pipeline

```bash
python3 helpers/parse_cis_report.py     # HTML report  -> rules + group titles
python3 helpers/parse_cis_pdf.py        # benchmark PDF -> registry mappings
python3 helpers/build_policies_cis.py   # -> policies/Policies-CIS.json
python3 helpers/build_policies_vdi.py   # -> policies/Policies-VDI.json + decisions CSV
```

Requirements: Python 3.9+ and `pypdf` (step 2 only). Intermediates are cached in
`.cis-build/`; the extracted PDF text is reused unless the PDF is newer.

The Edge baseline is independent of the CIS pipeline and runs on its own:

```bash
python3 helpers/build_policies_edge.py   # -> policies/Policies-Edge.json
```

It reads the Policy Analyzer `*.PolicyRules` export (the authority for the
registry key, value name, type and data — it is a mechanical dump of the
baseline's `registry.pol`) and the converted `*.xlsx` audit report, which is
used only to cross-check the setting list and seed the rationale. Friendly
policy names, Administrative Templates paths, priorities and the expanded notes
are curated in `META` at the top of the script, because neither input carries
them. Adding a setting to the baseline without adding it to `META` produces a
warning rather than a silently missing check.

Each script finds its input in `sources/` by glob (falling back to the repository
root) and stops if it finds more than one candidate; pass `--report` / `--pdf` to be explicit.

## Windows Server sets

```bash
python3 helpers/build_policies_cis_server.py                 # all Server PDFs, MS + DC
python3 helpers/build_policies_cis_server.py --profile DC    # one profile
python3 helpers/build_policies_cis_server.py --pdf sources/CIS_Microsoft_Windows_Server_2022_Benchmark_v5.1.0.pdf
```

It picks up every `CIS_Microsoft_Windows_Server_*_Benchmark_*.pdf` in
`sources/` and writes `policies/Policies-CIS-Server<year>-MS.json` (Level 1 -
Member Server) and `-DC.json` (Level 1 - Domain Controller). Intermediates go to
`.cis-build/server<year>/` (`layout.txt`, the cached PDF text, and `recs.json`,
every parsed recommendation).

There is no CIS-CAT report for Windows Server, so this pipeline reads the **PDF
only** (`parse_cis_server_pdf.py`). Each recommendation carries the same nine
labelled parts the report had; text is extracted with pypdf's *layout* mode,
which keeps words and registry paths intact where the default mode splits them.
Wrapped registry paths, Group Policy paths and hyphens are rejoined by rules
documented at the top of the parser.

Differences from the Windows 11 builder:

- **Curated tables are keyed by setting name, never by section number** — the
  numbering differs between benchmarks (2.2.33 is *Increase scheduling
  priority* in Server 2022 and *Impersonate a client* in Server 2019).
- **The title sets the direction of a bare number.** The Audit text prints
  `32768` where the title says *32,768 or greater*; the builder emits `ge`, and
  lists every such derivation as a `~` line so it can be reviewed.
- **Conditional principals** in the recommended-state sentence (*"... and (when
  the Web Server (IIS) Role ... is installed) IIS_IUSRS"*) are added to the
  allow list; one with no well-known SID is noted for manual review.
- **Two recommendations for one user right** in the same profile are folded
  into a single check when one allow list contains the other; otherwise it is a
  warning.
- The remotely accessible registry path lists are written out in the script
  and **checked against the benchmark text** on every run.

Tables and helpers shared with the Windows 11 builder (principal SIDs, priority
rules, the expected-value phrase parser) live in `_cis_common.py`.

**Validating the parser.** The same builder can be pointed at the Windows 11
PDF (profile `Level 1 (L1)`) and its output diffed against `Policies-CIS.json`,
which was built independently from the CIS-CAT report. All 409 checks agree on
registry path, value name, type, value, operator, audit GUID/flags and category;
the only differences are the Windows 11 builder's hand-added extra SIDs and
three Windows 11 defects this comparison found (see below).

Known Windows 11 defects surfaced by that comparison, not yet fixed in
`build_policies_cis.py`: 18.5.12 `WarningLevel`, 18.9.26.5 `PasswordLength` and
18.9.26.6 `PasswordAgeDays` are emitted as `eq` although CIS says *90% or less*,
*15 or more* and *30 or fewer*; and 2.3.10.7 / 2.3.10.8 carry the value list in
`PolicyPath` instead of the Group Policy path.

## Where each field comes from

| Field | Source |
|-------|--------|
| `RegistryPath`, `SettingName`, `ValueType` | the benchmark PDF's *Audit* section (`HKLM\...\Key:ValueName`, `REG_DWORD`) |
| `RecommendedValue`, `Operator` | the PDF's expected-value phrase — "900 or less, but not 0" becomes `between 1,900`, "4 or that the key does not exist" becomes `eq 4` + `AbsentIsCompliant` |
| `PolicyPath` | the report's remediation UI path |
| `Notes` | the report's full description + rationale + impact, plus the PDF's default value |
| `Category` | the enclosing benchmark group title |
| `RecommendedSids` | parsed from the CIS recommendation title, cross-checked against `Policies.json` |
| `SettingName` for auditpol | subcategory GUID, read from the PDF's own `auditpol /get /subcategory:"{...}"` line; `Policies.json` and the three added here are only a fallback, and a disagreement is reported as a warning |

The report's OVAL criteria are used to cross-check every registry value name.
Where the two disagree the PDF wins — the report's OVAL content has known errors
(for example 18.6.7.3 names `AuditClientDoesNotSupportSigning` when the setting
is `AuditInsecureGuestLogon`).

## Warnings are meaningful

`build_policies_cis.py` prints a warning whenever a user-right SID set derived
from the recommendation title disagrees with the hand-written table in
`Policies.json`. The three warnings it currently prints are the defects it
corrected (2.2.6 was missing Administrators; 2.2.16 and 2.2.17 listed
Administrators where CIS says Guests). A *new* warning after a benchmark update
means CIS changed the recommendation — read it, don't silence it.

It warns the same way when an audit subcategory GUID in `Policies.json`
disagrees with the GUID the benchmark itself quotes, and uses the benchmark's.
That check exists because two of them were shifted by one: *Audit Detailed File
Share* carried the *Network Policy Server* GUID and *Audit Removable Storage*
carried *Detailed File Share*'s, so both checks silently read the wrong
subcategory.

## Editing the VDI decisions

`NESTED_VIRT` at the top of `build_policies_vdi.py` records whether the
hypervisor exposes nested virtualisation to the guest (it does not on Citrix
Hypervisor/XenServer; it does on vSphere 6.7+, Hyper-V and AVD/W365 Gen2). It is
`False` by default, which excludes the whole 18.9.5 VBS group — those checks
read a registry value that Group Policy writes whether or not VBS actually
starts, so on a platform that cannot run VBS they report Configured for a
desktop with no protection.

All other VDI judgements live in four tables:

- `EXCLUDE` — not applicable to a non-persistent desktop (dropped from the JSON
  so it cannot skew the compliance score, kept in the CSV with the reason)
- `ADJUST` — different value/operator, with the rationale that lands in
  `VDIRationale`
- `TOLERANT_PREFIX` — checks where a missing value is acceptable (the service
  checks, since VDI optimisation baselines remove services outright)
- `NOTES` — kept unchanged, but with an implementation note

Add or change an entry there and re-run step 4; never edit `Policies-VDI.json`
by hand.
