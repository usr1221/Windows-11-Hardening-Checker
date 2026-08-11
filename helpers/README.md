# helpers — regenerating the CIS and VDI policy sets

These four scripts rebuild `Policies-CIS.json`, `Policies-VDI.json` and
`Policies-VDI-Decisions.csv` from the two source documents in the repository
root: the CIS-CAT HTML report and the CIS benchmark PDF. Nothing in the audit
tool depends on them — they exist so the policy sets can be regenerated when CIS
publishes a new benchmark revision, instead of being hand-edited.

## Running the pipeline

```bash
python3 helpers/parse_cis_report.py     # HTML report  -> rules + group titles
python3 helpers/parse_cis_pdf.py        # benchmark PDF -> registry mappings
python3 helpers/build_policies_cis.py   # -> Policies-CIS.json
python3 helpers/build_policies_vdi.py   # -> Policies-VDI.json + decisions CSV
```

Requirements: Python 3.9+ and `pypdf` (step 2 only). Intermediates are cached in
`.cis-build/`; the extracted PDF text is reused unless the PDF is newer.

Each script finds its input in the repository root by glob and stops if it finds
more than one candidate; pass `--report` / `--pdf` to be explicit.

## Where each field comes from

| Field | Source |
|-------|--------|
| `RegistryPath`, `SettingName`, `ValueType` | the benchmark PDF's *Audit* section (`HKLM\...\Key:ValueName`, `REG_DWORD`) |
| `RecommendedValue`, `Operator` | the PDF's expected-value phrase — "900 or less, but not 0" becomes `between 1,900`, "4 or that the key does not exist" becomes `eq 4` + `AbsentIsCompliant` |
| `PolicyPath` | the report's remediation UI path |
| `Notes` | the report's full description + rationale + impact, plus the PDF's default value |
| `Category` | the enclosing benchmark group title |
| `RecommendedSids` | parsed from the CIS recommendation title, cross-checked against `Policies.json` |
| `SettingName` for auditpol | subcategory GUID, from `Policies.json` plus three added here |

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

## Editing the VDI decisions

All VDI judgements live in four tables at the top of `build_policies_vdi.py`:

- `EXCLUDE` — not applicable to a non-persistent desktop (dropped from the JSON
  so it cannot skew the compliance score, kept in the CSV with the reason)
- `ADJUST` — different value/operator, with the rationale that lands in
  `VDIRationale`
- `TOLERANT_PREFIX` — checks where a missing value is acceptable (the service
  checks, since VDI optimisation baselines remove services outright)
- `NOTES` — kept unchanged, but with an implementation note

Add or change an entry there and re-run step 4; never edit `Policies-VDI.json`
by hand.
