# Windows 11 Hardening Audit Tool (ASD / ACSC)

A read-only PowerShell tool that audits a **Windows 11 workstation** against the
Australian Signals Directorate (ASD / ACSC) guide
[*Hardening Microsoft Windows 11 workstations*](https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/system-hardening/hardening-microsoft-windows-11-workstations)
and produces a colour-coded **Excel (.xlsx)** report.

The tool is **read-only** — it never changes any setting. It audits **seven data
sources**, not just the registry:

| CheckType | Source | Covers |
|-----------|--------|--------|
| `Registry` (default) | HKLM / HKCU | Group Policy–backed settings |
| `SecEditAccess` | `secedit /export` | Password & account lockout policy, security options in the SAM/LSA database |
| `SecEditPrivilege` | `secedit /export` | User rights assignments (compared **by SID**, so results are correct on non-English Windows) |
| `AuditPol` | `auditpol /backup` | Advanced audit policy subcategories (compared by **GUID + numeric value**, language-independent) |
| `LocalUser` | `Get-LocalUser` | Built-in Administrator/Guest status & renaming |
| `OptionalFeature` | DISM API | SMBv1, PowerShell 2.0 engine |
| `AppLocker` | `Get-AppLockerPolicy -Effective` | Application control policy presence |

(`secedit /export` and `auditpol /backup` only *write a temp file* — they never
modify configuration.)

## Files

| File | Purpose |
|------|---------|
| `Invoke-Win11HardeningAudit.ps1` | The audit engine + self-contained `.xlsx` writer |
| `Policies.json` | The policy definitions (registry paths, recommended values, priorities). Edit this to add/adjust checks |
| `README.md` | This file |

## Requirements

- Windows 11
- Windows PowerShell 5.1 (built in) or PowerShell 7+
- **No** extra modules and **no** installed copy of Excel are required — the
  `.xlsx` is generated directly via the Open XML format.
- Run from an **elevated (Administrator)** PowerShell for complete results.
  `secedit`, `auditpol` and the DISM feature checks **require elevation**; when
  run as a standard user those checks report **Unknown** (grey) instead of a
  misleading result, and some `HKLM` policy keys may read as *Not Configured*.

## Usage

```powershell
# From the audit_tool folder, in an elevated PowerShell:
powershell -ExecutionPolicy Bypass -File .\Invoke-Win11HardeningAudit.ps1
```

Options:

```powershell
# Choose the output path, also emit a CSV, and open the report when done
.\Invoke-Win11HardeningAudit.ps1 -OutputPath C:\Reports\audit.xlsx -IncludeCsv -OpenWhenDone

# Use a custom policy file
.\Invoke-Win11HardeningAudit.ps1 -PoliciesPath .\MyPolicies.json
```

By default the report is written next to the script as
`Win11_Hardening_Audit_<HOSTNAME>_<TIMESTAMP>.xlsx`.

## The report

**Sheet 1 – Summary:** host/OS info, totals, a compliance score, and a
non-compliant breakdown by priority.

**Sheet 2 – Audit Results:** one row per check, with a frozen header row and
auto-filters, containing the requested columns:

| Column | Meaning |
|--------|---------|
| Category | Grouping from the ASD guide (added for usability) |
| **Policy Name** | The Group Policy / setting name |
| **Scope** | `Computer` (HKLM) or `User` (HKCU) |
| **Policy Path** | Where the setting lives in the Group Policy editor |
| **Registry Path** | The backing registry key |
| **Setting name** | The registry value name |
| **Current Value** | What is configured on this machine (`<not set>` if absent) |
| **Recommended Value** | The ASD-recommended value |
| **Status** | `Configured` / `Mismatch` / `Not Configured` |
| **Priority** | `High` / `Medium` / `Low` |
| Notes | Short explanation (added for usability) |

### Status logic

- **Configured** (green) – the value matches the recommendation.
- **Mismatch** (red) – the value exists but does not match.
- **Not Configured** (yellow) – the value is absent (left at the Windows default).
- **Unknown** (grey) – the data source needs elevation (or the feature, e.g.
  AppLocker, is unsupported on this SKU). Re-run as Administrator. Unknown
  checks are excluded from the compliance score.

> A *Not Configured* result means the hardening setting has not been explicitly
> applied. In a few cases the Windows default is already secure, so treat
> *Not Configured* as "needs review", not automatically "insecure".

### Priority

Priorities reflect the relative risk. **High** items map to controls with the
biggest security impact (e.g. Essential Eight: Attack Surface Reduction rules,
Office macro hardening, credential protection, SMB signing, UAC, firewall).

## Extending / tuning the checks

All checks live in `Policies.json`. Each entry looks like:

```json
{
  "Category": "Network authentication",
  "PolicyName": "Network security: LAN Manager authentication level",
  "Scope": "Computer",
  "PolicyPath": "Computer Configuration\\...\\Security Options",
  "RegistryPath": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
  "SettingName": "LmCompatibilityLevel",
  "ValueType": "DWord",
  "RecommendedValue": "5",
  "Operator": "eq",
  "Priority": "High",
  "Notes": "5 = Send NTLMv2 response only; refuse LM and NTLM."
}
```

`Operator` controls the comparison:

| Operator | Meaning |
|----------|---------|
| `eq` | equals (numeric or string) |
| `ne` | not equal |
| `ge` | current ≥ recommended (numeric) |
| `le` | current ≤ recommended (numeric) |
| `between` | recommended is `"min,max"`; current must fall inside (e.g. lockout threshold `"1,5"`) |
| `oneof` | matches any value in a comma-separated list (e.g. `"1,2"`) |
| `contains` | current value contains every comma-separated token (used for multi-field values such as Hardened UNC Paths) |

`SecEditPrivilege` checks use set operators against `RecommendedSids`:

| Operator | Meaning |
|----------|---------|
| `subsetof` | every account holding the right must be in the allowlist (fewer is fine) |
| `contains` | the listed accounts (e.g. Guests in a deny right) must all be present |
| `setequals` | exact set match — with empty `RecommendedSids` this means "No one" |

`AuditPol` checks use `RequiredFlags` (1 = Success, 2 = Failure, 3 = both); the
current setting must include at least the required flags.

Add a new object to the array, save, and re-run — no code changes needed.

## Coverage and limitations

This release ships **407 checks**:

- **329 registry-based checks** spanning: Attack Surface Reduction (incl.
  vulnerable-signed-driver block), Microsoft Defender Antivirus (incl. Block at
  First Sight, Network Protection, exclusion hardening, PUA, heuristics,
  quarantine, file-hash computation, MAPS override lockdown), Controlled Folder
  Access (incl. protected folders / allowed apps), credential caching / LSA
  protection / Credential Guard / CredSSP / credential delegation / Custom SSP
  block / trusted-path credential prompts, User Account Control, local
  administrator accounts & LAPS (backup directory, encryption, complexity,
  length, age), Windows Hello for Business (PIN complexity/length/expiration,
  TPM, biometrics), Microsoft accounts, anonymous & network access, NTLM / LAN
  Manager & NTLM session security (incl. LDAP client signing, Kerberos
  encryption types, NULL session fallback), SMB signing & SMBv1, secure
  channel (incl. machine account password age), LLMNR, insecure guest logons,
  RPC hardening (incl. packet-level privacy), MSS network-stack settings,
  Hardened UNC Paths, Remote Desktop & Remote Assistance (incl. clipboard /
  server authentication), PowerShell logging & signing, Command Prompt &
  registry tools, Autoplay/AutoRun, BitLocker & DMA protection (fixed / OS /
  removable drives, passwords, encryption type, recovery, enhanced PIN, Secure
  Boot integrity), Secure Launch, Early Launch Antimalware, SEHOP / DEP,
  SmartScreen / Enhanced Phishing Protection, Mark-of-the-Web / Attachment
  Manager, session & lock screen (incl. logon screen network-selection UI,
  CTRL+ALT+DEL enforcement, safe-mode admin-only, convenience PIN sign-in),
  event log sizing, command-line process auditing, WinRM/WinRS, Windows Search
  & Cortana, Windows Defender Firewall (incl. logging), Windows Installer,
  print hardening (PrintNightmare / Point and Print / Redirection Guard / RPC
  connection / listener / TCP port / driver signature validation / queue file
  processing), MSDT (Follina mitigation), legacy run lists, network bridging,
  power management (standby S1-S3, hibernate / sleep / unattended / hybrid
  sleep timeouts, power-menu visibility), diagnostic data, Microsoft Edge and
  Office macro hardening, Windows Update (Automatic Updates, WSUS server,
  pause-updates lockdown), removable storage classes (CD/DVD, removable disks,
  tape drives, WPD - read/write/execute deny), device installation
  restrictions, Group Policy processing (registry / security policy background
  refresh, RSoP data generation), cryptography (FIPS, force-strong-key
  protection), location services, Microsoft Store lockdown, Windows Ink
  Workspace, Windows Copilot, Windows spotlight 3rd-party content, app
  privacy (voice activation on lock), corporate Windows Error Reporting, app
  compatibility inventory, Sound Recorder, W32time NTP client, Wi-Fi
  auto-hotspot behaviour, and Windows Explorer hardening (file extensions,
  Security tab, CD burning, per-profile file sharing).
- **13 account-policy checks** (password history/age/length/complexity,
  reversible encryption, lockout threshold/duration/reset, admin lockout,
  relax-min-length, anonymous SID translation, force logoff) via `secedit`.
- **27 user-rights-assignment checks** via `secedit`, compared by SID
  (incl. Change system time, Allow log on through RDS, Deny batch/service
  logon).
- **30 advanced-audit-policy subcategory checks** via `auditpol`, compared by
  GUID and numeric value.
- **4 built-in account checks** (Administrator/Guest disabled & renamed) via
  `Get-LocalUser`.
- **3 Windows feature checks** (SMBv1, PowerShell 2.0) via DISM.
- **1 application-control presence check** (AppLocker effective policy).

### How coverage was verified

The policy set was cross-checked against the **authoritative list of ~600
settings** in Microsoft's official *Intune ACSC Windows Hardening Guidelines*
implementation of this guide. Remaining intentional exclusions:

- **~200 Internet Explorer 11 security-zone settings** — IE11 is removed from
  Windows 11, so these keys do not apply. (Edge hardening is covered instead.)
- A small number of list-valued / device-inventory settings (device-install
  allow/deny lists, removable-storage class GUID rules) that require
  environment-specific values rather than a single recommended value.

**Known limitations:**

- **AppLocker check is presence-only.** It confirms an effective policy with
  rules exists — it cannot judge rule quality/coverage, and it does not detect
  WDAC (a valid alternative). Application control needs manual review.
- **User scope = current user.** `HKCU` checks reflect the account that runs the
  script, not every profile on the machine.
- **Localized built-in account names.** On non-English Windows the default
  Guest/Administrator names may be translated (e.g. `Gość`), so the "renamed"
  checks can pass as a locale artifact — verify manually.
- **Recommended values should be validated against the live guide.** Microsoft
  and the ASD update guidance over time. Treat `Policies.json` as a baseline to
  review against the current published version, and adjust the few values that
  are environment-dependent (e.g. event-log sizes, telemetry level, audit
  Success/Failure levels, lockout duration, whether RDP is required at all).

## Source

- ASD / ACSC — *Hardening Microsoft Windows 11 workstations*:
  <https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/system-hardening/hardening-microsoft-windows-11-workstations>
- Microsoft — *Intune ACSC Windows Hardening Guidelines*:
  <https://github.com/microsoft/Intune-ACSC-Windows-Hardening-Guidelines>
