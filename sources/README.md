# sources — inputs for the policy-set generators

The generators in `helpers/` read their source documents from this folder (and,
as a fallback, from the repository root). Nothing here is needed to *run* an
audit — only to rebuild a file in `policies/`.

| Policy set | Files expected here | Where to get them |
|------------|---------------------|-------------------|
| `Policies-CIS.json` (+ VDI) | `CIS_Microsoft_Windows_11_Enterprise_Benchmark_*.pdf` and a CIS-CAT HTML report whose name contains `CIS_Microsoft_Windows_11` | Benchmark PDF: [cisecurity.org](https://www.cisecurity.org/benchmark/microsoft_windows_desktop). Report: a CIS-CAT run against a Windows 11 machine. |
| `Policies-CIS-Server<year>-{MS,DC}.json` | `CIS_Microsoft_Windows_Server_<year>_Benchmark_*.pdf` (one per year) | [cisecurity.org](https://www.cisecurity.org/benchmark/microsoft_windows_server) — free, after a registration form |
| `Policies-Edge.json` | `*Edge*.PolicyRules` and the converted `*edge*.xlsx` audit report | Microsoft Security Compliance Toolkit (Policy Analyzer); convert with `tools/Convert-PolicyAnalyzerToXlsx.ps1` |

Keep one file per benchmark: a generator stops when it finds two candidates
(pass `--pdf` / `--report` to choose explicitly).

## Why this folder is git-ignored

The CIS terms of use say it is never acceptable to host a CIS Benchmark, in any
format, on a non-CIS site, and CIS-CAT or Policy Analyzer reports describe the
host they ran on. `.gitignore` therefore excludes everything here except this
README.

Ignoring does not untrack a file that was committed before the rule existed.
To stop distributing one that is already in the repository:

```bash
git rm --cached sources/<file>.pdf
```

(It stays in earlier commits; removing it from history needs a history rewrite.)
