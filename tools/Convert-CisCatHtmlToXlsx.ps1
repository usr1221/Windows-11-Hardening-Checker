<#
.SYNOPSIS
    Converts a CIS-CAT benchmark HTML report to an Excel (.xlsx) workbook that
    matches the format produced by Invoke-Win11HardeningAudit.ps1.

.DESCRIPTION
    Reads a CIS-CAT Pro Assessor HTML report (v4 or Legacy Bundle), extracts the
    benchmark metadata, per-rule results, and score, and writes a colour-coded
    Excel workbook with the same two-sheet layout as the audit tool:

        Sheet 1 - Summary       host/benchmark info + totals + score
        Sheet 2 - Audit Results one row per CIS rule (frozen header, filters)

    CIS-CAT result mapping to the tool's Status column:
        Pass            -> Configured        (green)
        Fail            -> Mismatch          (red)
        Error           -> Unknown           (grey)
        Unknown         -> Unknown           (grey)
        Not Applicable  -> Not Configured    (yellow)
        Informational   -> Not Configured    (yellow)
        Not Checked     -> Not Configured    (yellow)
        Not Selected    -> Not Configured    (yellow)

    Priority uses the CIS rule severity/level (or "Medium" if not present).

    Like the audit tool, the .xlsx is produced with the built-in Open XML writer
    - NO ImportExcel module and NO Excel install required.

.PARAMETER InputPath
    Path to the CIS-CAT HTML report (required).

.PARAMETER OutputPath
    Path of the .xlsx to create. Defaults to <InputPath basename>.xlsx.

.PARAMETER OpenWhenDone
    Open the report when finished (Windows only).

.EXAMPLE
    .\Convert-CisCatHtmlToXlsx.ps1 -InputPath .\CIS_Windows11_Report.html

.EXAMPLE
    .\Convert-CisCatHtmlToXlsx.ps1 -InputPath .\report.html `
        -OutputPath C:\Reports\ciscat.xlsx -OpenWhenDone
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,

    [string]$OutputPath,

    [switch]$OpenWhenDone
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $InputPath)) {
    throw "CIS-CAT HTML report not found: $InputPath"
}
$InputPath = (Resolve-Path -LiteralPath $InputPath).ProviderPath

if (-not $OutputPath) {
    $OutputPath = [System.IO.Path]::ChangeExtension($InputPath, '.xlsx')
}

Write-Host "CIS-CAT HTML -> XLSX converter" -ForegroundColor Cyan
Write-Host ("  Input  : {0}" -f $InputPath)
Write-Host ("  Output : {0}" -f $OutputPath)

$html = Get-Content -Path $InputPath -Raw -Encoding UTF8

# --------------------------------------------------------------------------
#  HTML parsing helpers
# --------------------------------------------------------------------------
function Convert-HtmlToText {
    # Strip tags, decode common entities, collapse whitespace.
    param([string]$Html)
    if ([string]::IsNullOrEmpty($Html)) { return '' }
    $t = $Html
    $t = [regex]::Replace($t, '(?is)<script.*?</script>', ' ')
    $t = [regex]::Replace($t, '(?is)<style.*?</style>',  ' ')
    $t = [regex]::Replace($t, '(?is)<br\s*/?>', "`n")
    $t = [regex]::Replace($t, '<[^>]+>', ' ')
    $t = $t -replace '&nbsp;', ' '
    $t = $t -replace '&amp;',  '&'
    $t = $t -replace '&lt;',   '<'
    $t = $t -replace '&gt;',   '>'
    $t = $t -replace '&quot;', '"'
    $t = $t -replace '&#39;',  "'"
    $t = $t -replace '&apos;', "'"
    # decode numeric entities
    $t = [regex]::Replace($t, '&#(\d+);', { param($m) [char][int]$m.Groups[1].Value })
    $t = [regex]::Replace($t, '&#x([0-9a-fA-F]+);', { param($m) [char][Convert]::ToInt32($m.Groups[1].Value, 16) })
    # collapse whitespace
    $t = ($t -replace '\s+', ' ').Trim()
    return $t
}

function Get-FirstMatch {
    param([string]$Text, [string[]]$Patterns)
    foreach ($p in $Patterns) {
        $m = [regex]::Match($Text, $p, 'IgnoreCase, Singleline')
        if ($m.Success -and $m.Groups.Count -ge 2) { return $m.Groups[1].Value.Trim() }
    }
    return ''
}

# --------------------------------------------------------------------------
#  Benchmark / target metadata
# --------------------------------------------------------------------------
$plainAll = Convert-HtmlToText $html

# Benchmark title.  CIS-CAT report has:
#   <title>Benchmark Result xccdf_..._CIS_Google_Chrome_Group_Policy_Benchmark</title>
#   <h2>CIS Google Chrome Group Policy Benchmark v1.0.0</h2>
# Prefer the h2 (contains the human-readable name + version).
$benchmarkTitle = ''
foreach ($m in [regex]::Matches($html, '(?is)<h2[^>]*>(?<t>[^<]*CIS\s[^<]*?Benchmark[^<]*)</h2>')) {
    $benchmarkTitle = Convert-HtmlToText $m.Groups['t'].Value
    if ($benchmarkTitle) { break }
}
if (-not $benchmarkTitle) {
    $benchmarkTitle = Convert-HtmlToText (Get-FirstMatch $html @(
        '<h1[^>]*>([^<]*Assessment[^<]*)</h1>',
        '<title[^>]*>(.*?)</title>'
    ))
}
if (-not $benchmarkTitle) { $benchmarkTitle = 'CIS Benchmark' }

$benchmarkVersion = Get-FirstMatch $benchmarkTitle @(
    '\bv(\d+(?:\.\d+){1,3})\b',
    '\bVersion\s+(\d+(?:\.\d+){1,3})\b'
)

# Target host: the CIS-CAT cover page has "<h1>Security Configuration
# Assessment Report</h1><h1>for HOSTNAME</h1>", plus "Target IP Address: X".
$targetHost = Convert-HtmlToText (Get-FirstMatch $html @(
    '<h1[^>]*>\s*for\s+([^<]+?)\s*</h1>'
))
if (-not $targetHost) {
    $targetHost = Get-FirstMatch $plainAll @(
        'Host\s*Name[:\s]+([^\s|]+)',
        'Target[:\s]+([^\s|]+)',
        'Hostname[:\s]+([^\s|]+)'
    )
}

$targetIp = Get-FirstMatch $plainAll @(
    'Target\s*IP\s*Address[:\s]+([0-9a-fA-F.:]+)',
    'IP\s*Address[:\s]+([0-9a-fA-F.:]+)'
)

# OS field: CIS-CAT HTML reports typically omit it from the cover page, so we
# only take it from a target-facts-style label if present, and only if short.
$targetOs = ''
$osMatch = [regex]::Match($html, '(?is)Target\s*Operating\s*System[:\s]*</[^>]+>\s*<[^>]+>([^<]{1,80})<')
if ($osMatch.Success) { $targetOs = (Convert-HtmlToText $osMatch.Groups[1].Value) }

# Assessment time: prefer the <meta name="date" content="..."> tag.
$assessmentTime = Get-FirstMatch $html @(
    '<meta[^>]*name="date"[^>]*content="([^"]+)"'
)
if (-not $assessmentTime) {
    $assessmentTime = Get-FirstMatch $plainAll @(
        'Assessment\s*(?:Start\s*)?Time[:\s]+(\d{4}-\d{2}-\d{2}[T\s][\d:.]+(?:Z|[+\-]\d{2}:?\d{2})?)',
        'Timestamp[:\s]+(\d{4}-\d{2}-\d{2}[T\s][\d:.]+(?:Z|[+\-]\d{2}:?\d{2})?)'
    )
}

# Score: CIS-CAT stores the numeric score on <div class="gauge" data-score="NN">.
$score = Get-FirstMatch $html @(
    '<div[^>]*class="gauge"[^>]*data-score="([0-9]+(?:\.[0-9]+)?)"',
    'Score[:\s]+([0-9]+(?:\.[0-9]+)?\s*%?)'
)

# --------------------------------------------------------------------------
#  Rule extraction
#
#  CIS-CAT Pro Assessor writes each rule as
#     <div id="detail-..." class="Rule ...">
#       <span class="outcome pass|fail|error|... ruleResultArea">Label</span>
#       <h3 class="ruleTitle" title="xccdf_...">1.2.3 (L1) Ensure ...</h3>
#       <div class="description">...</div>
#       <div class="rationale">...</div>
#       <div class="fixtext">
#         <code class="code_block">Computer Configuration\Policies\...</code>
#       </div>
#       <div class="check">... Criterion: Ensure 'X' is '...' to 'Y' ...</div>
#     </div>
#
#  Section headings that precede the rule blocks are
#     <h2 class="ruleGroupTitle" title="xccdf_..._group_2.2_Content_Settings">
#         2.2 Content Settings
#     </h2>
#
#  Rule divs contain other divs, so we can't safely non-greedy-match them.
#  Instead we walk the list of rule-block start positions and slice each
#  rule's body from position[i] to position[i+1].
# --------------------------------------------------------------------------
$resultKeywords = @(
    'pass','fail','error','unknown','informational','notchecked',
    'notselected','notapplicable'
)
$rkPattern = ($resultKeywords -join '|')

# Primary CIS-CAT pattern: outcome span followed by the ruleTitle heading.
$primaryRegex = "(?is)<span[^>]*class=`"outcome\s+(?<res>$rkPattern)\b[^`"]*`"[^>]*>[^<]*</span>\s*<h3[^>]*class=`"ruleTitle`"[^>]*>(?<title>.*?)</h3>"

# Fallback patterns for other CIS-CAT layouts (Legacy Bundle).
$fallbackRegex = @(
    "(?is)<div[^>]*class=`"[^`"]*\b(?<res>$rkPattern)\b[^`"]*`"[^>]*>(?<body>.*?)</div>",
    "(?is)<tr[^>]*class=`"[^`"]*\b(?<res>$rkPattern)\b[^`"]*`"[^>]*>(?<body>.*?)</tr>"
)

# Match "2.2.3 (L1) Ensure ..." -> id="2.2.3" level="1" title="Ensure ..."
$titlePrefixRegex = '^\s*(?<id>\d+(?:\.\d+){0,6})(?:\s*\((?<lvl>L?[12A-Za-z]+)\))?\s*(?<rest>.*)$'
$ruleIdRegex      = '(?<![\w.])(\d+(?:\.\d+){1,6})(?![\w.])'
$titleTagRegex    = '(?is)<(?:span|a|h[1-6]|td)[^>]*class="[^"]*(?:ruleTitle|rule-title|check-title)[^"]*"[^>]*>(.*?)</(?:span|a|h[1-6]|td)>'

function Get-EvidenceTableValue {
    # Parse a single <table class="evidence"> block.
    #   - If it's just the "No matching system items were found." single-cell
    #     table, return that literal string.
    #   - If it has <th> headers (e.g. Item Name | Type | Status | Value),
    #     parse each <tr> row, pick the row whose "Item Name" matches the
    #     rule's setting name, and return only that row's "Value" column.
    #     Otherwise join remaining rows as "Name=Value; Name=Value;".
    param([string]$TableHtml, [string]$SettingName)

    if (-not $TableHtml) { return '' }

    # Extract header cells (<th>...</th>) if present.
    $headers = @()
    foreach ($h in [regex]::Matches($TableHtml, '(?is)<th[^>]*>(?<t>.*?)</th>')) {
        $headers += (Convert-HtmlToText $h.Groups['t'].Value)
    }

    # Extract data rows (<tr>...</tr>) excluding rows that only contain <th>.
    # Also collect every row CIS-CAT flagged as class="evaluated" - those are
    # the rows the criterion actually tested and whose Value we want.
    $dataRows         = New-Object System.Collections.Generic.List[object]
    $evaluatedIndexes = New-Object System.Collections.Generic.List[int]
    foreach ($rm in [regex]::Matches($TableHtml, '(?is)<tr(?<attrs>[^>]*)>(?<r>.*?)</tr>')) {
        $rowHtml  = $rm.Groups['r'].Value
        $rowAttrs = $rm.Groups['attrs'].Value
        if ($rowHtml -notmatch '(?is)<td[^>]*>') { continue }
        $cells = @()
        foreach ($cm in [regex]::Matches($rowHtml, '(?is)<td[^>]*>(?<c>.*?)</td>')) {
            $cells += (Convert-HtmlToText $cm.Groups['c'].Value)
        }
        if ($cells.Count -gt 0) {
            [void]$dataRows.Add([object[]]$cells)
            if ($rowAttrs -match '\bclass="[^"]*\bevaluated\b') {
                [void]$evaluatedIndexes.Add($dataRows.Count - 1)
            }
        }
    }

    # Fallback: no <th> headers.  Handle two shapes:
    #   (1) single-cell tables ("No matching system items were found.")
    #   (2) 1-row 2-cell "label: content" tables like
    #         <td class="bold">Output:</td><td><ul>...</ul></td>
    #       -> return just the content cell (script check output can be long)
    if ($headers.Count -eq 0 -and $dataRows.Count -le 1) {
        if ($dataRows.Count -eq 1 -and $dataRows[0].Count -eq 2 `
            -and $dataRows[0][0] -match ':\s*$') {
            $content = $dataRows[0][1]
            if ($content.Length -le 1000) { return $content }
            return $content.Substring(0, 997) + '...'
        }
        $flat = Convert-HtmlToText $TableHtml
        if ($flat.Length -le 500) { return $flat }
        return $flat.Substring(0, 497) + '...'
    }

    # Header-driven parse.  Locate the Item Name and Value columns.
    $nameCol  = -1
    $valueCol = -1
    for ($i = 0; $i -lt $headers.Count; $i++) {
        $h = $headers[$i].ToLowerInvariant()
        if ($nameCol  -lt 0 -and $h -match '^(item\s*name|name|item)$') { $nameCol  = $i }
        if ($valueCol -lt 0 -and $h -match '^(value|current\s*value|actual|data)$') { $valueCol = $i }
    }

    if ($valueCol -lt 0) {
        # No dedicated Value column - fall back to flat text (capped).
        $flat = Convert-HtmlToText $TableHtml
        if ($flat.Length -le 200) { return $flat }
        return ''
    }

    # Priority 1: CIS-CAT marks the row(s) it actually tested with
    # <tr class="evaluated">.  For "Windows: Registry Value" checks the
    # engine typically flags TWO rows - one for Type (whose Value column
    # holds "reg_dword"/"reg_sz"/etc.) and one for Value (whose Value
    # column holds the actual data).  Prefer the Value row so we don't
    # report the type as the current value.
    if ($evaluatedIndexes.Count -gt 0 -and $nameCol -ge 0) {
        foreach ($ei in $evaluatedIndexes) {
            $row = $dataRows[$ei]
            if ($row.Count -le [Math]::Max($nameCol, $valueCol)) { continue }
            if ($row[$nameCol].Trim().ToLowerInvariant() -eq 'value') {
                return $row[$valueCol]
            }
        }
    }
    if ($evaluatedIndexes.Count -gt 0) {
        $row = $dataRows[$evaluatedIndexes[0]]
        if ($row.Count -gt $valueCol) { return $row[$valueCol] }
    }

    # Priority 1b: entity-item tables (Registry Item / File Item / etc.)
    # list the entity's properties row-by-row with the actual runtime data
    # in the row where Name column = "Value".  If no evaluated marker is
    # present but such a row exists, prefer it over a joined dump.
    if ($nameCol -ge 0) {
        foreach ($row in $dataRows) {
            if ($row.Count -le [Math]::Max($nameCol, $valueCol)) { continue }
            if ($row[$nameCol].Trim().ToLowerInvariant() -eq 'value') {
                return $row[$valueCol]
            }
        }
    }

    # Priority 2: match the current rule's setting name against Item Name.
    if ($SettingName -and $nameCol -ge 0) {
        $sn = $SettingName.ToLowerInvariant()
        # Common short-form aliases (Passwd/Password, Len/Length, Min/Minimum).
        $variants = @($sn, $sn.Replace('password','passwd'),
                      $sn.Replace('length','len'),
                      $sn.Replace('minimum','min').Replace('maximum','max'))
        foreach ($row in $dataRows) {
            if ($row.Count -le [Math]::Max($nameCol, $valueCol)) { continue }
            $rn = $row[$nameCol].ToLowerInvariant()
            foreach ($v in $variants) {
                if ($rn -eq $v -or $rn -like "*$v*" -or $v -like "*$rn*") {
                    return $row[$valueCol]
                }
            }
        }
    }

    # No setting-name match - join every row as "Name=Value; ...".
    $parts = @()
    foreach ($row in $dataRows) {
        if ($row.Count -le [Math]::Max($nameCol, $valueCol)) { continue }
        if ($nameCol -ge 0) {
            $parts += ('{0}={1}' -f $row[$nameCol], $row[$valueCol])
        } else {
            $parts += $row[$valueCol]
        }
    }
    if ($parts.Count -eq 0) { return '' }
    return ($parts -join '; ')
}

function Get-RuleDetails {
    # Extract Scope, Policy Path, Setting Name, Current Value, Recommended Value,
    # description from the HTML body of a single CIS-CAT rule.
    param([string]$Body, [string]$RawResult, [string]$TitleText)

    $out = @{
        Scope             = ''
        PolicyPath        = ''
        RegistryPath      = ''
        SettingName       = ''
        CurrentValue      = ''
        RecommendedValue  = ''
        DescriptionSnippet= ''
    }

    # Group Policy path from <code class="code_block">
    $m = [regex]::Match($Body, '(?is)<code[^>]*class="code_block"[^>]*>(.*?)</code>')
    if ($m.Success) {
        $gp = Convert-HtmlToText $m.Groups[1].Value
        if ($gp -match '^(Computer|User)\s+Configuration') {
            $out.Scope = $Matches[1]
            $out.PolicyPath = $gp
        } elseif ($gp) {
            $out.PolicyPath = $gp
        }
    }

    # Criterion: "Ensure 'ValueName' is 'Windows: Registry Value' to 'ExpectedValue'"
    # Walk every match and prefer a real registry-value check over the "Existence
    # Test" checks CIS-CAT emits for allowlist rules (those show \d+ / none_exist).
    foreach ($cri in [regex]::Matches($Body,
        "(?is)Ensure\s+'([^']+)'\s+is\s+'([^']+)'\s+(?:to|equal(?:s)?|set\s+to)\s+'([^']+)'")) {
        $name  = $cri.Groups[1].Value.Trim()
        $check = $cri.Groups[2].Value.Trim()
        $expct = $cri.Groups[3].Value.Trim()

        # Skip OVAL placeholder criteria (existence tests, regex checks).
        if ($check -match '^(Existence Test|None Exist|At Least One Exists)$') { continue }
        if ($name  -in @('\d+','\w+','.*')) { continue }
        if ($expct -in @('none_exist','at_least_one_exists','all_exist')) { continue }

        # Safety: if a flattened table has leaked into the criterion (very long
        # name / expected value), skip and let the title fallback fill in.
        if ($name.Length  -gt 120) { continue }
        if ($expct.Length -gt 120) { continue }

        $out.SettingName      = $name
        $out.RecommendedValue = $expct
        # Some benchmarks embed a full registry path in the criterion
        # (e.g. "HKLM\Software\...\ValueName"); if so, split it out.
        if ($out.SettingName -match '^(HK[A-Z_]+\\[^\\]+(?:\\[^\\]+)*)\\([^\\]+)$') {
            $out.RegistryPath = $Matches[1]
            $out.SettingName  = $Matches[2]
        }
        break
    }

    # Current value comes from the "Assessment Evidence" section (from the
    # <table class="evidence"> block that follows the criterion table).  Two
    # shapes to handle:
    #
    #   (a) Single-cell "No matching system items were found."          -> take verbatim
    #   (b) Multi-row structured table with headers e.g.
    #         | Item Name | Type | Status | Value |
    #         | Max Passwd Age | Int | Exists | 3628800 |
    #         | Min Passwd Age | Int | Exists | 0       |
    #       -> parse each row, pick the row whose Item Name matches this
    #          rule's setting name, and take just its Value column.  If no
    #          row matches, join the remaining rows as "Name=Value; ...".
    #
    # Manual / notchecked / informational rules have no evidence table.
    if ($RawResult -eq 'notchecked' -or $RawResult -eq 'informational' -or
        $RawResult -eq 'notselected' -or $RawResult -eq 'notapplicable') {
        $out.CurrentValue = 'Manual review required'
    } else {
        # Restrict to the visible check block so we don't grab the hidden
        # <pre>&lt;xccdf:rule-result&gt;...&lt;/pre&gt; dump beneath it.
        $checkBlock = [regex]::Match($Body,
            '(?is)<div[^>]*class="check"[^>]*>(?<c>.*?)(?=<br>\s*<div><span[^>]*class="action"|</div>\s*<script)')
        $scanIn = if ($checkBlock.Success) { $checkBlock.Groups['c'].Value } else { $Body }

        # Collect every evidence table, then pick the best one.  Placeholder
        # tables ("No error lines were collected." from Script Check Engine
        # rules) are demoted so a companion "Output:" table wins over them.
        $candidates = New-Object System.Collections.Generic.List[object]
        foreach ($vm in [regex]::Matches($scanIn,
            '(?is)<table[^>]*class="evidence"[^>]*>(?<t>.*?)</table>')) {
            $parsed = Get-EvidenceTableValue -TableHtml $vm.Groups['t'].Value -SettingName $out.SettingName
            if ($parsed) { [void]$candidates.Add($parsed) }
        }
        $best = ''
        foreach ($c in $candidates) {
            if ($c -match '^\s*No error lines were collected\.?\s*$') { continue }
            $best = $c; break
        }
        if (-not $best -and $candidates.Count -gt 0) { $best = $candidates[0] }
        $out.CurrentValue = $best
    }

    # --- Title-based fallbacks ---------------------------------------------
    # If the criterion didn't yield a setting name / recommended value (e.g.
    # the rule uses an existence-test allowlist check, or is manual with no
    # evidence at all), fall back to parsing the rule title, which follows
    # patterns such as:
    #   Ensure 'Setting Name' is set to 'Recommended Value'
    #   Ensure 'Setting Name' Is 'Recommended Value'
    #   Ensure 'Setting Name' Is Configured
    #   Ensure 'Setting Name' Is Disabled
    if ($TitleText) {
        if (-not $out.SettingName) {
            $nm = [regex]::Match($TitleText, "Ensure\s+'([^']+)'")
            if ($nm.Success) { $out.SettingName = $nm.Groups[1].Value.Trim() }
        }
        if (-not $out.RecommendedValue) {
            $tail = $TitleText
            $stripped = [regex]::Match($tail, "Ensure\s+'[^']+'\s*(?<r>.+)$")
            if ($stripped.Success) { $tail = $stripped.Groups['r'].Value.Trim() }
            $rm = [regex]::Match($tail,
                "(?i)^(?:(?:is|are|has been)\s+(?:set\s+to\s+)?)?'(?<v>[^']+)'")
            if ($rm.Success) {
                $out.RecommendedValue = $rm.Groups['v'].Value.Trim()
            } elseif ($tail -match '(?i)\b(Is|are)\s+(Configured|Disabled|Enabled|Not\s+Configured)\b') {
                $out.RecommendedValue = $Matches[2]
            }
        }
    }

    # First paragraph of the description, trimmed to a snippet.
    $dm = [regex]::Match($Body,
        '(?is)<div\s+class="description">.*?<p>(?<p>.*?)</p>')
    if ($dm.Success) {
        $desc = Convert-HtmlToText $dm.Groups['p'].Value
        if ($desc.Length -gt 220) { $desc = $desc.Substring(0, 217) + '...' }
        $out.DescriptionSnippet = $desc
    }

    return $out
}

function New-ResultRow {
    param(
        [string]$Category,
        [string]$RuleId,
        [string]$Title,
        [string]$RawResult,
        [string]$Level,
        [hashtable]$Details
    )

    $r = $RawResult.ToLowerInvariant()
    switch ($r) {
        'pass'          { $status = 'Configured';     break }
        'fail'          { $status = 'Mismatch';       break }
        'error'         { $status = 'Unknown';        break }
        'unknown'       { $status = 'Unknown';        break }
        'informational' { $status = 'Not Configured'; break }
        'notchecked'    { $status = 'Not Configured'; break }
        'notselected'   { $status = 'Not Configured'; break }
        'notapplicable' { $status = 'Not Configured'; break }
        default         { $status = 'Unknown' }
    }

    # CIS levels: L2 -> High (more restrictive), L1 -> Medium.
    $priority = 'Medium'
    if     ($Level -match '2') { $priority = 'High' }
    elseif ($Level -match '1') { $priority = 'Medium' }

    $notes = if ($Level) { "CIS Level $Level" } else { '' }
    if ($Details.DescriptionSnippet) {
        if ($notes) { $notes = "$notes. $($Details.DescriptionSnippet)" }
        else        { $notes = $Details.DescriptionSnippet }
    }

    [pscustomobject]@{
        Category           = $Category
        'Policy Name'      = if ($RuleId) { "$RuleId  $Title" } else { $Title }
        Scope              = $Details.Scope
        'Policy Path'      = $Details.PolicyPath
        'Registry Path'    = $Details.RegistryPath
        'Setting name'     = $Details.SettingName
        'Current Value'    = $Details.CurrentValue
        'Recommended Value'= $Details.RecommendedValue
        Status             = $status
        Priority           = $priority
        Notes              = $notes
        RawResult          = $RawResult
    }
}

# Section catalogue.  CIS-CAT uses <h2 class="ruleGroupTitle" title="xccdf_...">
# and (for the summary) plain <h2>/<h3> headings.  Both are captured here so
# each rule can find its enclosing group.
$sections = New-Object System.Collections.Generic.List[object]
$sectionRegexes = @(
    '(?is)<h2[^>]*class="ruleGroupTitle"[^>]*>(?<t>.*?)</h2>',
    '(?is)<h([2-4])[^>]*>(?<t>[^<]*?)</h[2-4]>'
)
$sectionSeen = @{}
foreach ($rgx in $sectionRegexes) {
    foreach ($m in [regex]::Matches($html, $rgx)) {
        $text = Convert-HtmlToText $m.Groups['t'].Value
        if ($text -match '^\s*(\d+(?:\.\d+){0,3})\s+(.+?)\s*$') {
            $key = "$($m.Index):$($Matches[1])"
            if ($sectionSeen.ContainsKey($key)) { continue }
            $sectionSeen[$key] = $true
            $sections.Add([pscustomobject]@{
                Position = $m.Index
                Number   = $Matches[1]
                Title    = $Matches[2]
            })
        }
    }
}
$sections = $sections | Sort-Object Position

function Get-SectionForRule {
    param([string]$RuleId, [int]$Pos)
    # First try to match by the id's parent prefix (e.g. rule 2.2.3 -> group 2.2).
    $parts = $RuleId -split '\.'
    if ($parts.Count -ge 2) {
        $parent = ($parts[0..($parts.Count - 2)] -join '.')
        $bySection = $sections | Where-Object { $_.Number -eq $parent } | Select-Object -First 1
        if ($bySection) { return "$($bySection.Number) $($bySection.Title)" }
    }
    # Fall back to nearest preceding heading.
    $cur = $null
    foreach ($s in $sections) {
        if ($s.Position -le $Pos) { $cur = $s } else { break }
    }
    if ($cur) { return "$($cur.Number) $($cur.Title)" }
    return ''
}

$rows = New-Object System.Collections.Generic.List[object]
$seen = @{}

# --- Primary pass ----------------------------------------------------------
# Slice each rule's full body from its <div id="detail-..." class="Rule ...">
# start position to the start of the next rule.  The full body is needed to
# extract the Group Policy path, setting name, current value, etc.
$ruleStartRegex = '(?is)<div\s+id="detail-[^"]+"\s+class="[^"]*\bRule\b[^"]*"[^>]*>'
$startMatches = [regex]::Matches($html, $ruleStartRegex)

for ($i = 0; $i -lt $startMatches.Count; $i++) {
    $from = $startMatches[$i].Index
    $to   = if ($i + 1 -lt $startMatches.Count) { $startMatches[$i + 1].Index } else { $html.Length }
    $body = $html.Substring($from, $to - $from)

    $om = [regex]::Match($body, "(?is)<span[^>]*class=`"outcome\s+(?<res>$rkPattern)\b[^`"]*`"[^>]*>[^<]*</span>")
    if (-not $om.Success) { continue }
    $res = $om.Groups['res'].Value

    $tm = [regex]::Match($body, '(?is)<h3[^>]*class="ruleTitle"[^>]*>(?<t>.*?)</h3>')
    if (-not $tm.Success) { continue }
    $titleTxt = Convert-HtmlToText $tm.Groups['t'].Value
    if (-not $titleTxt) { continue }

    $ruleId = ''; $level = ''; $title = $titleTxt
    $pm = [regex]::Match($titleTxt, $titlePrefixRegex)
    if ($pm.Success) {
        $ruleId = $pm.Groups['id'].Value
        $lvlRaw = $pm.Groups['lvl'].Value
        if ($lvlRaw -match '([12])') { $level = $Matches[1] }
        $title  = $pm.Groups['rest'].Value.Trim()
    }
    if (-not $ruleId) { continue }

    $key = "$ruleId|$($res.ToLowerInvariant())"
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true

    $details  = Get-RuleDetails -Body $body -RawResult $res.ToLowerInvariant() -TitleText $titleTxt
    $category = Get-SectionForRule -RuleId $ruleId -Pos $from
    $rows.Add((New-ResultRow -Category $category -RuleId $ruleId -Title $title `
                             -RawResult $res -Level $level -Details $details)) | Out-Null
}

# --- Fallback pass ---------------------------------------------------------
# Only runs if the primary pass found nothing (legacy CIS-CAT layouts using
# <div class="pass|fail"> or <tr class="pass|fail"> around the rule).
if ($rows.Count -eq 0) {
    foreach ($pattern in $fallbackRegex) {
        foreach ($m in [regex]::Matches($html, $pattern)) {
            $res  = $m.Groups['res'].Value
            $body = $m.Groups['body'].Value
            $idMatch = [regex]::Match((Convert-HtmlToText $body), $ruleIdRegex)
            if (-not $idMatch.Success) { continue }
            $ruleId = $idMatch.Groups[1].Value
            $title = ''
            $tm = [regex]::Match($body, $titleTagRegex)
            if ($tm.Success) {
                $title = Convert-HtmlToText $tm.Groups[1].Value
            } else {
                $plain = Convert-HtmlToText $body
                $plain = [regex]::Replace($plain, "^\s*$([regex]::Escape($ruleId))\s*", '')
                $plain = [regex]::Replace($plain, "^(?i)($rkPattern)\s+", '')
                $trailResultRegex = '(?i)\s+(Pass|Fail|Error|Unknown|Informational|Not\s*Checked|Not\s*Selected|Not\s*Applicable)\s*$'
                $plain = [regex]::Replace($plain, $trailResultRegex, '')
                if ($plain.Length -gt 240) { $plain = $plain.Substring(0, 240) + '...' }
                $title = $plain
            }
            if (-not $title) { continue }
            $level = ''
            $lm = [regex]::Match($body, '(?i)Level\s*[:\s]*([12])')
            if ($lm.Success) { $level = $lm.Groups[1].Value }
            $key = "$ruleId|$($res.ToLowerInvariant())"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $details  = Get-RuleDetails -Body $body -RawResult $res.ToLowerInvariant() -TitleText $title
            $category = Get-SectionForRule -RuleId $ruleId -Pos $m.Index
            $rows.Add((New-ResultRow -Category $category -RuleId $ruleId -Title $title `
                                     -RawResult $res -Level $level -Details $details)) | Out-Null
        }
    }
}

if ($rows.Count -eq 0) {
    throw "No CIS-CAT rules were extracted from the HTML.  The report may use " +
          "an unrecognised layout - please verify the file is a CIS-CAT Pro " +
          "Assessor HTML report (v4 or Legacy Bundle)."
}

# order by rule id (natural numeric sort of the dotted numbers)
$rows = $rows | Sort-Object -Property @{
    Expression = {
        $id = ($_.'Policy Name' -split '\s+', 2)[0]
        $parts = $id -split '\.'
        # pad parts to fixed width so 1.10 sorts after 1.9
        ($parts | ForEach-Object { $_.PadLeft(4, '0') }) -join '.'
    }
}

Write-Host ("  Extracted {0} rule results." -f $rows.Count) -ForegroundColor Green

# --------------------------------------------------------------------------
#  Totals
# --------------------------------------------------------------------------
$total      = $rows.Count
$configured = ($rows | Where-Object { $_.Status -eq 'Configured'     }).Count
$mismatch   = ($rows | Where-Object { $_.Status -eq 'Mismatch'       }).Count
$notConfig  = ($rows | Where-Object { $_.Status -eq 'Not Configured' }).Count
$unknown    = ($rows | Where-Object { $_.Status -eq 'Unknown'        }).Count
$assessed   = $configured + $mismatch
$computedScore = if ($assessed -gt 0) { [math]::Round(($configured / $assessed) * 100, 1) } else { 0 }

$ncHigh   = ($rows | Where-Object { $_.Status -in @('Mismatch','Not Configured') -and $_.Priority -eq 'High'   }).Count
$ncMedium = ($rows | Where-Object { $_.Status -in @('Mismatch','Not Configured') -and $_.Priority -eq 'Medium' }).Count
$ncLow    = ($rows | Where-Object { $_.Status -in @('Mismatch','Not Configured') -and $_.Priority -eq 'Low'    }).Count

# --------------------------------------------------------------------------
#  XLSX writer (mirrors Invoke-Win11HardeningAudit.ps1)
# --------------------------------------------------------------------------
function ConvertTo-XmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $t = $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' `
               -replace '"', '&quot;' -replace "'", '&apos;'
    return ($t -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
}

function Get-ColumnLetter {
    param([int]$Index)
    $letter = ''
    while ($Index -gt 0) {
        $mod = ($Index - 1) % 26
        $letter = [char](65 + $mod) + $letter
        $Index = [int](($Index - $mod) / 26)
    }
    return $letter
}

function New-Cell {
    param([int]$Col, [int]$Row, $Value, [int]$Style = 0)
    $ref = (Get-ColumnLetter $Col) + $Row
    $txt = ConvertTo-XmlText ([string]$Value)
    "<c r=`"$ref`" s=`"$Style`" t=`"inlineStr`"><is><t xml:space=`"preserve`">$txt</t></is></c>"
}

function Build-SheetXml {
    param(
        [object[]]$Rows,
        [object[]]$Cols,
        [bool]$Freeze = $false,
        [string]$AutoFilterRef = $null
    )
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    [void]$sb.Append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
    if ($Freeze) {
        [void]$sb.Append('<sheetViews><sheetView workbookViewId="0">')
        [void]$sb.Append('<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>')
        [void]$sb.Append('<selection pane="bottomLeft"/></sheetView></sheetViews>')
    }
    [void]$sb.Append('<sheetFormatPr defaultRowHeight="15"/>')
    if ($Cols) {
        [void]$sb.Append('<cols>')
        foreach ($c in $Cols) {
            [void]$sb.Append(('<col min="{0}" max="{1}" width="{2}" customWidth="1"/>' -f $c.Min, $c.Max, $c.Width))
        }
        [void]$sb.Append('</cols>')
    }
    [void]$sb.Append('<sheetData>')
    $r = 0
    foreach ($row in $Rows) {
        $r++
        [void]$sb.Append("<row r=`"$r`">")
        $cIdx = 0
        foreach ($cell in $row) {
            $cIdx++
            $style = 0; if ($null -ne $cell.S) { $style = [int]$cell.S }
            [void]$sb.Append((New-Cell -Col $cIdx -Row $r -Value $cell.V -Style $style))
        }
        [void]$sb.Append('</row>')
    }
    [void]$sb.Append('</sheetData>')
    if ($AutoFilterRef) { [void]$sb.Append("<autoFilter ref=`"$AutoFilterRef`"/>") }
    [void]$sb.Append('</worksheet>')
    return $sb.ToString()
}

function Save-Xlsx {
    param([string]$Path, [hashtable]$Styles, [object[]]$SheetXmls, [string[]]$SheetNames)
    $contentTypes = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
__SHEET_OVERRIDES__
</Types>
'@
    $overrides = ''
    for ($i = 1; $i -le $SheetXmls.Count; $i++) {
        $overrides += "<Override PartName=`"/xl/worksheets/sheet$i.xml`" ContentType=`"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml`"/>`n"
    }
    $contentTypes = $contentTypes -replace '__SHEET_OVERRIDES__', $overrides.TrimEnd()

    $rootRels = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
'@

    $sheetTags = ''
    $relTags   = ''
    for ($i = 1; $i -le $SheetXmls.Count; $i++) {
        $nm = ConvertTo-XmlText $SheetNames[$i-1]
        $sheetTags += "<sheet name=`"$nm`" sheetId=`"$i`" r:id=`"rId$i`"/>"
        $relTags   += "<Relationship Id=`"rId$i`" Type=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet`" Target=`"worksheets/sheet$i.xml`"/>"
    }
    $styleRelId = $SheetXmls.Count + 1
    $relTags += "<Relationship Id=`"rId$styleRelId`" Type=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles`" Target=`"styles.xml`"/>"

    $workbook = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' +
        "<sheets>$sheetTags</sheets></workbook>"

    $workbookRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        "$relTags</Relationships>"

    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }

    $enc = [System.Text.UTF8Encoding]::new($false)
    Add-Type -AssemblyName System.IO.Compression         -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        function Add-Entry($zip, $name, $content, $enc) {
            $entry = $zip.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
            $stream = $entry.Open()
            $writer = New-Object System.IO.StreamWriter($stream, $enc)
            $writer.Write($content)
            $writer.Flush(); $writer.Dispose(); $stream.Dispose()
        }
        Add-Entry $zip '[Content_Types].xml'      $contentTypes $enc
        Add-Entry $zip '_rels/.rels'              $rootRels     $enc
        Add-Entry $zip 'xl/workbook.xml'          $workbook     $enc
        Add-Entry $zip 'xl/_rels/workbook.xml.rels' $workbookRels $enc
        Add-Entry $zip 'xl/styles.xml'            $Styles.Xml   $enc
        for ($i = 1; $i -le $SheetXmls.Count; $i++) {
            Add-Entry $zip "xl/worksheets/sheet$i.xml" $SheetXmls[$i-1] $enc
        }
    } finally {
        $zip.Dispose()
    }
}

# Styles: 0 default | 1 header | 2 green | 3 red | 4 yellow | 5 data | 6 bold | 7 sumHeader | 8 grey
$stylesXml = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="3">
<font><sz val="11"/><color rgb="FF000000"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FF000000"/><name val="Calibri"/></font>
</fonts>
<fills count="7">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF4472C4"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFC6EFCE"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFFC7CE"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFFEB9C"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFE0E0E0"/></patternFill></fill>
</fills>
<borders count="2">
<border><left/><right/><top/><bottom/><diagonal/></border>
<border><left style="thin"><color rgb="FFBFBFBF"/></left><right style="thin"><color rgb="FFBFBFBF"/></right><top style="thin"><color rgb="FFBFBFBF"/></top><bottom style="thin"><color rgb="FFBFBFBF"/></bottom><diagonal/></border>
</borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="9">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="4" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="5" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
<xf numFmtId="0" fontId="0" fillId="6" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>
'@

function Get-StatusStyle {
    param([string]$Status)
    switch ($Status) {
        'Configured'     { 2 }
        'Mismatch'       { 3 }
        'Not Configured' { 4 }
        'Unknown'        { 8 }
        default          { 5 }
    }
}

# --------------------------------------------------------------------------
#  Audit Results sheet
# --------------------------------------------------------------------------
$headers = 'Category','Policy Name','Scope','Policy Path','Registry Path','Setting name','Current Value','Recommended Value','Status','Priority','Notes'
$dataRows = New-Object System.Collections.ArrayList
[void]$dataRows.Add(@($headers | ForEach-Object { @{ V = $_; S = 1 } }))

foreach ($row in $rows) {
    $statusStyle = Get-StatusStyle $row.Status
    [void]$dataRows.Add(@(
        @{ V = $row.Category;             S = 5 },
        @{ V = $row.'Policy Name';        S = 5 },
        @{ V = $row.Scope;                S = 5 },
        @{ V = $row.'Policy Path';        S = 5 },
        @{ V = $row.'Registry Path';      S = 5 },
        @{ V = $row.'Setting name';       S = 5 },
        @{ V = $row.'Current Value';      S = 5 },
        @{ V = $row.'Recommended Value';  S = 5 },
        @{ V = $row.Status;               S = $statusStyle },
        @{ V = $row.Priority;             S = 5 },
        @{ V = $row.Notes;                S = 5 }
    ))
}

$cols = @(
    @{ Min=1;  Max=1;  Width=24 },
    @{ Min=2;  Max=2;  Width=70 },
    @{ Min=3;  Max=3;  Width=10 },
    @{ Min=4;  Max=4;  Width=55 },
    @{ Min=5;  Max=5;  Width=52 },
    @{ Min=6;  Max=6;  Width=30 },
    @{ Min=7;  Max=7;  Width=18 },
    @{ Min=8;  Max=8;  Width=18 },
    @{ Min=9;  Max=9;  Width=16 },
    @{ Min=10; Max=10; Width=10 },
    @{ Min=11; Max=11; Width=45 }
)
$lastRow = $dataRows.Count
$auditSheet = Build-SheetXml -Rows $dataRows.ToArray() -Cols $cols -Freeze $true -AutoFilterRef ("A1:K{0}" -f $lastRow)

# --------------------------------------------------------------------------
#  Summary sheet
# --------------------------------------------------------------------------
$scoreDisplay = if ($score) { $score } else { "{0}% (of {1} assessed)" -f $computedScore, $assessed }

$sumRows = New-Object System.Collections.ArrayList
[void]$sumRows.Add(@( @{ V='CIS-CAT Benchmark - Converted Report'; S=6 } ))
[void]$sumRows.Add(@( @{ V='Generated';        S=6 }, @{ V=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); S=0 } ))
[void]$sumRows.Add(@( @{ V='Source HTML';      S=6 }, @{ V=$InputPath; S=0 } ))
[void]$sumRows.Add(@( @{ V='Benchmark';        S=6 }, @{ V=$benchmarkTitle; S=0 } ))
if ($benchmarkVersion) {
    [void]$sumRows.Add(@( @{ V='Benchmark version'; S=6 }, @{ V=$benchmarkVersion; S=0 } ))
}
if ($targetHost) {
    [void]$sumRows.Add(@( @{ V='Target';          S=6 }, @{ V=$targetHost; S=0 } ))
}
if ($targetIp) {
    [void]$sumRows.Add(@( @{ V='Target IP';       S=6 }, @{ V=$targetIp; S=0 } ))
}
if ($targetOs) {
    [void]$sumRows.Add(@( @{ V='OS';              S=6 }, @{ V=$targetOs; S=0 } ))
}
if ($assessmentTime) {
    [void]$sumRows.Add(@( @{ V='Assessment time'; S=6 }, @{ V=$assessmentTime; S=0 } ))
}
[void]$sumRows.Add(@( @{ V=''; S=0 } ))
[void]$sumRows.Add(@( @{ V='Metric'; S=7 }, @{ V='Count'; S=7 } ))
[void]$sumRows.Add(@( @{ V='Total rules';           S=6 }, @{ V=$total;      S=5 } ))
[void]$sumRows.Add(@( @{ V='Configured (Pass)';     S=6 }, @{ V=$configured; S=2 } ))
[void]$sumRows.Add(@( @{ V='Mismatch (Fail)';       S=6 }, @{ V=$mismatch;   S=3 } ))
[void]$sumRows.Add(@( @{ V='Not Configured (N/A / Info)'; S=6 }, @{ V=$notConfig;  S=4 } ))
[void]$sumRows.Add(@( @{ V='Unknown (Error)';       S=6 }, @{ V=$unknown;    S=8 } ))
[void]$sumRows.Add(@( @{ V='Compliance score';     S=6 }, @{ V=$scoreDisplay; S=5 } ))
[void]$sumRows.Add(@( @{ V=''; S=0 } ))
[void]$sumRows.Add(@( @{ V='Non-compliant by priority'; S=7 }, @{ V='Count'; S=7 } ))
[void]$sumRows.Add(@( @{ V='High';   S=6 }, @{ V=$ncHigh;   S=5 } ))
[void]$sumRows.Add(@( @{ V='Medium'; S=6 }, @{ V=$ncMedium; S=5 } ))
[void]$sumRows.Add(@( @{ V='Low';    S=6 }, @{ V=$ncLow;    S=5 } ))

$sumCols = @( @{ Min=1; Max=1; Width=28 }, @{ Min=2; Max=2; Width=60 } )
$summarySheet = Build-SheetXml -Rows $sumRows.ToArray() -Cols $sumCols

# --------------------------------------------------------------------------
#  Write the workbook
# --------------------------------------------------------------------------
Save-Xlsx -Path $OutputPath -Styles @{ Xml = $stylesXml } `
    -SheetXmls @($summarySheet, $auditSheet) -SheetNames @('Summary','Audit Results')

Write-Host ""
Write-Host ("Excel report written to: {0}" -f $OutputPath) -ForegroundColor Green

if ($OpenWhenDone) { Invoke-Item -LiteralPath $OutputPath }
