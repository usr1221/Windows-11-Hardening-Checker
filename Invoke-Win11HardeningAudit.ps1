<#
.SYNOPSIS
    Audits a Windows 11 workstation against the ASD/ACSC "Hardening Microsoft
    Windows 11 workstations" guidance and produces an Excel (.xlsx) report.

.DESCRIPTION
    Reads the local registry (read-only - it never changes anything) for each
    policy defined in Policies.json, compares the current value to the
    ASD-recommended value, and writes a colour-coded Excel workbook with the
    columns: Policy Name, Scope, Policy Path, Registry Path, Setting name,
    Current Value, Recommended Value, Status and Priority (plus Category and
    Notes for context).

    Status values:
        Configured     - the setting exists and matches the recommendation
        Mismatch       - the setting exists but does not match
        Not Configured - the setting is absent (left at the Windows default)

    The .xlsx is generated directly via the Open XML (SpreadsheetML) format, so
    NO third-party module (ImportExcel) and NO installed copy of Excel are
    required.

.PARAMETER PoliciesPath
    Path to the policy definition JSON. Defaults to Policies.json next to this
    script.

.PARAMETER OutputPath
    Path of the .xlsx to create. Defaults to a timestamped file next to this
    script.

.PARAMETER IncludeCsv
    Also write a .csv alongside the .xlsx.

.PARAMETER OpenWhenDone
    Open the report when finished.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-Win11HardeningAudit.ps1

.NOTES
    Run in an elevated (Administrator) PowerShell for complete results - some
    HKLM policy keys are not readable by standard users. User-scope (HKCU)
    checks reflect the account running the script.
#>
[CmdletBinding()]
param(
    [string]$PoliciesPath,
    [string]$OutputPath,
    [switch]$IncludeCsv,
    [switch]$OpenWhenDone
)

# --------------------------------------------------------------------------
#  Setup
# --------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

if (-not $PoliciesPath) { $PoliciesPath = Join-Path $scriptDir 'Policies.json' }
if (-not (Test-Path $PoliciesPath)) {
    throw "Policy definition file not found: $PoliciesPath"
}

if (-not $OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path $scriptDir ("Win11_Hardening_Audit_{0}_{1}.xlsx" -f $env:COMPUTERNAME, $stamp)
}

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "Windows 11 Hardening Audit (ASD/ACSC)" -ForegroundColor Cyan
Write-Host ("  Host        : {0}" -f $env:COMPUTERNAME)
Write-Host ("  User        : {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
Write-Host ("  Elevated    : {0}" -f $isAdmin)
Write-Host ("  Policy file : {0}" -f $PoliciesPath)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator - some Computer-scope checks may read as 'Not Configured'."
}

$policies = Get-Content -Path $PoliciesPath -Raw | ConvertFrom-Json
Write-Host ("  Loaded {0} policy checks." -f $policies.Count) -ForegroundColor Green

# --------------------------------------------------------------------------
#  Helpers
# --------------------------------------------------------------------------
function Get-RegistryValue {
    # Returns @{ Exists = $bool; Value = <raw> }
    # Uses the .NET registry API so value names are matched LITERALLY (some ASD
    # value names, e.g. Hardened UNC Paths "\\*\NETLOGON", contain characters
    # that Get-ItemProperty -Name would treat as wildcards).
    param([string]$Path, [string]$Name)

    $hive = $null; $sub = $null
    if     ($Path -match '^(?:HKLM|HKEY_LOCAL_MACHINE)\\(.+)$') { $hive = [Microsoft.Win32.Registry]::LocalMachine; $sub = $Matches[1] }
    elseif ($Path -match '^(?:HKCU|HKEY_CURRENT_USER)\\(.+)$')  { $hive = [Microsoft.Win32.Registry]::CurrentUser;  $sub = $Matches[1] }
    elseif ($Path -match '^(?:HKU|HKEY_USERS)\\(.+)$')          { $hive = [Microsoft.Win32.Registry]::Users;        $sub = $Matches[1] }
    else { return @{ Exists = $false; Value = $null } }

    $key = $null
    try {
        $key = $hive.OpenSubKey($sub)
        if (-not $key) { return @{ Exists = $false; Value = $null } }
        $exists = $false
        foreach ($n in $key.GetValueNames()) { if ($n -ieq $Name) { $exists = $true; break } }
        if (-not $exists) { return @{ Exists = $false; Value = $null } }
        return @{ Exists = $true; Value = $key.GetValue($Name) }
    } catch {
        return @{ Exists = $false; Value = $null }
    } finally {
        if ($key) { $key.Close() }
    }
}

function ConvertTo-DisplayString {
    param($Value)
    if ($null -eq $Value) { return '<not set>' }
    if ($Value -is [System.Array]) { return ($Value -join '; ') }
    return [string]$Value
}

function Test-Numeric {
    param($Value, [ref]$Result)
    $d = 0.0
    if ([double]::TryParse([string]$Value, [ref]$d)) { $Result.Value = $d; return $true }
    return $false
}

function Get-ComplianceStatus {
    param($Current, [bool]$Exists, [string]$Recommended, [string]$Operator)

    if (-not $Exists) { return 'Not Configured' }
    if (-not $Operator) { $Operator = 'eq' }

    $curStr = (ConvertTo-DisplayString $Current).Trim()
    $cn = 0.0; $rn = 0.0
    $curIsNum = Test-Numeric $curStr ([ref]$cn)
    $recIsNum = Test-Numeric $Recommended ([ref]$rn)

    switch ($Operator) {
        'eq' {
            if ($curIsNum -and $recIsNum) { if ($cn -eq $rn) { return 'Configured' } else { return 'Mismatch' } }
            if ($curStr -ieq $Recommended.Trim()) { return 'Configured' } else { return 'Mismatch' }
        }
        'ne' {
            if ($curIsNum -and $recIsNum) { if ($cn -ne $rn) { return 'Configured' } else { return 'Mismatch' } }
            if ($curStr -ine $Recommended.Trim()) { return 'Configured' } else { return 'Mismatch' }
        }
        'ge' {
            if ($curIsNum -and $recIsNum) { if ($cn -ge $rn) { return 'Configured' } else { return 'Mismatch' } }
            return 'Mismatch'
        }
        'le' {
            if ($curIsNum -and $recIsNum) { if ($cn -le $rn) { return 'Configured' } else { return 'Mismatch' } }
            return 'Mismatch'
        }
        'oneof' {
            $options = $Recommended -split ',' | ForEach-Object { $_.Trim() }
            foreach ($opt in $options) {
                $on = 0.0
                if ((Test-Numeric $opt ([ref]$on)) -and $curIsNum) {
                    if ($cn -eq $on) { return 'Configured' }
                } elseif ($curStr -ieq $opt) { return 'Configured' }
            }
            return 'Mismatch'
        }
        'contains' {
            # every comma-separated token must appear in the current value
            $tokens = $Recommended -split ',' | ForEach-Object { $_.Trim() }
            foreach ($tok in $tokens) {
                if ($curStr -notlike "*$tok*") { return 'Mismatch' }
            }
            return 'Configured'
        }
        default {
            if ($curStr -ieq $Recommended.Trim()) { return 'Configured' } else { return 'Mismatch' }
        }
    }
}

# --------------------------------------------------------------------------
#  Run the audit
# --------------------------------------------------------------------------
$results = foreach ($p in $policies) {
    $reg = Get-RegistryValue -Path $p.RegistryPath -Name $p.SettingName
    $status = Get-ComplianceStatus -Current $reg.Value -Exists $reg.Exists `
                  -Recommended ([string]$p.RecommendedValue) -Operator $p.Operator

    [pscustomobject][ordered]@{
        Category          = $p.Category
        'Policy Name'     = $p.PolicyName
        Scope             = $p.Scope
        'Policy Path'     = $p.PolicyPath
        'Registry Path'   = $p.RegistryPath
        'Setting name'    = $p.SettingName
        'Current Value'   = (ConvertTo-DisplayString $reg.Value)
        'Recommended Value' = [string]$p.RecommendedValue
        Status            = $status
        Priority          = $p.Priority
        Notes             = $p.Notes
    }
}

# --------------------------------------------------------------------------
#  Console summary
# --------------------------------------------------------------------------
$total       = $results.Count
$configured  = @($results | Where-Object Status -eq 'Configured').Count
$mismatch    = @($results | Where-Object Status -eq 'Mismatch').Count
$notConfig   = @($results | Where-Object Status -eq 'Not Configured').Count
$score       = if ($total) { [math]::Round(($configured / $total) * 100, 1) } else { 0 }

$nonCompliant = @($results | Where-Object Status -ne 'Configured')
$ncHigh   = @($nonCompliant | Where-Object Priority -eq 'High').Count
$ncMedium = @($nonCompliant | Where-Object Priority -eq 'Medium').Count
$ncLow    = @($nonCompliant | Where-Object Priority -eq 'Low').Count

Write-Host ""
Write-Host "Results" -ForegroundColor Cyan
Write-Host ("  Total checks   : {0}" -f $total)
Write-Host ("  Configured     : {0}" -f $configured) -ForegroundColor Green
Write-Host ("  Mismatch       : {0}" -f $mismatch)   -ForegroundColor Red
Write-Host ("  Not Configured : {0}" -f $notConfig)  -ForegroundColor Yellow
Write-Host ("  Compliance     : {0}%" -f $score)
Write-Host ("  Non-compliant by priority -> High:{0}  Medium:{1}  Low:{2}" -f $ncHigh, $ncMedium, $ncLow)

# --------------------------------------------------------------------------
#  Minimal Open XML (.xlsx) writer  - no external dependencies
# --------------------------------------------------------------------------
Add-Type -AssemblyName System.IO.Compression          | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null

function ConvertTo-XmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $t = $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' `
               -replace '"', '&quot;' -replace "'", '&apos;'
    # strip XML-illegal control characters
    return ($t -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
}

function Get-ColumnLetter {
    param([int]$Index)   # 1-based
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
        [object[]]$Rows,        # array of rows; each row is array of @{V=..;S=..}
        [object[]]$Cols,        # array of @{Min;Max;Width}
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

# Styles: 0 default | 1 header | 2 green | 3 red | 4 yellow | 5 data | 6 bold | 7 sumHeader
$stylesXml = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="3">
<font><sz val="11"/><color rgb="FF000000"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FF000000"/><name val="Calibri"/></font>
</fonts>
<fills count="6">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF4472C4"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFC6EFCE"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFFC7CE"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFFEB9C"/></patternFill></fill>
</fills>
<borders count="2">
<border><left/><right/><top/><bottom/><diagonal/></border>
<border><left style="thin"><color rgb="FFBFBFBF"/></left><right style="thin"><color rgb="FFBFBFBF"/></right><top style="thin"><color rgb="FFBFBFBF"/></top><bottom style="thin"><color rgb="FFBFBFBF"/></bottom><diagonal/></border>
</borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="8">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="4" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="5" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
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
        default          { 5 }
    }
}

# ---- Build the "Audit Results" sheet ----
$headers = 'Category','Policy Name','Scope','Policy Path','Registry Path','Setting name','Current Value','Recommended Value','Status','Priority','Notes'
$dataRows = New-Object System.Collections.ArrayList
[void]$dataRows.Add(@($headers | ForEach-Object { @{ V = $_; S = 1 } }))

foreach ($row in $results) {
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
    @{ Min=2;  Max=2;  Width=48 },
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

# ---- Build the "Summary" sheet ----
$sumRows = New-Object System.Collections.ArrayList
[void]$sumRows.Add(@( @{ V='Windows 11 Hardening Audit (ASD/ACSC) - Summary'; S=6 } ))
[void]$sumRows.Add(@( @{ V='Generated';       S=6 }, @{ V=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); S=0 } ))
[void]$sumRows.Add(@( @{ V='Hostname';        S=6 }, @{ V=$env:COMPUTERNAME; S=0 } ))
[void]$sumRows.Add(@( @{ V='User';            S=6 }, @{ V=("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME); S=0 } ))
[void]$sumRows.Add(@( @{ V='OS';              S=6 }, @{ V=((Get-CimInstance Win32_OperatingSystem).Caption + ' (build ' + [System.Environment]::OSVersion.Version.Build + ')'); S=0 } ))
[void]$sumRows.Add(@( @{ V='Run elevated';    S=6 }, @{ V=$isAdmin; S=0 } ))
[void]$sumRows.Add(@( @{ V=''; S=0 } ))
[void]$sumRows.Add(@( @{ V='Metric'; S=7 }, @{ V='Count'; S=7 } ))
[void]$sumRows.Add(@( @{ V='Total checks';    S=6 }, @{ V=$total;      S=5 } ))
[void]$sumRows.Add(@( @{ V='Configured';      S=6 }, @{ V=$configured; S=2 } ))
[void]$sumRows.Add(@( @{ V='Mismatch';        S=6 }, @{ V=$mismatch;   S=3 } ))
[void]$sumRows.Add(@( @{ V='Not Configured';  S=6 }, @{ V=$notConfig;  S=4 } ))
[void]$sumRows.Add(@( @{ V='Compliance score';S=6 }, @{ V=("{0}%" -f $score); S=5 } ))
[void]$sumRows.Add(@( @{ V=''; S=0 } ))
[void]$sumRows.Add(@( @{ V='Non-compliant by priority'; S=7 }, @{ V='Count'; S=7 } ))
[void]$sumRows.Add(@( @{ V='High';   S=6 }, @{ V=$ncHigh;   S=5 } ))
[void]$sumRows.Add(@( @{ V='Medium'; S=6 }, @{ V=$ncMedium; S=5 } ))
[void]$sumRows.Add(@( @{ V='Low';    S=6 }, @{ V=$ncLow;    S=5 } ))
$sumCols = @( @{ Min=1; Max=1; Width=28 }, @{ Min=2; Max=2; Width=40 } )
$summarySheet = Build-SheetXml -Rows $sumRows.ToArray() -Cols $sumCols

# ---- Write the workbook ----
Save-Xlsx -Path $OutputPath -Styles @{ Xml = $stylesXml } `
    -SheetXmls @($summarySheet, $auditSheet) -SheetNames @('Summary', 'Audit Results')

Write-Host ""
Write-Host ("Excel report written to: {0}" -f $OutputPath) -ForegroundColor Green

if ($IncludeCsv) {
    $csvPath = [System.IO.Path]::ChangeExtension($OutputPath, 'csv')
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host ("CSV report written to:   {0}" -f $csvPath) -ForegroundColor Green
}

if ($OpenWhenDone) { Invoke-Item -LiteralPath $OutputPath }
