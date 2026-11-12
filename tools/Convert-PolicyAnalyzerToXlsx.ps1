<#
.SYNOPSIS
    Converts a Microsoft Policy Analyzer XLSX report into an Excel workbook
    that matches the format produced by Invoke-Win11HardeningAudit.ps1
    and Convert-CisCatHtmlToXlsx.ps1.

.DESCRIPTION
    Policy Analyzer's exported .xlsx has 15 columns
    (Policy Config | Policy Path | Policy Setting Name | Policy Type |
     Policy Group or Registry Key | Policy Setting |
     Baseline(s) | Baseline(s) Option | Baseline(s) Type |
     Effective state | Effective state Option | Effective state Type |
     Explain Text | Baseline(s) GPO | Effective state GPO).

    This script rewrites those rows into the two-sheet audit format:

        Sheet 1 - Summary       benchmark/target info + totals
        Sheet 2 - Audit Results Category | Policy Name | Scope |
                                Policy Path | Registry Path |
                                Setting name | Current Value |
                                Recommended Value | Status |
                                Priority | Notes

    Status is inferred by comparing Effective state to Baseline(s):
        Effective present and equal to Baseline   -> Configured   (green)
        Effective present but different           -> Mismatch     (red)
        Effective empty (setting not applied)     -> Not Configured (yellow)
        Baseline empty (should not happen)        -> Unknown      (grey)

    Like the sibling scripts, the .xlsx is produced with the built-in
    Open XML writer - no ImportExcel module and no Excel required.

.PARAMETER InputPath
    Path to the Policy Analyzer .xlsx (required).

.PARAMETER OutputPath
    Path of the .xlsx to create.  Defaults to
    <input basename>_Audit.xlsx alongside the input.

.PARAMETER OpenWhenDone
    Open the report when finished (Windows only).

.EXAMPLE
    .\Convert-PolicyAnalyzerToXlsx.ps1 -InputPath .\Zeszyt1.xlsx
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
    throw "Policy Analyzer workbook not found: $InputPath"
}
$InputPath = (Resolve-Path -LiteralPath $InputPath).ProviderPath

if (-not $OutputPath) {
    $dir  = [System.IO.Path]::GetDirectoryName($InputPath)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($InputPath)
    $OutputPath = [System.IO.Path]::Combine($dir, "${base}_Audit.xlsx")
}

Write-Host "Policy Analyzer XLSX -> Audit XLSX converter" -ForegroundColor Cyan
Write-Host ("  Input  : {0}" -f $InputPath)
Write-Host ("  Output : {0}" -f $OutputPath)

Add-Type -AssemblyName System.IO.Compression         -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

# --------------------------------------------------------------------------
#  XLSX reader (shared-strings based)
# --------------------------------------------------------------------------
function Get-ZipEntryText {
    param([System.IO.Compression.ZipArchive]$Zip, [string]$Name)
    $entry = $Zip.GetEntry($Name)
    if (-not $entry) { return $null }
    $stream = $entry.Open()
    try {
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function Convert-XmlText {
    # Decode XML entities and Excel's _xHHHH_ escape sequences.
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $Text
    $t = $t -replace '&lt;',  '<'
    $t = $t -replace '&gt;',  '>'
    $t = $t -replace '&quot;','"'
    $t = $t -replace '&apos;',"'"
    $t = $t -replace '&amp;', '&'
    # _xHHHH_ -> Unicode codepoint HHHH (Excel's escape for control chars)
    $t = [regex]::Replace($t, '_x([0-9A-Fa-f]{4})_', {
        param($m) [char][Convert]::ToInt32($m.Groups[1].Value, 16)
    })
    return $t
}

function Clean-CellText {
    # Turn embedded CR/LF into simple spaces so cells stay readable when
    # narrow but keep the original text otherwise.  Policy Analyzer packs
    # multiple ADMX policies that share a single registry value into one
    # cell separated by CR+LF; drop exact-duplicate halves so we don't end
    # up with "Computer Configuration Computer Configuration".
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $parts = [regex]::Split($Text, "\r\n|\r|\n")
    $seen  = New-Object System.Collections.Generic.HashSet[string]
    $keep  = New-Object System.Collections.Generic.List[string]
    foreach ($p in $parts) {
        $trim = ($p -replace '\s{2,}', ' ').Trim()
        if (-not $trim) { continue }
        if ($seen.Add($trim)) { [void]$keep.Add($trim) }
    }
    return (($keep -join ' ') -replace '\s{2,}', ' ').Trim()
}

function Get-SharedStrings {
    param([System.IO.Compression.ZipArchive]$Zip)
    $xml = Get-ZipEntryText -Zip $Zip -Name 'xl/sharedStrings.xml'
    $strings = New-Object System.Collections.Generic.List[string]
    if (-not $xml) { return $strings }
    # Each <si> may contain a single <t> or several <r><t>...</t></r> runs.
    foreach ($si in [regex]::Matches($xml, '(?is)<si\b[^>]*>(?<b>.*?)</si>')) {
        $body = $si.Groups['b'].Value
        $parts = @()
        foreach ($tm in [regex]::Matches($body, '(?is)<t\b[^>]*>(?<t>.*?)</t>')) {
            $parts += $tm.Groups['t'].Value
        }
        $joined = ($parts -join '')
        $strings.Add((Convert-XmlText $joined))
    }
    return $strings
}

function ConvertFrom-CellRef {
    # "AB12" -> @{ Col=28; Row=12 }
    param([string]$Ref)
    $m = [regex]::Match($Ref, '^([A-Z]+)(\d+)$')
    if (-not $m.Success) { return $null }
    $letters = $m.Groups[1].Value
    $col = 0
    foreach ($ch in $letters.ToCharArray()) {
        $col = $col * 26 + ([int][char]$ch - 64)
    }
    return @{ Col = $col; Row = [int]$m.Groups[2].Value }
}

function Get-CellValue {
    param([string]$CellXml, [System.Collections.Generic.List[string]]$Shared)
    $type = ''
    $tm = [regex]::Match($CellXml, '(?is)^<c\b[^>]*\bt="([^"]+)"')
    if ($tm.Success) { $type = $tm.Groups[1].Value }
    switch ($type) {
        's' {
            $vm = [regex]::Match($CellXml, '(?is)<v>(.*?)</v>')
            if ($vm.Success) {
                $idx = [int]$vm.Groups[1].Value
                if ($idx -ge 0 -and $idx -lt $Shared.Count) { return $Shared[$idx] }
            }
            return ''
        }
        'inlineStr' {
            $parts = @()
            foreach ($tt in [regex]::Matches($CellXml, '(?is)<t\b[^>]*>(?<t>.*?)</t>')) {
                $parts += $tt.Groups['t'].Value
            }
            return (Convert-XmlText ($parts -join ''))
        }
        'str' {
            $vm = [regex]::Match($CellXml, '(?is)<v>(.*?)</v>')
            if ($vm.Success) { return (Convert-XmlText $vm.Groups[1].Value) }
            return ''
        }
        'b' {
            $vm = [regex]::Match($CellXml, '(?is)<v>(.*?)</v>')
            if ($vm.Success) {
                return $(if ($vm.Groups[1].Value -eq '1') { 'TRUE' } else { 'FALSE' })
            }
            return ''
        }
        default {
            # Numeric or date; return raw value.
            $vm = [regex]::Match($CellXml, '(?is)<v>(.*?)</v>')
            if ($vm.Success) { return (Convert-XmlText $vm.Groups[1].Value) }
            return ''
        }
    }
}

function Read-XlsxRows {
    # Returns an array of string arrays, one per data row.  First row is
    # assumed to be the header.
    param([string]$Path)
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $shared = Get-SharedStrings -Zip $zip
        # Use the first worksheet; Policy Analyzer only produces one.
        $sheetXml = Get-ZipEntryText -Zip $zip -Name 'xl/worksheets/sheet1.xml'
        if (-not $sheetXml) {
            throw "Workbook has no xl/worksheets/sheet1.xml (unexpected format)."
        }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($rm in [regex]::Matches($sheetXml, '(?is)<row\b[^>]*>(?<b>.*?)</row>')) {
            $rowBody = $rm.Groups['b'].Value
            $cells = @{}
            $maxCol = 0
            foreach ($cm in [regex]::Matches($rowBody, '(?is)<c\b(?<attrs>[^>]*)>(?<body>.*?)</c>|<c\b[^>]*/>')) {
                $cellXml = $cm.Value
                # cell may be self-closed <c r="A1"/> with no value
                $refMatch = [regex]::Match($cellXml, '\br="([A-Z]+\d+)"')
                if (-not $refMatch.Success) { continue }
                $rc = ConvertFrom-CellRef $refMatch.Groups[1].Value
                if (-not $rc) { continue }
                if ($cellXml -match '/\s*>$') {
                    $val = ''
                } else {
                    $val = Get-CellValue -CellXml $cellXml -Shared $shared
                }
                $cells[$rc.Col] = $val
                if ($rc.Col -gt $maxCol) { $maxCol = $rc.Col }
            }
            if ($maxCol -eq 0) { continue }
            $arr = @()
            for ($i = 1; $i -le $maxCol; $i++) {
                if ($cells.ContainsKey($i)) { $arr += $cells[$i] } else { $arr += '' }
            }
            [void]$rows.Add([object[]]$arr)
        }
        return $rows
    } finally {
        $zip.Dispose()
    }
}

# --------------------------------------------------------------------------
#  Row mapping
# --------------------------------------------------------------------------
function Get-Field {
    param([object[]]$Row, [int]$Index)
    if ($Index -lt 0 -or $Index -ge $Row.Count) { return '' }
    if ($null -eq $Row[$Index]) { return '' }
    return [string]$Row[$Index]
}

function Get-Scope {
    # Prefer whatever Policy Config already says (Polish or English);
    # fall back to the Policy Type column.
    param([string]$PolicyConfig, [string]$PolicyType)
    if ($PolicyConfig) {
        if ($PolicyConfig -match '(?i)komputer|Computer\s+Configuration') { return 'Computer' }
        if ($PolicyConfig -match '(?i)użytkownik|User\s+Configuration')  { return 'User' }
    }
    switch -Regex ($PolicyType) {
        'HKLM'              { return 'Computer' }
        'HKCU'              { return 'User' }
        'Audit\s*Policy'    { return 'Computer' }
        'Security\s*Template' { return 'Computer' }
    }
    return ''
}

function Normalize-Value {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return ($Text -replace '\s+', '').ToLowerInvariant()
}

function Test-BaselineRequiresAbsence {
    # Policy Analyzer marks "value must not exist" baselines with
    # [[[delete]]] in the Option column or [[[Delete all values]]] in the
    # Policy Setting column.
    param([string]$Baseline, [string]$BaseOption, [string]$SettingName)
    foreach ($v in @($Baseline, $BaseOption, $SettingName)) {
        if ($v -match '^\s*\[\[\[\s*delete(\s+all\s+values)?\s*\]\]\]\s*$') { return $true }
    }
    return $false
}

function Get-Status {
    param(
        [string]$Baseline,
        [string]$BaseOption,
        [string]$Effective,
        [string]$EffectiveGpo,
        [string]$SettingName
    )
    $mustBeAbsent = Test-BaselineRequiresAbsence -Baseline $Baseline `
        -BaseOption $BaseOption -SettingName $SettingName

    if ($mustBeAbsent) {
        # Baseline demands the value be absent.  Empty effective = compliant.
        if (-not $Effective -and -not $EffectiveGpo) { return 'Configured' }
        return 'Mismatch'
    }

    if (-not $Baseline -and -not $BaseOption) { return 'Unknown' }
    if (-not $Effective -and -not $EffectiveGpo) { return 'Not Configured' }
    if ((Normalize-Value $Baseline) -eq (Normalize-Value $Effective)) {
        return 'Configured'
    }
    return 'Mismatch'
}

# --------------------------------------------------------------------------
#  Read input, build mapped rows
# --------------------------------------------------------------------------
$srcRows = Read-XlsxRows -Path $InputPath
if (-not $srcRows -or $srcRows.Count -lt 2) {
    throw "No data rows found in Policy Analyzer workbook."
}

$header  = $srcRows[0]
$dataRaw = $srcRows | Select-Object -Skip 1

# Detect any baseline names present so we can put them in the Summary.
$baselineNames = New-Object System.Collections.Generic.HashSet[string]

$mapped = New-Object System.Collections.Generic.List[object]

foreach ($r in $dataRaw) {
    $polConfig   = Get-Field $r 0
    $polPath     = Get-Field $r 1
    $polSetName  = Get-Field $r 2
    $polType     = Get-Field $r 3
    $regKey      = Get-Field $r 4
    $valueName   = Get-Field $r 5
    $baseline    = Get-Field $r 6
    $baseOption  = Get-Field $r 7
    $baseType    = Get-Field $r 8
    $effective   = Get-Field $r 9
    $effOption   = Get-Field $r 10
    $effType     = Get-Field $r 11
    $explain     = Get-Field $r 12
    $baseGpo     = Get-Field $r 13
    $effGpo      = Get-Field $r 14

    # Skip rows that are essentially empty (no baseline setting at all)
    if (-not ($valueName -or $baseline -or $baseOption -or $polSetName)) { continue }

    if ($baseGpo) { [void]$baselineNames.Add($baseGpo) }

    $scope = Get-Scope -PolicyConfig $polConfig -PolicyType $polType

    # Registry Path: only meaningful for HKLM/HKCU rows
    $registryPath = ''
    if ($polType -match '^HK') {
        $hive = if ($polType -eq 'HKLM') { 'HKEY_LOCAL_MACHINE' }
                elseif ($polType -eq 'HKCU') { 'HKEY_CURRENT_USER' }
                else { $polType }
        if ($regKey) { $registryPath = "$hive\$regKey" } else { $registryPath = $hive }
    } elseif ($polType -match 'Security\s*Template' -or $polType -match 'Audit\s*Policy') {
        if ($regKey) { $registryPath = "$polType\$regKey" } else { $registryPath = $polType }
    } else {
        $registryPath = $regKey
    }

    $settingName = if ($valueName) { $valueName } else { $polSetName }
    $policyName  = if ($polSetName) { $polSetName } else { $valueName }

    # Prefer human-readable "Option" columns for the recommended / current
    # values.  Fall back to the raw baseline/effective otherwise.
    $recommended = if ($baseOption) { $baseOption } else { $baseline }
    $current     = if ($effOption)  { $effOption  } else { $effective }
    if (-not $current) {
        # Show explicit marker when the setting is missing on the host.
        if (-not $effGpo) { $current = '(not configured on host)' }
    }

    $status = Get-Status -Baseline $baseline -BaseOption $baseOption `
        -Effective $effective -EffectiveGpo $effGpo -SettingName $valueName

    # Rewrite the Policy Analyzer sentinels into human-readable text.
    if ($recommended -match '^\s*\[\[\[\s*delete(\s+all\s+values)?\s*\]\]\]\s*$') {
        $recommended = '(value must not be present)'
    }
    if ($settingName -match '^\s*\[\[\[\s*Delete\s+all\s+values\s*\]\]\]\s*$') {
        $settingName = '(all values under key)'
    }

    $noteBits = @()
    if ($baseType) { $noteBits += "Baseline type: $baseType" }
    if ($baseGpo)  { $noteBits += "Source: $baseGpo" }
    if ($effGpo -and $effGpo -ne $baseGpo) { $noteBits += "Effective from: $effGpo" }
    if ($explain) {
        $snippet = Clean-CellText $explain
        if ($snippet.Length -gt 260) { $snippet = $snippet.Substring(0, 257) + '...' }
        $noteBits += $snippet
    }
    $notes = ($noteBits -join ' | ')

    $category = if ($polConfig) { $polConfig } else { $polType }

    $mapped.Add([pscustomobject]@{
        Category           = Clean-CellText $category
        'Policy Name'      = Clean-CellText $policyName
        Scope              = $scope
        'Policy Path'      = Clean-CellText $polPath
        'Registry Path'    = Clean-CellText $registryPath
        'Setting name'     = Clean-CellText $settingName
        'Current Value'    = Clean-CellText $current
        'Recommended Value'= Clean-CellText $recommended
        Status             = $status
        Priority           = 'Medium'
        Notes              = $notes
    }) | Out-Null
}

if ($mapped.Count -eq 0) {
    throw "No usable rows were mapped from the Policy Analyzer workbook."
}

# Sort by Category then Policy Path for readability.
$mapped = $mapped | Sort-Object -Property @{Expression='Category'}, @{Expression='Policy Path'}, @{Expression='Policy Name'}

Write-Host ("  Mapped {0} policy rows." -f $mapped.Count) -ForegroundColor Green

# --------------------------------------------------------------------------
#  Totals
# --------------------------------------------------------------------------
$total      = $mapped.Count
$configured = ($mapped | Where-Object { $_.Status -eq 'Configured'     }).Count
$mismatch   = ($mapped | Where-Object { $_.Status -eq 'Mismatch'       }).Count
$notConfig  = ($mapped | Where-Object { $_.Status -eq 'Not Configured' }).Count
$unknown    = ($mapped | Where-Object { $_.Status -eq 'Unknown'        }).Count
$assessed   = $configured + $mismatch + $notConfig
$computedScore = if ($assessed -gt 0) { [math]::Round(($configured / $assessed) * 100, 1) } else { 0 }

$ncHigh   = ($mapped | Where-Object { $_.Status -in @('Mismatch','Not Configured') -and $_.Priority -eq 'High'   }).Count
$ncMedium = ($mapped | Where-Object { $_.Status -in @('Mismatch','Not Configured') -and $_.Priority -eq 'Medium' }).Count
$ncLow    = ($mapped | Where-Object { $_.Status -in @('Mismatch','Not Configured') -and $_.Priority -eq 'Low'    }).Count

# --------------------------------------------------------------------------
#  XLSX writer (identical layout to Convert-CisCatHtmlToXlsx.ps1)
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
$outRows = New-Object System.Collections.ArrayList
[void]$outRows.Add(@($headers | ForEach-Object { @{ V = $_; S = 1 } }))

foreach ($row in $mapped) {
    $statusStyle = Get-StatusStyle $row.Status
    [void]$outRows.Add(@(
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
    @{ Min=1;  Max=1;  Width=32 },
    @{ Min=2;  Max=2;  Width=55 },
    @{ Min=3;  Max=3;  Width=10 },
    @{ Min=4;  Max=4;  Width=55 },
    @{ Min=5;  Max=5;  Width=50 },
    @{ Min=6;  Max=6;  Width=30 },
    @{ Min=7;  Max=7;  Width=32 },
    @{ Min=8;  Max=8;  Width=32 },
    @{ Min=9;  Max=9;  Width=16 },
    @{ Min=10; Max=10; Width=10 },
    @{ Min=11; Max=11; Width=60 }
)
$lastRow = $outRows.Count
$auditSheet = Build-SheetXml -Rows $outRows.ToArray() -Cols $cols -Freeze $true -AutoFilterRef ("A1:K{0}" -f $lastRow)

# --------------------------------------------------------------------------
#  Summary sheet
# --------------------------------------------------------------------------
$sumRows = New-Object System.Collections.ArrayList
[void]$sumRows.Add(@( @{ V='Policy Analyzer - Converted Report'; S=6 } ))
[void]$sumRows.Add(@( @{ V='Generated';   S=6 }, @{ V=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); S=0 } ))
[void]$sumRows.Add(@( @{ V='Source XLSX'; S=6 }, @{ V=$InputPath; S=0 } ))
if ($baselineNames.Count -gt 0) {
    $names = ($baselineNames | Sort-Object) -join '; '
    [void]$sumRows.Add(@( @{ V='Baseline(s)'; S=6 }, @{ V=$names; S=0 } ))
}
[void]$sumRows.Add(@( @{ V=''; S=0 } ))
[void]$sumRows.Add(@( @{ V='Metric'; S=7 }, @{ V='Count'; S=7 } ))
[void]$sumRows.Add(@( @{ V='Total policies';      S=6 }, @{ V=$total;      S=5 } ))
[void]$sumRows.Add(@( @{ V='Configured';          S=6 }, @{ V=$configured; S=2 } ))
[void]$sumRows.Add(@( @{ V='Mismatch';            S=6 }, @{ V=$mismatch;   S=3 } ))
[void]$sumRows.Add(@( @{ V='Not Configured';      S=6 }, @{ V=$notConfig;  S=4 } ))
[void]$sumRows.Add(@( @{ V='Unknown';             S=6 }, @{ V=$unknown;    S=8 } ))
[void]$sumRows.Add(@( @{ V='Compliance score';    S=6 }, @{ V=("{0}% (of {1} assessed)" -f $computedScore, $assessed); S=5 } ))
[void]$sumRows.Add(@( @{ V=''; S=0 } ))
[void]$sumRows.Add(@( @{ V='Non-compliant by priority'; S=7 }, @{ V='Count'; S=7 } ))
[void]$sumRows.Add(@( @{ V='High';   S=6 }, @{ V=$ncHigh;   S=5 } ))
[void]$sumRows.Add(@( @{ V='Medium'; S=6 }, @{ V=$ncMedium; S=5 } ))
[void]$sumRows.Add(@( @{ V='Low';    S=6 }, @{ V=$ncLow;    S=5 } ))

$sumCols = @( @{ Min=1; Max=1; Width=28 }, @{ Min=2; Max=2; Width=70 } )
$summarySheet = Build-SheetXml -Rows $sumRows.ToArray() -Cols $sumCols

# --------------------------------------------------------------------------
#  Write the workbook
# --------------------------------------------------------------------------
Save-Xlsx -Path $OutputPath -Styles @{ Xml = $stylesXml } `
    -SheetXmls @($summarySheet, $auditSheet) -SheetNames @('Summary','Audit Results')

Write-Host ""
Write-Host ("Excel report written to: {0}" -f $OutputPath) -ForegroundColor Green

if ($OpenWhenDone) { Invoke-Item -LiteralPath $OutputPath }
