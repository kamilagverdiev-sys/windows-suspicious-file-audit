[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ScanPath,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$RecentDays = 45,

    [Parameter()]
    [ValidateRange(1, 100000)]
    [int]$MaxFiles = 15000,

    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'reports'),

    [Parameter()]
    [string]$StateDirectory = (Join-Path $PSScriptRoot 'state'),

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [string]$AuditProfile = 'Quick',

    [Parameter()]
    [switch]$IncludeLargeUserFolders,

    [Parameter()]
    [switch]$SkipFileScan,

    [Parameter()]
    [switch]$SkipHostInspection,

    [Parameter()]
    [switch]$VerifyFindingsWithKaspersky,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$MaxKasperskyFiles = 25
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:AuditErrors = New-Object System.Collections.Generic.List[string]
$script:KasperskyResults = New-Object System.Collections.Generic.List[object]
$script:SeenFindings = @{}
$script:IsComplete = $true
$script:Cutoff = (Get-Date).AddDays(-$RecentDays)
$script:ToolFiles = @(
    [IO.Path]::GetFullPath($PSCommandPath),
    [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'Start-SuspiciousFileAudit.cmd')),
    [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'Start-DeepAudit.cmd')),
    [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'Install-WeeklyAudit.ps1')),
    [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'Remove-WeeklyAudit.ps1'))
)

function Add-AuditError {
    param(
        [string]$Message,
        [switch]$AffectsCompleteness
    )

    [void]$script:AuditErrors.Add($Message)
    if ($AffectsCompleteness) {
        $script:IsComplete = $false
    }
}

function Get-NormalizedPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ''
    }

    $expandedPath = [Environment]::ExpandEnvironmentVariables($Path).Trim().Trim('"')
    try {
        return [IO.Path]::GetFullPath($expandedPath).TrimEnd('\')
    }
    catch {
        return $expandedPath.TrimEnd('\')
    }
}

function Test-PathWithinRoot {
    param(
        [string]$Path,
        [string]$Root
    )

    $normalizedPath = Get-NormalizedPath -Path $Path
    $normalizedRoot = Get-NormalizedPath -Path $Root
    if ([string]::IsNullOrWhiteSpace($normalizedPath) -or [string]::IsNullOrWhiteSpace($normalizedRoot)) {
        return $false
    }

    return ($normalizedPath -ieq $normalizedRoot) -or
        $normalizedPath.StartsWith(($normalizedRoot + '\'), [StringComparison]::OrdinalIgnoreCase)
}

function Add-Finding {
    param(
        [ValidateSet('High', 'Medium', 'Low', 'Info')]
        [string]$Severity,
        [string]$Category,
        [string]$Item,
        [string]$Reason,
        [string]$Path = '',
        [string]$Publisher = '',
        [string]$Sha256 = ''
    )

    $normalizedPath = Get-NormalizedPath -Path $Path
    $key = '{0}|{1}|{2}|{3}|{4}' -f $Severity, $Category, $Item, $Reason, $normalizedPath
    if ($script:SeenFindings.ContainsKey($key)) {
        return
    }

    $script:SeenFindings[$key] = $true
    $score = switch ($Severity) {
        'High' { 80 }
        'Medium' { 50 }
        'Low' { 25 }
        default { 0 }
    }

    [void]$script:Findings.Add([pscustomobject]@{
            Severity  = $Severity
            Score     = $score
            Category  = $Category
            Item      = $Item
            Reason    = $Reason
            Path      = $normalizedPath
            Publisher = $Publisher
            SHA256    = $Sha256
        })
}

function Test-UserWritableOrTempPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    $suspectRoots = @(
        $env:TEMP,
        $env:TMP,
        $env:APPDATA,
        $env:LOCALAPPDATA,
        (Join-Path $env:LOCALAPPDATA 'Temp'),
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:PUBLIC 'Downloads')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($root in $suspectRoots) {
        if (Test-PathWithinRoot -Path $Path -Root $root) {
            return $true
        }
    }

    return $false
}

function Get-SignatureDetails {
    param([string]$Path)

    $result = [pscustomobject]@{
        Status    = 'NotChecked'
        Publisher = ''
    }

    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $publisher = ''
        if ($null -ne $signature.SignerCertificate) {
            $publisher = $signature.SignerCertificate.Subject
        }

        return [pscustomobject]@{
            Status    = [string]$signature.Status
            Publisher = $publisher
        }
    }
    catch {
        return $result
    }
}

function Get-SafeHash {
    param([string]$Path)

    try {
        return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash
    }
    catch {
        return ''
    }
}

function Resolve-CommandFilePath {
    param([string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) {
        return ''
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($Command).Trim()
    if ($expanded -match '^\s*"([^"]+)"') {
        return $Matches[1]
    }

    if ($expanded -match '^\s*([^\s]+\.(?:exe|com|bat|cmd|ps1|vbs|js|jse|wsf|hta|scr|dll|msi))\b') {
        return $Matches[1]
    }

    return $expanded.Trim('"')
}

function Get-FirstMatchValue {
    param([System.Collections.IDictionary]$MatchValues)

    foreach ($index in 1..3) {
        $value = [string]$MatchValues[$index]
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    return ''
}

function Resolve-CommandPayloadPath {
    param(
        [string]$Command,
        [string]$LauncherPath
    )

    if ([string]::IsNullOrWhiteSpace($Command)) {
        return ''
    }

    $launcherName = [IO.Path]::GetFileNameWithoutExtension($LauncherPath)
    if ($launcherName -match '^(?i:powershell|pwsh)$' -and
        $Command -match '(?i)(?:-file|-f)\s+(?:"([^"]+)"|''([^'']+)''|([^\s]+))') {
        return Get-FirstMatchValue -MatchValues $Matches
    }

    if ($launcherName -match '^(?i:wscript|cscript|mshta)$' -and
        $Command -match '(?i)\s+(?:"([^"]+\.(?:vbs|vbe|js|jse|wsf|hta))"|''([^'']+\.(?:vbs|vbe|js|jse|wsf|hta))''|([^\s]+\.(?:vbs|vbe|js|jse|wsf|hta)))\b') {
        return Get-FirstMatchValue -MatchValues $Matches
    }

    if ($launcherName -match '^(?i:rundll32)$' -and
        $Command -match '(?i)\s+(?:"([^"]+\.dll)"|''([^'']+\.dll)''|([^\s,]+\.dll))[, ]') {
        return Get-FirstMatchValue -MatchValues $Matches
    }

    return ''
}

function Inspect-PersistentCommand {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Command
    )

    $launcherPath = Resolve-CommandFilePath -Command $Command
    $payloadPath = Resolve-CommandPayloadPath -Command $Command -LauncherPath $launcherPath
    $targetPath = if ([string]::IsNullOrWhiteSpace($payloadPath)) { $launcherPath } else { $payloadPath }
    $reasons = New-Object System.Collections.Generic.List[string]
    $severity = 'Low'

    if ($Category -eq 'Scheduled Task' -and $Name -eq '\Suspicious File Audit Weekly' -and
        ($script:ToolFiles -contains (Get-NormalizedPath -Path $payloadPath))) {
        return
    }

    if (Test-UserWritableOrTempPath -Path $targetPath) {
        [void]$reasons.Add('launches from a user-writable or temporary folder')
        $severity = 'Medium'
    }

    if ($Command -match '(?i)(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?\b') {
        [void]$reasons.Add('uses a script or living-off-the-land launcher')
        $severity = 'Medium'
    }

    if ($Command -match '(?i)(-enc(odedcommand)?\b|frombase64string|javascript:|http[s]?://)') {
        [void]$reasons.Add('contains encoded or remote-content indicators')
        $severity = 'High'
    }

    if ($reasons.Count -eq 0) {
        return
    }

    $publisher = ''
    $hash = ''
    if (-not [string]::IsNullOrWhiteSpace($targetPath) -and (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
        $signature = Get-SignatureDetails -Path $targetPath
        $publisher = $signature.Publisher
        if ($signature.Status -eq 'Valid' -and $severity -eq 'Medium') {
            $severity = 'Low'
        }
        $hash = Get-SafeHash -Path $targetPath
    }

    Add-Finding -Severity $severity -Category $Category -Item $Name `
        -Reason ($reasons -join '; ') -Path $targetPath -Publisher $publisher -Sha256 $hash
}

function Inspect-RegistryAutoruns {
    $registryLocations = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($location in $registryLocations) {
        try {
            if (-not (Test-Path $location)) {
                continue
            }

            $values = (Get-ItemProperty -Path $location).PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' }
            foreach ($value in $values) {
                Inspect-PersistentCommand -Category 'Registry Autorun' `
                    -Name ('{0}\{1}' -f $location, $value.Name) -Command ([string]$value.Value)
            }
        }
        catch {
            Add-AuditError ('Could not read registry autoruns at {0}: {1}' -f $location, $_.Exception.Message) -AffectsCompleteness
        }
    }
}

function Inspect-StartupFolders {
    $folders = @(
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
    )

    foreach ($folder in $folders) {
        if (-not (Test-Path -LiteralPath $folder)) {
            continue
        }

        try {
            foreach ($file in Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction Stop) {
                if ($file.Name -ieq 'desktop.ini') {
                    continue
                }

                $signature = Get-SignatureDetails -Path $file.FullName
                $severity = if ($signature.Status -eq 'Valid') { 'Info' } else { 'Medium' }
                Add-Finding -Severity $severity -Category 'Startup Folder' -Item $file.Name `
                    -Reason ('starts with Windows; signature status: {0}' -f $signature.Status) `
                    -Path $file.FullName -Publisher $signature.Publisher -Sha256 (Get-SafeHash -Path $file.FullName)
            }
        }
        catch {
            Add-AuditError ('Could not inspect startup folder {0}: {1}' -f $folder, $_.Exception.Message) -AffectsCompleteness
        }
    }
}

function Inspect-ScheduledTasks {
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.TaskPath -notlike '\Microsoft\*' }

        foreach ($task in $tasks) {
            foreach ($action in @($task.Actions)) {
                $command = ('{0} {1}' -f $action.Execute, $action.Arguments).Trim()
                Inspect-PersistentCommand -Category 'Scheduled Task' `
                    -Name ('{0}{1}' -f $task.TaskPath, $task.TaskName) -Command $command
            }
        }
    }
    catch {
        Add-AuditError ('Could not inspect scheduled tasks: {0}' -f $_.Exception.Message) -AffectsCompleteness
    }
}

function Inspect-AutoStartServices {
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop |
            Where-Object { $_.StartMode -eq 'Auto' -and -not [string]::IsNullOrWhiteSpace($_.PathName) }

        foreach ($service in $services) {
            Inspect-PersistentCommand -Category 'Auto-start Service' `
                -Name $service.Name -Command ([string]$service.PathName)
        }
    }
    catch {
        Add-AuditError ('Could not inspect auto-start services: {0}' -f $_.Exception.Message) -AffectsCompleteness
    }
}

function Inspect-WmiPersistence {
    try {
        $commandConsumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName CommandLineEventConsumer -ErrorAction Stop)
        foreach ($consumer in $commandConsumers) {
            $command = ('{0} {1}' -f $consumer.ExecutablePath, $consumer.CommandLineTemplate).Trim()
            Inspect-PersistentCommand -Category 'WMI Persistence' -Name ([string]$consumer.Name) -Command $command
            if (-not ($script:Findings | Where-Object { $_.Category -eq 'WMI Persistence' -and $_.Item -eq $consumer.Name })) {
                Add-Finding -Severity 'Medium' -Category 'WMI Persistence' -Item ([string]$consumer.Name) `
                    -Reason 'permanent WMI command consumer should be reviewed' -Path (Resolve-CommandFilePath -Command $command)
            }
        }

        $scriptConsumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName ActiveScriptEventConsumer -ErrorAction Stop)
        foreach ($consumer in $scriptConsumers) {
            $reason = 'permanent WMI script consumer should be reviewed'
            $severity = 'Medium'
            if ([string]$consumer.ScriptText -match '(?i)(frombase64string|http[s]?://|powershell|-enc(odedcommand)?)') {
                $reason += '; script contains encoded or remote-content indicators'
                $severity = 'High'
            }
            Add-Finding -Severity $severity -Category 'WMI Persistence' -Item ([string]$consumer.Name) -Reason $reason
        }
    }
    catch {
        Add-AuditError ('Could not inspect WMI persistence: {0}' -f $_.Exception.Message) -AffectsCompleteness
    }
}

function Inspect-Processes {
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.ExecutablePath) }

        foreach ($process in $processes) {
            if (-not (Test-UserWritableOrTempPath -Path $process.ExecutablePath)) {
                continue
            }

            $signature = Get-SignatureDetails -Path $process.ExecutablePath
            $severity = if ($signature.Status -eq 'Valid') { 'Low' } else { 'Medium' }
            Add-Finding -Severity $severity -Category 'Running Process' -Item $process.Name `
                -Reason ('is running from a user-writable location; signature status: {0}' -f $signature.Status) `
                -Path $process.ExecutablePath -Publisher $signature.Publisher -Sha256 (Get-SafeHash -Path $process.ExecutablePath)
        }
    }
    catch {
        Add-AuditError ('Could not inspect running processes: {0}' -f $_.Exception.Message) -AffectsCompleteness
    }
}

function Get-KasperskyCli {
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Kaspersky Lab'),
        (Join-Path $env:ProgramFiles 'Kaspersky Lab')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) }

    foreach ($root in $roots) {
        $candidate = Get-ChildItem -LiteralPath $root -Filter 'avp.com' -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($null -ne $candidate) {
            return $candidate.FullName
        }
    }

    return ''
}

function Invoke-KasperskyReview {
    param(
        [object[]]$Findings,
        [string]$Timestamp
    )

    $kasperskyCli = Get-KasperskyCli
    if ([string]::IsNullOrWhiteSpace($kasperskyCli)) {
        Add-AuditError 'Kaspersky verification was requested, but avp.com was not found.'
        return
    }

    $reviewDirectory = Join-Path $OutputDirectory ('kaspersky-review-{0}' -f $Timestamp)
    New-Item -Path $reviewDirectory -ItemType Directory -Force | Out-Null
    $targets = @(
        $Findings |
            Where-Object { $_.Severity -in @('High', 'Medium') -and -not [string]::IsNullOrWhiteSpace($_.Path) } |
            Select-Object -ExpandProperty Path -Unique |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First $MaxKasperskyFiles
    )

    foreach ($target in $targets) {
        $reportName = ('scan-{0}.txt' -f ([Guid]::NewGuid().ToString('N')))
        $kasperskyReport = Join-Path $reviewDirectory $reportName
        $consoleOutput = & $kasperskyCli 'SCAN' $target '/i0' ('/RA:{0}' -f $kasperskyReport) 2>&1
        $exitCode = $LASTEXITCODE
        $detected = $null
        if (Test-Path -LiteralPath $kasperskyReport) {
            $match = Select-String -LiteralPath $kasperskyReport -Pattern 'Total detected:\s*(\d+)' -ErrorAction SilentlyContinue |
                Select-Object -Last 1
            if ($null -ne $match) {
                $detected = [int]$match.Matches[0].Groups[1].Value
            }
        }
        [void]$script:KasperskyResults.Add([pscustomobject]@{
                Path       = $target
                ExitCode   = $exitCode
                Detected   = $detected
                ReportPath = $kasperskyReport
                Console    = ($consoleOutput -join [Environment]::NewLine)
            })
    }
}

function Get-FindingIdentity {
    param([object]$Finding)

    return ('{0}|{1}|{2}|{3}' -f $Finding.Category, $Finding.Item, $Finding.Path, $Finding.Reason)
}

function Compare-WithPreviousAudit {
    param(
        [object[]]$Findings,
        [string]$SnapshotPath
    )

    if (-not (Test-Path -LiteralPath $SnapshotPath)) {
        return [pscustomobject]@{
            HasBaseline      = $false
            NewFindings      = @()
            ResolvedFindings = @()
        }
    }

    try {
        $previousSnapshot = Get-Content -LiteralPath $SnapshotPath -Raw -ErrorAction Stop | ConvertFrom-Json
        $previousFindings = @($previousSnapshot.Findings)
        $previousKeys = @{}
        foreach ($finding in $previousFindings) {
            $previousKeys[(Get-FindingIdentity -Finding $finding)] = $true
        }
        $currentKeys = @{}
        foreach ($finding in $Findings) {
            $currentKeys[(Get-FindingIdentity -Finding $finding)] = $true
        }

        return [pscustomobject]@{
            HasBaseline      = $true
            NewFindings      = @($Findings | Where-Object { -not $previousKeys.ContainsKey((Get-FindingIdentity -Finding $_)) })
            ResolvedFindings = @($previousFindings | Where-Object { -not $currentKeys.ContainsKey((Get-FindingIdentity -Finding $_)) })
        }
    }
    catch {
        Add-AuditError ('Could not compare with previous audit snapshot: {0}' -f $_.Exception.Message)
        return [pscustomobject]@{
            HasBaseline      = $false
            NewFindings      = @()
            ResolvedFindings = @()
        }
    }
}

function Get-ScopeFingerprint {
    param([object]$Scope)

    $scopeJson = $Scope | ConvertTo-Json -Compress -Depth 4
    $bytes = [Text.Encoding]::UTF8.GetBytes($scopeJson)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '').Substring(0, 12).ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Write-HtmlReport {
    param(
        [object]$Summary,
        [string]$Path
    )

    $style = @'
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #202124; background: #f7f8fa; }
h1 { margin-bottom: 4px; }
.muted { color: #626a73; }
.cards { display: flex; gap: 12px; margin: 22px 0; flex-wrap: wrap; }
.card { padding: 14px 20px; background: #fff; border-radius: 10px; border: 1px solid #e0e3e7; min-width: 100px; }
.high { color: #b42318; } .medium { color: #b54708; } .low { color: #175cd3; } .info { color: #475467; }
table { width: 100%; border-collapse: collapse; background: #fff; margin: 12px 0 26px; font-size: 13px; }
th, td { border: 1px solid #e0e3e7; padding: 8px; text-align: left; vertical-align: top; }
th { background: #eef1f5; }
code { word-break: break-all; }
</style>
'@
    $findingsTable = if ($Summary.Findings.Count -gt 0) {
        $Summary.Findings | Select-Object Severity, Category, Item, Reason, Path, Publisher, SHA256 |
            ConvertTo-Html -Fragment
    }
    else {
        '<p>No suspicious findings were recorded by this heuristic audit.</p>'
    }
    $kasperskyTable = if ($Summary.KasperskyValidation.Count -gt 0) {
        $Summary.KasperskyValidation | Select-Object Path, Detected, ExitCode, ReportPath |
            ConvertTo-Html -Fragment
    }
    else {
        '<p>Kaspersky validation was not requested or no reviewable files were found.</p>'
    }
    $errorsTable = if ($Summary.Errors.Count -gt 0) {
        $Summary.Errors | ForEach-Object { [pscustomobject]@{ Message = $_ } } | ConvertTo-Html -Fragment
    }
    else {
        '<p>No audit errors recorded.</p>'
    }
    $changesTable = if (-not $Summary.AuditComplete) {
        '<p>This audit was incomplete. History comparison was skipped to avoid false resolved findings.</p>'
    }
    elseif (-not $Summary.HasBaseline) {
        '<p>This is the first stored run. It becomes the comparison baseline for the next audit.</p>'
    }
    elseif ($Summary.NewFindings.Count -gt 0) {
        $Summary.NewFindings | Select-Object Severity, Category, Item, Reason, Path |
            ConvertTo-Html -Fragment
    }
    else {
        '<p>No new findings compared with the previous audit.</p>'
    }
    $resolvedTable = if (-not $Summary.AuditComplete) {
        '<p>Resolved findings are unavailable for an incomplete audit.</p>'
    }
    elseif ($Summary.HasBaseline -and $Summary.ResolvedFindings.Count -gt 0) {
        $Summary.ResolvedFindings | Select-Object Severity, Category, Item, Reason, Path |
            ConvertTo-Html -Fragment
    }
    else {
        '<p>No previously recorded findings disappeared in this run.</p>'
    }
    $body = @"
<h1>Suspicious File Audit</h1>
<p class="muted">Created $($Summary.Finished) on $($Summary.ComputerName). Heuristic triage only; findings are not a malware verdict.</p>
<div class="cards">
<div class="card"><strong>Complete</strong><br>$($Summary.AuditComplete)</div>
<div class="card high"><strong>High</strong><br>$($Summary.HighCount)</div>
<div class="card medium"><strong>Medium</strong><br>$($Summary.MediumCount)</div>
<div class="card low"><strong>Low</strong><br>$($Summary.LowCount)</div>
<div class="card info"><strong>Info</strong><br>$($Summary.Informational)</div>
<div class="card"><strong>Files checked</strong><br>$($Summary.FilesChecked)</div>
<div class="card"><strong>New since last run</strong><br>$($Summary.NewFindings.Count)</div>
</div>
<h2>New Since Previous Audit</h2>
$changesTable
<h2>Resolved Since Previous Audit</h2>
$resolvedTable
<h2>Findings</h2>
$findingsTable
<h2>Kaspersky Validation</h2>
$kasperskyTable
<h2>Audit Errors</h2>
$errorsTable
"@
    ConvertTo-Html -Title 'Suspicious File Audit' -Head $style -Body $body |
        Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-DefaultScanPaths {
    $paths = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        $env:TEMP,
        (Join-Path $env:LOCALAPPDATA 'Temp')
    )

    if ($IncludeLargeUserFolders) {
        $paths += (Join-Path $env:APPDATA '')
        $paths += (Join-Path $env:LOCALAPPDATA '')
    }

    return @($paths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique)
}

function Inspect-Files {
    param([string[]]$Paths)

    $riskyExtensions = @(
        '.exe', '.com', '.scr', '.dll', '.sys', '.msi', '.msp',
        '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse',
        '.wsf', '.wsh', '.hta', '.lnk', '.jar'
    )
    $filesChecked = 0

    foreach ($path in $Paths) {
        try {
            $remaining = [Math]::Max(0, $MaxFiles - $filesChecked)
            if ($remaining -eq 0) {
                Add-AuditError ('File scan stopped at MaxFiles limit: {0}' -f $MaxFiles) -AffectsCompleteness
                return $filesChecked
            }

            $enumerationErrors = @()
            $files = @(
                Get-ChildItem -LiteralPath $path -File -Force -Recurse -ErrorAction SilentlyContinue -ErrorVariable enumerationErrors |
                Where-Object { $riskyExtensions -contains $_.Extension.ToLowerInvariant() } |
                Where-Object {
                    $fullName = Get-NormalizedPath -Path $_.FullName
                    -not (($script:ToolFiles -contains $fullName) -or
                        (Test-PathWithinRoot -Path $fullName -Root $script:OutputPath))
                } |
                Select-Object -First ($remaining + 1)
            )
            if ($enumerationErrors.Count -gt 0) {
                Add-AuditError ('Could not fully scan path {0}: {1}' -f $path, $enumerationErrors[0].Exception.Message) -AffectsCompleteness
            }
            $truncated = $files.Count -gt $remaining

            foreach ($file in @($files | Select-Object -First $remaining)) {
                $fullPath = [IO.Path]::GetFullPath($file.FullName)
                $filesChecked++
                $reasons = New-Object System.Collections.Generic.List[string]
                $severity = 'Low'

                if ($file.LastWriteTime -ge $script:Cutoff) {
                    [void]$reasons.Add(('executable or script created/modified within {0} days' -f $RecentDays))
                }

                if ($file.Name -match '(?i)\.(pdf|docx?|xlsx?|jpg|png|txt|zip)\.(exe|scr|com|bat|cmd|ps1|js|jse|vbs|vbe|wsf|hta|lnk)$') {
                    [void]$reasons.Add('uses a deceptive double extension')
                    $severity = 'High'
                }

                if (($file.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) {
                    [void]$reasons.Add('is hidden')
                    if ($severity -ne 'High') {
                        $severity = 'Medium'
                    }
                }

                $signature = Get-SignatureDetails -Path $file.FullName
                if ($signature.Status -ne 'Valid') {
                    [void]$reasons.Add(('has no valid digital signature ({0})' -f $signature.Status))
                    if ($severity -ne 'High') {
                        $severity = 'Medium'
                    }
                }

                if ($reasons.Count -gt 0) {
                    Add-Finding -Severity $severity -Category 'File' -Item $file.Name `
                        -Reason ($reasons -join '; ') -Path $file.FullName `
                        -Publisher $signature.Publisher -Sha256 (Get-SafeHash -Path $file.FullName)
                }

            }

            if ($truncated) {
                Add-AuditError ('File scan stopped at MaxFiles limit: {0}' -f $MaxFiles) -AffectsCompleteness
                return $filesChecked
            }
        }
        catch {
            Add-AuditError ('Could not scan path {0}: {1}' -f $path, $_.Exception.Message) -AffectsCompleteness
        }
    }

    return $filesChecked
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path -LiteralPath $StateDirectory)) {
    New-Item -Path $StateDirectory -ItemType Directory -Force | Out-Null
}
$script:OutputPath = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\') + '\'

$started = Get-Date
if (-not $SkipHostInspection) {
    Write-Host 'Checking persistence locations and currently running processes...'
    Inspect-RegistryAutoruns
    Inspect-StartupFolders
    Inspect-ScheduledTasks
    Inspect-AutoStartServices
    Inspect-WmiPersistence
    Inspect-Processes
}

$requestedPaths = @(
    if ($PSBoundParameters.ContainsKey('ScanPath')) {
        $ScanPath | ForEach-Object { Get-NormalizedPath -Path $_ } | Select-Object -Unique
    }
    else {
        Get-DefaultScanPaths | ForEach-Object { Get-NormalizedPath -Path $_ } | Select-Object -Unique
    }
)
$resolvedPaths = @($requestedPaths | Where-Object { Test-Path -LiteralPath $_ })
if (-not $SkipFileScan) {
    foreach ($missingPath in @($requestedPaths | Where-Object { -not (Test-Path -LiteralPath $_) })) {
        Add-AuditError ('Scan path does not exist or is unavailable: {0}' -f $missingPath) -AffectsCompleteness
    }
}

$checkedFiles = 0
if (-not $SkipFileScan) {
    Write-Host ('Scanning risky file types under {0} location(s)...' -f $resolvedPaths.Count)
    $checkedFiles = Inspect-Files -Paths $resolvedPaths
}

$sortedFindings = @($script:Findings | Sort-Object -Property @{ Expression = 'Score'; Descending = $true }, Category, Item)
$timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss-fff')
if ($VerifyFindingsWithKaspersky) {
    Write-Host 'Validating high and medium file findings with Kaspersky (report only)...'
    Invoke-KasperskyReview -Findings $sortedFindings -Timestamp $timestamp
}

$finished = Get-Date
$findingsPath = Join-Path $OutputDirectory ('findings-{0}.csv' -f $timestamp)
$reportPath = Join-Path $OutputDirectory ('report-{0}.json' -f $timestamp)
$htmlPath = Join-Path $OutputDirectory ('report-{0}.html' -f $timestamp)
$scope = [ordered]@{
    AuditProfile            = $AuditProfile
    ScanPaths               = @($requestedPaths | Sort-Object)
    IncludeLargeUserFolders = [bool]$IncludeLargeUserFolders
    SkipFileScan            = [bool]$SkipFileScan
    SkipHostInspection      = [bool]$SkipHostInspection
    RecentDays              = $RecentDays
    MaxFiles                = $MaxFiles
}
$scopeFingerprint = Get-ScopeFingerprint -Scope $scope
$snapshotPath = Join-Path $StateDirectory ('last-audit-{0}-{1}.json' -f $AuditProfile, $scopeFingerprint)
if ($script:IsComplete) {
    $comparison = Compare-WithPreviousAudit -Findings $sortedFindings -SnapshotPath $snapshotPath
}
else {
    Add-AuditError 'History comparison and baseline update were skipped because this audit was incomplete.'
    $comparison = [pscustomobject]@{
        HasBaseline      = $false
        NewFindings      = @()
        ResolvedFindings = @()
    }
}
$summary = [pscustomobject]@{
    Started        = $started.ToString('s')
    Finished       = $finished.ToString('s')
    Duration       = ($finished - $started).ToString()
    ComputerName   = $env:COMPUTERNAME
    UserName       = $env:USERNAME
    AuditProfile   = $AuditProfile
    AuditComplete  = $script:IsComplete
    Scope          = $scope
    ScopeFingerprint = $scopeFingerprint
    ScanPaths      = $resolvedPaths
    FilesChecked   = $checkedFiles
    FindingCount   = $sortedFindings.Count
    HighCount      = @($sortedFindings | Where-Object Severity -eq 'High').Count
    MediumCount    = @($sortedFindings | Where-Object Severity -eq 'Medium').Count
    LowCount       = @($sortedFindings | Where-Object Severity -eq 'Low').Count
    Informational  = @($sortedFindings | Where-Object Severity -eq 'Info').Count
    Errors         = @($script:AuditErrors | ForEach-Object { $_ })
    KasperskyValidation = @($script:KasperskyResults | ForEach-Object { $_ })
    HasBaseline    = $comparison.HasBaseline
    NewFindings    = @($comparison.NewFindings)
    ResolvedFindings = @($comparison.ResolvedFindings)
    Findings       = @($sortedFindings)
}

$sortedFindings | Export-Csv -LiteralPath $findingsPath -NoTypeInformation -Encoding UTF8
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-HtmlReport -Summary $summary -Path $htmlPath
if ($script:IsComplete) {
    $summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $snapshotPath -Encoding UTF8
}

Write-Host ''
Write-Host 'Audit finished. This is a triage report, not a malware verdict.'
Write-Host ('High: {0}; Medium: {1}; Low: {2}; Info: {3}' -f $summary.HighCount, $summary.MediumCount, $summary.LowCount, $summary.Informational)
Write-Host ('Risky files reviewed: {0}' -f $checkedFiles)
Write-Host ('CSV findings: {0}' -f $findingsPath)
Write-Host ('JSON report:  {0}' -f $reportPath)
Write-Host ('HTML report:  {0}' -f $htmlPath)
if ($summary.HasBaseline) {
    Write-Host ('New findings since previous audit: {0}; resolved: {1}' -f $summary.NewFindings.Count, $summary.ResolvedFindings.Count)
}
elseif (-not $summary.AuditComplete) {
    Write-Host 'History was not updated because the audit did not complete all requested checks.'
}
else {
    Write-Host 'History baseline created. The next run will show what changed.'
}
if ($summary.KasperskyValidation.Count -gt 0) {
    Write-Host ('Files validated with Kaspersky: {0}' -f $summary.KasperskyValidation.Count)
}

if ($sortedFindings.Count -gt 0) {
    Write-Host ''
    Write-Host 'Top findings:'
    $sortedFindings | Select-Object -First 15 Severity, Category, Item, Reason, Path | Format-Table -AutoSize
}
