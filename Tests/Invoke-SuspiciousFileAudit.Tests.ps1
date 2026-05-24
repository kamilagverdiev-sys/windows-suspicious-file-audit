$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-SuspiciousFileAudit.ps1'

function New-AuditTestDirectory {
    param([string]$Name)

    $path = Join-Path $TestDrive $Name
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    return $path
}

function Get-LatestAuditReport {
    param([string]$OutputDirectory)

    $reportFile = Get-ChildItem -LiteralPath $OutputDirectory -Filter 'report-*.json' |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    return Get-Content -LiteralPath $reportFile.FullName -Raw | ConvertFrom-Json
}

Describe 'Invoke-SuspiciousFileAudit file findings' {
    BeforeEach {
        $outputDirectory = New-AuditTestDirectory -Name ('reports-' + [Guid]::NewGuid().ToString('N'))
        $stateDirectory = New-AuditTestDirectory -Name ('state-' + [Guid]::NewGuid().ToString('N'))
    }

    It 'keeps files with identical names from separate paths as distinct findings' {
        $firstPath = New-AuditTestDirectory -Name 'dedup-a'
        $secondPath = New-AuditTestDirectory -Name 'dedup-b'
        Set-Content -LiteralPath (Join-Path $firstPath 'setup.ps1') -Value 'Write-Output first'
        Set-Content -LiteralPath (Join-Path $secondPath 'setup.ps1') -Value 'Write-Output second'

        & $scriptPath -ScanPath $firstPath,$secondPath -OutputDirectory $outputDirectory `
            -StateDirectory $stateDirectory -AuditProfile Dedup -SkipHostInspection -MaxFiles 10 | Out-Null

        $report = Get-LatestAuditReport -OutputDirectory $outputDirectory
        @($report.Findings | Where-Object Item -eq 'setup.ps1').Count | Should Be 2
    }

    It 'classifies a document disguised as a PowerShell script as high risk' {
        $scanPath = New-AuditTestDirectory -Name 'double-extension'
        Set-Content -LiteralPath (Join-Path $scanPath 'invoice.pdf.ps1') -Value 'Write-Output suspicious'

        & $scriptPath -ScanPath $scanPath -OutputDirectory $outputDirectory `
            -StateDirectory $stateDirectory -AuditProfile Extension -SkipHostInspection -MaxFiles 10 | Out-Null

        $report = Get-LatestAuditReport -OutputDirectory $outputDirectory
        $finding = @($report.Findings | Where-Object Item -eq 'invoice.pdf.ps1')[0]
        $finding.Severity | Should Be 'High'
        $finding.Reason | Should Match 'deceptive double extension'
    }

    It 'does not replace a complete baseline after a scan is truncated' {
        $scanPath = New-AuditTestDirectory -Name 'truncated'
        Set-Content -LiteralPath (Join-Path $scanPath 'first.ps1') -Value 'Write-Output first'

        & $scriptPath -ScanPath $scanPath -OutputDirectory $outputDirectory `
            -StateDirectory $stateDirectory -AuditProfile Truncated -SkipHostInspection -MaxFiles 1 | Out-Null
        $snapshotFile = Get-ChildItem -LiteralPath $stateDirectory -Filter 'last-audit-*.json' | Select-Object -First 1
        $originalSnapshot = Get-Content -LiteralPath $snapshotFile.FullName -Raw

        Set-Content -LiteralPath (Join-Path $scanPath 'second.ps1') -Value 'Write-Output second'
        & $scriptPath -ScanPath $scanPath -OutputDirectory $outputDirectory `
            -StateDirectory $stateDirectory -AuditProfile Truncated -SkipHostInspection -MaxFiles 1 | Out-Null

        $report = Get-LatestAuditReport -OutputDirectory $outputDirectory
        $report.AuditComplete | Should Be $false
        (Get-Content -LiteralPath $snapshotFile.FullName -Raw) | Should Be $originalSnapshot
    }

    It 'stores separate baselines for distinct scan scopes under one profile' {
        $firstPath = New-AuditTestDirectory -Name 'scope-a'
        $secondPath = New-AuditTestDirectory -Name 'scope-b'
        Set-Content -LiteralPath (Join-Path $firstPath 'one.ps1') -Value 'Write-Output one'
        Set-Content -LiteralPath (Join-Path $secondPath 'two.ps1') -Value 'Write-Output two'

        & $scriptPath -ScanPath $firstPath -OutputDirectory $outputDirectory `
            -StateDirectory $stateDirectory -AuditProfile Scope -SkipHostInspection -MaxFiles 10 | Out-Null
        & $scriptPath -ScanPath $secondPath -OutputDirectory $outputDirectory `
            -StateDirectory $stateDirectory -AuditProfile Scope -SkipHostInspection -MaxFiles 10 | Out-Null

        @(Get-ChildItem -LiteralPath $stateDirectory -Filter 'last-audit-*.json').Count | Should Be 2
    }
}

Describe 'Invoke-SuspiciousFileAudit command inspection helpers' {
    BeforeAll {
        $functionScanPath = New-AuditTestDirectory -Name 'functions-scan'
        $functionOutput = New-AuditTestDirectory -Name 'functions-reports'
        $functionState = New-AuditTestDirectory -Name 'functions-state'
        . $scriptPath -ScanPath $functionScanPath -OutputDirectory $functionOutput `
            -StateDirectory $functionState -AuditProfile Functions -SkipFileScan -SkipHostInspection | Out-Null
    }

    It 'extracts the payload path from a PowerShell file launcher' {
        $payload = Join-Path $env:APPDATA 'Vendor\update.ps1'
        $command = 'powershell.exe -NoProfile -File "{0}"' -f $payload

        (Resolve-CommandPayloadPath -Command $command -LauncherPath 'powershell.exe') | Should Be $payload
    }

    It 'identifies AppData paths but does not confuse a similarly named downloads folder' {
        (Test-UserWritableOrTempPath -Path (Join-Path $env:APPDATA 'Vendor\agent.exe')) | Should Be $true
        (Test-UserWritableOrTempPath -Path (Join-Path $env:USERPROFILE 'Downloads-Archive\agent.exe')) | Should Be $false
    }
}
