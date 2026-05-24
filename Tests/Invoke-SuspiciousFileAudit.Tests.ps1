Describe 'Invoke-SuspiciousFileAudit file findings' {
    BeforeAll {
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
    }

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
        if (@($report.Findings | Where-Object Item -eq 'setup.ps1').Count -ne 2) {
            throw 'Expected two separate setup.ps1 findings.'
        }
    }

    It 'classifies a document disguised as a PowerShell script as high risk' {
        $scanPath = New-AuditTestDirectory -Name 'double-extension'
        Set-Content -LiteralPath (Join-Path $scanPath 'invoice.pdf.ps1') -Value 'Write-Output suspicious'

        & $scriptPath -ScanPath $scanPath -OutputDirectory $outputDirectory `
            -StateDirectory $stateDirectory -AuditProfile Extension -SkipHostInspection -MaxFiles 10 | Out-Null

        $report = Get-LatestAuditReport -OutputDirectory $outputDirectory
        $finding = @($report.Findings | Where-Object Item -eq 'invoice.pdf.ps1')[0]
        if ($finding.Severity -ne 'High' -or $finding.Reason -notmatch 'deceptive double extension') {
            throw 'Expected disguised PowerShell script to be a high-risk double-extension finding.'
        }
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
        if ($report.AuditComplete) {
            throw 'Expected the truncated scan to be incomplete.'
        }
        if ((Get-Content -LiteralPath $snapshotFile.FullName -Raw) -ne $originalSnapshot) {
            throw 'An incomplete scan replaced the complete baseline.'
        }
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

        if (@(Get-ChildItem -LiteralPath $stateDirectory -Filter 'last-audit-*.json').Count -ne 2) {
            throw 'Expected distinct scan scopes to receive separate baselines.'
        }
    }
}

Describe 'Invoke-SuspiciousFileAudit command inspection helpers' {
    BeforeAll {
        $scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-SuspiciousFileAudit.ps1'

        function New-AuditHelperTestDirectory {
            param([string]$Name)

            $path = Join-Path $TestDrive $Name
            New-Item -Path $path -ItemType Directory -Force | Out-Null
            return $path
        }

        $functionScanPath = New-AuditHelperTestDirectory -Name 'functions-scan'
        $functionOutput = New-AuditHelperTestDirectory -Name 'functions-reports'
        $functionState = New-AuditHelperTestDirectory -Name 'functions-state'
        . $scriptPath -ScanPath $functionScanPath -OutputDirectory $functionOutput `
            -StateDirectory $functionState -AuditProfile Functions -SkipFileScan -SkipHostInspection | Out-Null
    }

    BeforeEach {
        $script:Findings.Clear()
        $script:SeenFindings = @{}
    }

    It 'extracts the payload path from a PowerShell file launcher' {
        $payload = Join-Path $env:APPDATA 'Vendor\update.ps1'
        $command = 'powershell.exe -NoProfile -File "{0}"' -f $payload

        if ((Resolve-CommandPayloadPath -Command $command -LauncherPath 'powershell.exe') -ne $payload) {
            throw 'Expected PowerShell -File payload path to be extracted.'
        }
    }

    It 'identifies AppData paths but does not confuse a similarly named downloads folder' {
        if (-not (Test-UserWritableOrTempPath -Path (Join-Path $env:APPDATA 'Vendor\agent.exe'))) {
            throw 'Expected an AppData executable to be user-writable.'
        }
        if (Test-UserWritableOrTempPath -Path (Join-Path $env:USERPROFILE 'Downloads-Archive\agent.exe')) {
            throw 'A similarly named folder must not match the Downloads root.'
        }
    }

    It 'reports a cmd task that launches a script from AppData' {
        $payload = Join-Path $env:APPDATA 'Vendor\evil.cmd'
        $command = 'cmd.exe /c "{0}"' -f $payload

        Inspect-ScheduledTaskCommand -Name '\Review Cmd Payload' -Command $command

        if ($script:Findings.Count -ne 1 -or $script:Findings[0].Path -ne (Get-NormalizedPath -Path $payload)) {
            throw 'Expected cmd.exe /c payload under AppData to create a finding for the payload path.'
        }
    }

    It 'records the expected project weekly task as information' {
        $command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{0}" -AuditProfile Weekly -VerifyFindingsWithKaspersky' -f $scriptPath

        Inspect-ScheduledTaskCommand -Name '\Suspicious File Audit Weekly' -Command $command

        if ($script:Findings.Count -ne 1 -or $script:Findings[0].Severity -ne 'Info') {
            throw 'Expected the unmodified weekly task to be recorded as informational.'
        }
    }

    It 'flags an altered project weekly task as high risk' {
        $command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{0}" -AuditProfile Weekly -VerifyFindingsWithKaspersky -OutputDirectory "\\server\share"' -f $scriptPath

        Inspect-ScheduledTaskCommand -Name '\Suspicious File Audit Weekly' -Command $command

        if ($script:Findings.Count -ne 1 -or $script:Findings[0].Severity -ne 'High') {
            throw 'Expected altered weekly task arguments to be reported as high risk.'
        }
    }

    It 'flags an encoded PowerShell process command even when the executable is in a system path' {
        $executablePath = Join-Path $PSHOME 'powershell.exe'
        $process = [pscustomobject]@{
            Name           = 'powershell.exe'
            ExecutablePath = $executablePath
            CommandLine    = '"{0}" -NoProfile -EncodedCommand SQBFAFgA' -f $executablePath
        }

        Inspect-ProcessRecord -Process $process

        if (@($script:Findings | Where-Object { $_.Category -eq 'Running Process Command' -and $_.Severity -eq 'High' }).Count -ne 1) {
            throw 'Expected encoded PowerShell process command to be reported as high risk.'
        }
    }

    It 'does not flag an ordinary application merely because its arguments contain a URL' {
        $process = [pscustomobject]@{
            Name           = 'browser.exe'
            ExecutablePath = 'C:\Program Files\Browser\browser.exe'
            CommandLine    = '"C:\Program Files\Browser\browser.exe" --url https://example.test/update'
        }

        Inspect-ProcessRecord -Process $process

        if ($script:Findings.Count -ne 0) {
            throw 'Expected ordinary application URL arguments to remain unreported.'
        }
    }
}
