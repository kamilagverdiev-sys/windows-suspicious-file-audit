[CmdletBinding()]
param(
    [Parameter()]
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

$script:ScannerPath = Join-Path $PSScriptRoot 'Invoke-SuspiciousFileAudit.ps1'
$script:ReportsDirectory = Join-Path $PSScriptRoot 'reports'
$script:RunningProcess = $null
$script:LastHtmlReport = ''

function New-UiFont {
    param(
        [float]$Size,
        [System.Drawing.FontStyle]$Style = [System.Drawing.FontStyle]::Regular
    )

    return New-Object System.Drawing.Font('Segoe UI', $Size, $Style)
}

function Get-UiColor {
    param([string]$Value)

    return [System.Drawing.ColorTranslator]::FromHtml($Value)
}

function New-SummaryCard {
    param(
        [string]$Title,
        [string]$Color,
        [int]$Left
    )

    $panel = New-Object System.Windows.Forms.Panel
    $panel.Location = New-Object System.Drawing.Point($Left, 152)
    $panel.Size = New-Object System.Drawing.Size(138, 70)
    $panel.BackColor = [System.Drawing.Color]::White
    $panel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Title
    $label.Font = New-UiFont -Size 9
    $label.ForeColor = Get-UiColor '#667085'
    $label.Location = New-Object System.Drawing.Point(12, 10)
    $label.AutoSize = $true

    $value = New-Object System.Windows.Forms.Label
    $value.Text = '-'
    $value.Font = New-UiFont -Size 20 -Style Bold
    $value.ForeColor = Get-UiColor $Color
    $value.Location = New-Object System.Drawing.Point(10, 30)
    $value.AutoSize = $true

    $panel.Controls.Add($label)
    $panel.Controls.Add($value)

    return [pscustomobject]@{
        Panel = $panel
        Value = $value
    }
}

function Get-LatestReportFile {
    if (-not (Test-Path -LiteralPath $script:ReportsDirectory)) {
        return $null
    }

    return Get-ChildItem -LiteralPath $script:ReportsDirectory -Filter 'report-*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

function Set-Status {
    param(
        [string]$Text,
        [string]$Color = '#667085'
    )

    $statusLabel.Text = $Text
    $statusLabel.ForeColor = Get-UiColor $Color
}

function Load-Report {
    param([System.IO.FileInfo]$ReportFile)

    if ($null -eq $ReportFile) {
        Set-Status -Text 'No reports yet. Start the first audit.'
        return
    }

    try {
        $summary = Get-Content -LiteralPath $ReportFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $highCard.Value.Text = [string]$summary.HighCount
        $mediumCard.Value.Text = [string]$summary.MediumCount
        $lowCard.Value.Text = [string]([int]$summary.LowCount + [int]$summary.Informational)
        $filesCard.Value.Text = [string]$summary.FilesChecked

        $complete = $true
        if ($summary.PSObject.Properties.Name -contains 'AuditComplete') {
            $complete = [bool]$summary.AuditComplete
        }

        $profileText = [string]$summary.AuditProfile
        $finishedText = [string]$summary.Finished
        $completionText = if ($complete) { 'complete' } else { 'incomplete' }
        $lastRunLabel.Text = 'Last audit: {0} | {1} | {2}' -f $profileText, $finishedText, $completionText

        $findingsGrid.Rows.Clear()
        foreach ($finding in @($summary.Findings)) {
            [void]$findingsGrid.Rows.Add(
                [string]$finding.Severity,
                [string]$finding.Category,
                [string]$finding.Item,
                [string]$finding.Reason,
                [string]$finding.Path
            )
        }

        $script:LastHtmlReport = [IO.Path]::ChangeExtension($ReportFile.FullName, '.html')
        $openReportButton.Enabled = Test-Path -LiteralPath $script:LastHtmlReport
        if ($complete) {
            Set-Status -Text ('Showing report: {0}' -f $ReportFile.Name) -Color '#027a48'
        }
        else {
            Set-Status -Text 'Last audit was incomplete: baseline was not updated.' -Color '#b54708'
        }
    }
    catch {
        Set-Status -Text ('Unable to read the report: {0}' -f $_.Exception.Message) -Color '#b42318'
    }
}

function Set-ScanControlsEnabled {
    param([bool]$Enabled)

    $startButton.Enabled = $Enabled
    $modeBox.Enabled = $Enabled
    $kasperskyCheckBox.Enabled = $Enabled
    $recentDaysControl.Enabled = $Enabled
}

function Start-Audit {
    if ($null -ne $script:RunningProcess -and -not $script:RunningProcess.HasExited) {
        return
    }

    $profile = if ($modeBox.SelectedIndex -eq 1) { 'Deep' } else { 'Quick' }
    $arguments = New-Object System.Collections.Generic.List[string]
    $arguments.Add('-NoProfile')
    $arguments.Add('-ExecutionPolicy')
    $arguments.Add('Bypass')
    $arguments.Add('-File')
    $arguments.Add(('"{0}"' -f $script:ScannerPath))
    $arguments.Add('-AuditProfile')
    $arguments.Add($profile)
    $arguments.Add('-RecentDays')
    $arguments.Add([string][int]$recentDaysControl.Value)
    if ($profile -eq 'Deep') {
        $arguments.Add('-IncludeLargeUserFolders')
        $arguments.Add('-MaxFiles')
        $arguments.Add('100000')
    }
    if ($kasperskyCheckBox.Checked) {
        $arguments.Add('-VerifyFindingsWithKaspersky')
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = 'powershell.exe'
    $startInfo.Arguments = ($arguments -join ' ')
    $startInfo.WorkingDirectory = $PSScriptRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    try {
        $script:RunningProcess = [System.Diagnostics.Process]::Start($startInfo)
        Set-ScanControlsEnabled -Enabled $false
        $progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
        $progressBar.Visible = $true
        Set-Status -Text ('{0} audit is running. Please wait...' -f $profile) -Color '#175cd3'
        $pollTimer.Start()
    }
    catch {
        Set-Status -Text ('Unable to start audit: {0}' -f $_.Exception.Message) -Color '#b42318'
    }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Windows Suspicious File Audit'
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.Size = New-Object System.Drawing.Size(1040, 680)
$form.MinimumSize = New-Object System.Drawing.Size(900, 600)
$form.BackColor = Get-UiColor '#f5f7fb'
$form.Font = New-UiFont -Size 9

$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$headerPanel.Height = 82
$headerPanel.BackColor = Get-UiColor '#101828'
$form.Controls.Add($headerPanel)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = 'Windows Suspicious File Audit'
$titleLabel.Font = New-UiFont -Size 18 -Style Bold
$titleLabel.ForeColor = [System.Drawing.Color]::White
$titleLabel.Location = New-Object System.Drawing.Point(24, 14)
$titleLabel.AutoSize = $true
$headerPanel.Controls.Add($titleLabel)

$subtitleLabel = New-Object System.Windows.Forms.Label
$subtitleLabel.Text = 'Read-only triage: detection and reports without deleting files'
$subtitleLabel.Font = New-UiFont -Size 9
$subtitleLabel.ForeColor = Get-UiColor '#d0d5dd'
$subtitleLabel.Location = New-Object System.Drawing.Point(27, 48)
$subtitleLabel.AutoSize = $true
$headerPanel.Controls.Add($subtitleLabel)

$controlsPanel = New-Object System.Windows.Forms.Panel
$controlsPanel.Location = New-Object System.Drawing.Point(24, 96)
$controlsPanel.Size = New-Object System.Drawing.Size(982, 44)
$controlsPanel.Anchor = 'Top, Left, Right'
$form.Controls.Add($controlsPanel)

$modeLabel = New-Object System.Windows.Forms.Label
$modeLabel.Text = 'Mode'
$modeLabel.Location = New-Object System.Drawing.Point(0, 13)
$modeLabel.AutoSize = $true
$controlsPanel.Controls.Add($modeLabel)

$modeBox = New-Object System.Windows.Forms.ComboBox
$modeBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$modeBox.Location = New-Object System.Drawing.Point(54, 9)
$modeBox.Size = New-Object System.Drawing.Size(132, 25)
[void]$modeBox.Items.Add('Quick')
[void]$modeBox.Items.Add('Deep')
$modeBox.SelectedIndex = 0
$controlsPanel.Controls.Add($modeBox)

$daysLabel = New-Object System.Windows.Forms.Label
$daysLabel.Text = 'Recent days'
$daysLabel.Location = New-Object System.Drawing.Point(208, 13)
$daysLabel.AutoSize = $true
$controlsPanel.Controls.Add($daysLabel)

$recentDaysControl = New-Object System.Windows.Forms.NumericUpDown
$recentDaysControl.Minimum = 1
$recentDaysControl.Maximum = 3650
$recentDaysControl.Value = 45
$recentDaysControl.Location = New-Object System.Drawing.Point(302, 9)
$recentDaysControl.Size = New-Object System.Drawing.Size(72, 25)
$controlsPanel.Controls.Add($recentDaysControl)

$kasperskyCheckBox = New-Object System.Windows.Forms.CheckBox
$kasperskyCheckBox.Text = 'Validate findings with Kaspersky'
$kasperskyCheckBox.Checked = $true
$kasperskyCheckBox.Location = New-Object System.Drawing.Point(401, 11)
$kasperskyCheckBox.Size = New-Object System.Drawing.Size(218, 24)
$controlsPanel.Controls.Add($kasperskyCheckBox)

$startButton = New-Object System.Windows.Forms.Button
$startButton.Text = 'Start audit'
$startButton.Location = New-Object System.Drawing.Point(632, 6)
$startButton.Size = New-Object System.Drawing.Size(138, 32)
$startButton.BackColor = Get-UiColor '#175cd3'
$startButton.ForeColor = [System.Drawing.Color]::White
$startButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$startButton.Add_Click({ Start-Audit })
$controlsPanel.Controls.Add($startButton)

$openReportButton = New-Object System.Windows.Forms.Button
$openReportButton.Text = 'Open HTML'
$openReportButton.Location = New-Object System.Drawing.Point(778, 6)
$openReportButton.Size = New-Object System.Drawing.Size(116, 32)
$openReportButton.Enabled = $false
$openReportButton.Add_Click({
        if (Test-Path -LiteralPath $script:LastHtmlReport) {
            Start-Process -FilePath $script:LastHtmlReport
        }
    })
$controlsPanel.Controls.Add($openReportButton)

$openFolderButton = New-Object System.Windows.Forms.Button
$openFolderButton.Text = 'Folder'
$openFolderButton.Location = New-Object System.Drawing.Point(902, 6)
$openFolderButton.Size = New-Object System.Drawing.Size(72, 32)
$openFolderButton.Add_Click({
        if (-not (Test-Path -LiteralPath $script:ReportsDirectory)) {
            New-Item -LiteralPath $script:ReportsDirectory -ItemType Directory -Force | Out-Null
        }
        Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $script:ReportsDirectory)
    })
$controlsPanel.Controls.Add($openFolderButton)

$highCard = New-SummaryCard -Title 'High' -Color '#b42318' -Left 24
$mediumCard = New-SummaryCard -Title 'Medium' -Color '#b54708' -Left 174
$lowCard = New-SummaryCard -Title 'Low / Info' -Color '#175cd3' -Left 324
$filesCard = New-SummaryCard -Title 'Files scanned' -Color '#101828' -Left 474
$form.Controls.Add($highCard.Panel)
$form.Controls.Add($mediumCard.Panel)
$form.Controls.Add($lowCard.Panel)
$form.Controls.Add($filesCard.Panel)

$lastRunLabel = New-Object System.Windows.Forms.Label
$lastRunLabel.Text = 'Last audit: no data'
$lastRunLabel.Location = New-Object System.Drawing.Point(630, 172)
$lastRunLabel.Size = New-Object System.Drawing.Size(365, 42)
$lastRunLabel.ForeColor = Get-UiColor '#475467'
$form.Controls.Add($lastRunLabel)

$gridTitle = New-Object System.Windows.Forms.Label
$gridTitle.Text = 'Latest findings'
$gridTitle.Font = New-UiFont -Size 11 -Style Bold
$gridTitle.Location = New-Object System.Drawing.Point(24, 240)
$gridTitle.AutoSize = $true
$form.Controls.Add($gridTitle)

$findingsGrid = New-Object System.Windows.Forms.DataGridView
$findingsGrid.Location = New-Object System.Drawing.Point(24, 270)
$findingsGrid.Size = New-Object System.Drawing.Size(982, 300)
$findingsGrid.Anchor = 'Top, Bottom, Left, Right'
$findingsGrid.AllowUserToAddRows = $false
$findingsGrid.AllowUserToDeleteRows = $false
$findingsGrid.AllowUserToResizeRows = $false
$findingsGrid.ReadOnly = $true
$findingsGrid.RowHeadersVisible = $false
$findingsGrid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$findingsGrid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
$findingsGrid.BackgroundColor = [System.Drawing.Color]::White
[void]$findingsGrid.Columns.Add('Severity', 'Severity')
[void]$findingsGrid.Columns.Add('Category', 'Category')
[void]$findingsGrid.Columns.Add('Item', 'Item')
[void]$findingsGrid.Columns.Add('Reason', 'Reason')
[void]$findingsGrid.Columns.Add('Path', 'Path')
$findingsGrid.Columns[0].FillWeight = 45
$findingsGrid.Columns[1].FillWeight = 80
$findingsGrid.Columns[2].FillWeight = 100
$findingsGrid.Columns[3].FillWeight = 190
$findingsGrid.Columns[4].FillWeight = 185
$form.Controls.Add($findingsGrid)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = 'Ready to start.'
$statusLabel.Location = New-Object System.Drawing.Point(24, 588)
$statusLabel.Size = New-Object System.Drawing.Size(740, 28)
$statusLabel.Anchor = 'Bottom, Left, Right'
$statusLabel.ForeColor = Get-UiColor '#667085'
$form.Controls.Add($statusLabel)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(782, 590)
$progressBar.Size = New-Object System.Drawing.Size(224, 18)
$progressBar.Anchor = 'Bottom, Right'
$progressBar.Visible = $false
$form.Controls.Add($progressBar)

$pollTimer = New-Object System.Windows.Forms.Timer
$pollTimer.Interval = 650
$pollTimer.Add_Tick({
        if ($null -eq $script:RunningProcess -or -not $script:RunningProcess.HasExited) {
            return
        }

        $exitCode = $script:RunningProcess.ExitCode
        $pollTimer.Stop()
        $progressBar.Visible = $false
        Set-ScanControlsEnabled -Enabled $true
        if ($exitCode -eq 0) {
            Load-Report -ReportFile (Get-LatestReportFile)
        }
        else {
            Set-Status -Text ('Audit failed with exit code {0}.' -f $exitCode) -Color '#b42318'
        }
        $script:RunningProcess.Dispose()
        $script:RunningProcess = $null
    })

$form.Add_FormClosing({
        if ($null -ne $script:RunningProcess -and -not $script:RunningProcess.HasExited) {
            $choice = [System.Windows.Forms.MessageBox]::Show(
                'An audit is still running. Close the window? The audit process will continue in the background.',
                'Audit is running',
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($choice -ne [System.Windows.Forms.DialogResult]::Yes) {
                $_.Cancel = $true
            }
        }
    })

Load-Report -ReportFile (Get-LatestReportFile)

if ($ValidateOnly) {
    $form.Dispose()
    Write-Output 'UI initialized successfully.'
    return
}

[void]$form.ShowDialog()
