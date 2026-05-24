[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')]
    [string]$DayOfWeek = 'Sunday',

    [Parameter()]
    [datetime]$At = [datetime]::Today.AddHours(12),

    [Parameter()]
    [switch]$Deep
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$taskName = 'Suspicious File Audit Weekly'
$scannerPath = Join-Path $PSScriptRoot 'Invoke-SuspiciousFileAudit.ps1'
$arguments = @(
    '-NoProfile',
    '-ExecutionPolicy Bypass',
    ('-File "{0}"' -f $scannerPath),
    '-AuditProfile Weekly',
    '-VerifyFindingsWithKaspersky'
)
if ($Deep) {
    $arguments += '-IncludeLargeUserFolders'
    $arguments += '-MaxFiles 100000'
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($arguments -join ' ')
$trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $DayOfWeek -At $At
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host ('Weekly audit installed: {0} at {1:HH:mm}.' -f $DayOfWeek, $At)
Write-Host ('Mode: {0}' -f $(if ($Deep) { 'Deep' } else { 'Quick' }))
Write-Host 'Use Remove-WeeklyAudit.ps1 to remove this scheduled audit.'
