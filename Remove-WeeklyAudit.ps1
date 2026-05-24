[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$taskName = 'Suspicious File Audit Weekly'
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -eq $task) {
    Write-Host 'Weekly audit is not installed.'
    return
}

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
Write-Host 'Weekly audit removed.'
