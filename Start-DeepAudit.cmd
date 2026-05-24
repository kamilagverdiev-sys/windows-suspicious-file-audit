@echo off
setlocal
title Suspicious File Audit - Deep Scan
echo Starting a deep read-only security audit. This may take a long time.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-SuspiciousFileAudit.ps1" -AuditProfile Deep -IncludeLargeUserFolders -MaxFiles 100000 -VerifyFindingsWithKaspersky
echo.
echo Press any key to close this window.
pause >nul
