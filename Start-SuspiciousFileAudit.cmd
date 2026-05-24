@echo off
setlocal
title Suspicious File Audit
echo Starting a read-only security audit. This may take several minutes.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-SuspiciousFileAudit.ps1" -VerifyFindingsWithKaspersky
echo.
echo Press any key to close this window.
pause >nul
