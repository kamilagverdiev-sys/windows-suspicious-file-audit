# Changelog

## 0.3.0 - 2026-05-24

- Fixed finding deduplication so identically named files in separate locations are reported independently.
- Prevented incomplete or differently scoped audits from producing misleading resolved history.
- Added coverage for `AppData`/`LocalAppData` launches and payload extraction from common Windows launchers.
- Classified disguised PowerShell/script double extensions as high-risk findings.
- Added Pester tests, public documentation, a security policy, an MIT license, and Windows CI.

## 0.2.0 - 2026-05-24

- Added HTML reports and optional Kaspersky validation for flagged files.
- Added service and WMI persistence inspection.
- Added per-profile history comparison for new and resolved findings.
- Added quick, deep, and installable weekly audit entry points.

## 0.1.0 - 2026-05-24

- Created the initial read-only suspicious file audit script.
- Added checks for autoruns, scheduled tasks, running processes, and risky files.
