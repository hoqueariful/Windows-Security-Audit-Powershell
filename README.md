# Windows Security Audit PowerShell Module

**Al Shad Real Estate - fictional laboratory case study | 2-day project**

> A read-only Windows endpoint security audit toolkit built with native PowerShell 5.1. It collects security evidence, identifies configuration gaps, and produces reproducible audit outputs for security assurance workflows.


**50 security checks | 10 PowerShell modules | Windows 10 22H2 x64 | PowerShell 5.1**

**Covers:** RBAC and local accounts, Security Event Logs, Windows Firewall, network exposure, services, BitLocker, UAC, SMB, audit policy and evidence collection.

**Outputs:** CSV + JSON + HTML audit report.

**Approach:** evidence first, read-only collection, reproducible execution, ISO/IEC 27001:2022-aligned evidence themes. This is a laboratory demonstration, not an ISO certification or conformity assessment.

## Key findings from the assessed lab endpoint

The recorded assessment identified these areas for review:

- Built-in Administrator account enabled.
- Two members in the local Administrators group.
- Windows Firewall profiles reported disabled.
- System volume reported fully decrypted / BitLocker protection off.
- SMBv1 reported enabled.
- SMB client settings reported insecure guest logons enabled and signing not required.
- Multiple Windows audit subcategories reported as `No Auditing`.
- Endpoint protection checks had collection limitations in the audit session; these are reported as evidence limitations rather than fabricated security failures.

## Architecture

```text
Windows 10 endpoint
        |
        v
PowerShell 5.1 audit runner
        |
        +-- 10 modular audit components
        |     +-- System
        |     +-- Accounts
        |     +-- RBAC
        |     +-- Event Logs
        |     +-- Defender
        |     +-- Firewall
        |     +-- Network
        |     +-- Services
        |     +-- Hardening
        |     +-- Compliance evidence
        |
        v
50 audit functions
        |
        v
CSV / JSON / HTML
        |
        v
Evidence -> Finding -> Risk -> Recommendation
```

## Quick start

Run Windows PowerShell as Administrator.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Set-Location .
.\Scripts\00-Preflight.ps1
.\Scripts\01-ValidateProject.ps1
.\Scripts\Invoke-WindowsSecurityAudit.ps1
```

The validator must report:

```text
TOTAL EXPORTED AUDIT FUNCTIONS: 50 [OK]
```

Each audit run creates timestamped output under `Reports\<timestamp>\`.

## Evidence screenshots

The repository contains a compact evidence set from the Windows 10 laboratory run. Machine-specific identifiers have been redacted from the public copies.

| Evidence | File |
|---|---|
| Environment / preflight | `Screenshots/01-preflight.png` |
| 10 modules / 50 functions | `Screenshots/02-validation-50-functions.png` |
| Local users | `Screenshots/03-rbac-local-users.png` |
| Local Administrators | `Screenshots/04-rbac-administrators.png` |
| Security Event Log | `Screenshots/05-security-event-log.png` |
| Defender status | `Screenshots/06-defender-status.png` |
| Firewall profiles | `Screenshots/07-firewall-profiles.png` |
| Full audit execution | `Screenshots/08-audit-execution.png` |
| HTML audit output | `Screenshots/09-html-audit-report.png` |
| Findings / remediation view | `Screenshots/10-audit-findings.png` |

## Report

See `Docs/security-audit-report.pdf` for the recruiter-ready assessment summary, methodology, verified environment, key findings and remediation recommendations.

## Scope and limitations

- Fictional company and laboratory endpoint.
- Native Windows PowerShell and Windows security interfaces only.
- No destructive actions, exploitation or password changes.
- Some security interfaces are edition-dependent; unavailable telemetry is recorded as a collection limitation.
- ISO/IEC 27001:2022 references are evidence-mapping themes only; they do not establish organisational compliance.

## Project structure

```text
Modules/       10 modular audit components
Scripts/       Preflight, validator and audit runner
Docs/          Architecture, mapping, interview notes and report
Screenshots/   Recruiter-facing evidence
Reports/       Runtime output generated locally; not required in source control
Evidence/      Local evidence generated during execution
```

## CV entry

> **Windows Security Audit PowerShell Module | PowerShell, Windows Security, RBAC, Event Log Analysis, ISO/IEC 27001:2022-aligned Evidence Mapping**  
> **Al Shad Real Estate - Fictional Lab Case Study | 2-day project**  
> Developed and validated a modular 50-function, 10-module PowerShell toolkit to assess Windows endpoint security across privileged access, Security event logs, firewall configuration, network exposure, services, BitLocker and endpoint hardening. Generated reproducible CSV, JSON and HTML evidence outputs, analysed configuration and logging observations, and produced risk-based remediation recommendations aligned to ISO/IEC 27001:2022 security themes.
