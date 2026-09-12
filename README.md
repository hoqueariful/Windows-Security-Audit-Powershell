# Windows Security Audit PowerShell Module

**Al Shad Real Estate | Client Security Assessment | 2-day project**

> A read-only Windows endpoint security assessment toolkit built with native PowerShell 5.1. The project automates evidence collection, configuration review, security control checks and risk-based reporting for a small-business Windows environment.

## Recruiter view

**50 security checks | 10 PowerShell modules | Windows 10 22H2 x64 | PowerShell 5.1**

**Core areas:** RBAC and local accounts, Security Event Logs, Windows Firewall, network exposure, services, BitLocker, UAC, SMB, Windows audit policy and evidence collection.

**Reporting:** CSV + JSON + HTML audit outputs, supported by a professional assessment report.

**Method:** evidence-first assessment, read-only collection, repeatable execution and ISO/IEC 27001:2022-aligned evidence mapping.

## Assessment outcome

The assessment identified configuration and assurance areas requiring review, including:

- Built-in Administrator account enabled.
- Two members in the local Administrators group.
- Windows Firewall profiles reported disabled.
- System volume reported fully decrypted with BitLocker protection off.
- SMBv1 reported enabled.
- SMB client settings reported insecure guest logons enabled and signing not required.
- Multiple Windows audit subcategories reported as `No Auditing`.
- Endpoint-protection checks included session-specific collection limitations, which are recorded separately from confirmed security findings.

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

The validator should report:

```text
TOTAL EXPORTED AUDIT FUNCTIONS: 50 [OK]
```

Each assessment execution creates timestamped output under `Reports\\<timestamp>\\`.

## Evidence screenshots

The repository contains a focused evidence set showing environment validation, framework verification, access review, Windows Security event collection, endpoint controls, audit execution and the resulting findings.

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

## Assessment report

See `Docs/security-audit-report.pdf` for the assessment summary, objectives, scope, methodology, verification evidence, findings, remediation recommendations and reporting outputs.

## Scope and methodology

- Assessment scope: one Windows 10 endpoint within the client environment.
- Native Windows PowerShell 5.1 and Windows security interfaces were used.
- Assessment actions were read-only; no exploitation, password changes or destructive configuration changes were performed.
- Security observations are based on collected endpoint evidence from the assessment run.
- ISO/IEC 27001:2022 references are used for control and evidence mapping; this project does not represent an ISO certification or formal organisational conformity assessment.

## Reporting outputs

```text
Reports/
    audit_report.csv
    audit_report.json
    summary.json
    manifest.json
    audit_report.html
```

The repository separates source code, generated assessment output and supporting evidence so the project remains reproducible and easy to review.

## Project structure

```text
Modules/       10 modular audit components
Scripts/       Preflight, validator and audit runner
Docs/          Architecture, control mapping, interview notes and report
Screenshots/   Recruiter-facing evidence
Reports/       Generated assessment outputs
Evidence/      Supporting audit evidence
```

## Professional use

This project demonstrates practical Windows security assessment capability across endpoint configuration review, privileged access assessment, event-log analysis, security-control verification, evidence handling and risk-based reporting.
