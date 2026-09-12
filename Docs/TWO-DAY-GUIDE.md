# Two-Day Execution Guide — Windows Security Audit PowerShell

## Fixed lab baseline

- Operating system: Windows 10 22H2 x64
- PowerShell: Windows PowerShell 5.1
- Hostname: your real lab hostname
- User: Administrator in the lab
- Organisation: Al Shad Real Estate (fictional)
- Project duration: 2 days
- Audit style: read-only collection; no exploitation and no security-setting changes

## Day 1

### Step 1 — Start an elevated Windows PowerShell 5.1 session

Run:

    $PSVersionTable.PSVersion
    [Environment]::Is64BitProcess
    [Environment]::OSArchitecture
    Get-CimInstance Win32_OperatingSystem | Select Caption,Version,BuildNumber,OSArchitecture

Expected baseline:
- PowerShell 5.1.x
- True for 64-bit process
- 64-bit OS
- Windows 10, build 19045 for 22H2

Take Screenshot 01.

### Step 2 — Go to the project

    Set-Location "C:\Users\Administrator\Desktop\windows-security-audit-powershell-v2"

Take Screenshot 02 showing the folders.

### Step 3 — Check execution policy for this session

Do not permanently weaken Windows policy. Use:

    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

Verify:

    Get-ExecutionPolicy -List

Take Screenshot 03.

### Step 4 — Run the preflight

    .\Scripts\00-Preflight.ps1

The preflight shows whether required Windows commands are available.

Take Screenshot 04.

### Step 5 — Run the project validator

    Get-ChildItem .\Modules\*.psm1 | Sort-Object Name | ForEach-Object {
        Import-Module $_.FullName -Force
    }

Then:

    (Get-Command -Name "Test-ASRE*" -CommandType Function).Count

Expected:

    50

Do not type 50 yourself. The command must calculate it.

Take Screenshot 05.

### Step 6 — Inspect actual RBAC evidence

    Get-LocalUser

    Get-LocalGroupMember -Group "Administrators"

Take Screenshot 06.

### Step 7 — Inspect actual Security event evidence

    Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624,4625} -MaxEvents 20 |
        Select TimeCreated,Id,ProviderName

Take Screenshot 07.

### Step 8 — Inspect Defender

    Get-MpComputerStatus |
        Select AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated

Take Screenshot 08.

### Step 9 — Inspect firewall

    Get-NetFirewallProfile |
        Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction

Take Screenshot 09.

## Day 2

### Step 10 — Execute the complete audit

    .\Scripts\Invoke-WindowsSecurityAudit.ps1

The script itself verifies that exactly 50 `Test-ASRE*` functions are exported before it begins.

Take Screenshot 10 showing:
- "Verified exported audit functions: 50"
- execution of the checks
- "AUDIT COMPLETE"

### Step 11 — Inspect the generated report

    Get-ChildItem .\Reports -Recurse | Select FullName,Length

Open the newest:

    .\Reports\<timestamp>\audit-report.html

Take Screenshot 11 of the report.

### Step 12 — Inspect the CSV

    Import-Csv .\Reports\<timestamp>\audit-results.csv |
        Group-Object Status |
        Select Name,Count

Take a screenshot of the real PASS/WARN/FAIL/INFO distribution.

### Step 13 — Select findings

Choose only findings supported by the actual evidence.

Recommended finding structure:
- ID
- Observation
- Evidence
- Risk
- Recommendation
- Owner
- Priority

Never invent numbers, event counts, vulnerabilities, users or compliance status.

## What goes on GitHub

Upload:
- Modules
- Scripts
- Docs
- README
- Screenshots

Do not upload:
- passwords
- tokens
- real customer data
- sensitive Windows security policy artefacts from a real organisation
- entire raw Security event logs

For this personal lab, redact usernames or machine details if you prefer.
