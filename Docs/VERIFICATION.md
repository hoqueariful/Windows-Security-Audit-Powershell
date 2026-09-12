# Project verification

{
  "module_files": 10,
  "exported_test_functions": 50,
  "functions_per_module": {
    "01-SystemAudit.psm1": 5,
    "02-AccountAudit.psm1": 5,
    "03-RBACAudit.psm1": 5,
    "04-EventLogAudit.psm1": 5,
    "05-DefenderAudit.psm1": 5,
    "06-FirewallAudit.psm1": 5,
    "07-NetworkAudit.psm1": 5,
    "08-ServicesAudit.psm1": 5,
    "09-HardeningAudit.psm1": 5,
    "10-ComplianceEvidence.psm1": 5
  },
  "static_brace_balance_all_zero": true,
  "target_os": "Windows 10 22H2 x64",
  "target_powershell": "Windows PowerShell 5.1",
  "execution_note": "Windows PowerShell runtime execution must be performed on the target Windows machine; this environment does not include powershell.exe/pwsh."
}