#Requires -Version 5.1
Write-Host "=== Windows 10 / PowerShell 5.1 preflight ===" -ForegroundColor Cyan

Write-Host "`n[1] PowerShell version"
$PSVersionTable.PSVersion

Write-Host "`n[2] Process architecture"
[Environment]::Is64BitProcess
[Environment]::OSArchitecture

Write-Host "`n[3] Operating system"
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption,Version,BuildNumber,OSArchitecture

Write-Host "`n[4] Required cmdlets / commands"
"Get-WinEvent", "Get-LocalUser", "Get-LocalGroupMember", "Get-NetFirewallProfile", "Get-NetTCPConnection", "Get-NetIPConfiguration", "Get-DnsClientServerAddress", "Get-MpComputerStatus", "Get-BitLockerVolume", "auditpol.exe", "secedit.exe" |
    ForEach-Object {
        $cmd = Get-Command $_ -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Command = $_
            Available = ($null -ne $cmd)
            Source = if ($cmd) { $cmd.Source } else { "" }
        }
    } | Format-Table -AutoSize

Write-Host "`nInterpretation:"
Write-Host "- PowerShell should be 5.1.x."
Write-Host "- Process and OS should be 64-bit."
Write-Host "- Windows 10 22H2 is build 19045."
Write-Host "- Missing optional cmdlets are handled by the toolkit as INFO where practical."
