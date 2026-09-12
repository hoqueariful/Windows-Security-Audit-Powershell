# Firewall Audit

function New-ASREFirewallResult {
    param(
        [string]$Check,
        [string]$Status,
        [string]$Severity,
        [string]$Evidence,
        [string]$Recommendation,
        [string]$ControlRef
    )
    [pscustomobject]@{
        Check = $Check
        Status = $Status
        Severity = $Severity
        Evidence = $Evidence
        Recommendation = $Recommendation
        ControlRef = $ControlRef
    }
}

function Test-ASREFirewallProfiles {
    $p = Get-NetFirewallProfile -ErrorAction Stop
    $e = ($p | ForEach-Object { "$($_.Name):Enabled=$($_.Enabled);Inbound=$($_.DefaultInboundAction);Outbound=$($_.DefaultOutboundAction)" }) -join "; "
    $status = if (@($p | Where-Object { $_.Enabled -eq $false }).Count -eq 0) { "PASS" } else { "WARN" }
    New-ASREFirewallResult "Windows Firewall profiles" $status "High" $e "Keep active firewall profiles enabled and review default inbound policy." "ISO/IEC 27001:2022-aligned network security"
}

function Test-ASREPublicFirewallProfile {
    $p = Get-NetFirewallProfile -Name Public -ErrorAction Stop
    $status = if ($p.Enabled -and $p.DefaultInboundAction -eq "Block") { "PASS" } else { "WARN" }
    $e = "Enabled=$($p.Enabled); DefaultInbound=$($p.DefaultInboundAction); DefaultOutbound=$($p.DefaultOutboundAction)"
    New-ASREFirewallResult "Public firewall profile" $status "High" $e "For untrusted networks, maintain firewall protection and a restrictive inbound baseline." "ISO/IEC 27001:2022-aligned network security"
}

function Test-ASREInboundAllowRules {
    $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)
    New-ASREFirewallResult "Enabled inbound allow rules" "INFO" "Medium" "EnabledInboundAllowRuleCount=$($rules.Count)" "Review enabled inbound exceptions for business necessity and least privilege." "ISO/IEC 27001:2022-aligned network security"
}

function Test-ASRERemoteDesktopFirewallRules {
    $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayGroup -match "Remote Desktop" -and $_.Enabled -eq $true -and $_.Direction -eq "Inbound" })
    New-ASREFirewallResult "Enabled inbound Remote Desktop rules" "INFO" "Medium" "RuleCount=$($rules.Count)" "Confirm RDP exposure is required, restricted and monitored." "ISO/IEC 27001:2022-aligned remote access security"
}

function Test-ASRESmbFirewallRules {
    $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayGroup -match "File and Printer Sharing" -and $_.Enabled -eq $true -and $_.Direction -eq "Inbound" })
    New-ASREFirewallResult "Enabled inbound file-sharing rules" "INFO" "Medium" "RuleCount=$($rules.Count)" "Review SMB/file-sharing exposure and limit it to approved network profiles and business needs." "ISO/IEC 27001:2022-aligned network security"
}

Export-ModuleMember -Function "Test-ASREFirewallProfiles", "Test-ASREPublicFirewallProfile", "Test-ASREInboundAllowRules", "Test-ASRERemoteDesktopFirewallRules", "Test-ASRESmbFirewallRules"
