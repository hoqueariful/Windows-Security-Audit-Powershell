# Network Audit

function New-ASRENetworkResult {
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

function Test-ASRENetworkProfiles {
    $p = @(Get-NetConnectionProfile -ErrorAction Stop)
    $e = ($p | ForEach-Object { "$($_.InterfaceAlias):Category=$($_.NetworkCategory); IPv4=$($_.IPv4Connectivity); IPv6=$($_.IPv6Connectivity)" }) -join "; "
    New-ASRENetworkResult "Network profile baseline" "INFO" "Medium" $e "Confirm network categorisation is appropriate for trusted and untrusted environments." "ISO/IEC 27001:2022-aligned network security"
}

function Test-ASREListeningTcpPorts {
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Sort-Object LocalPort)
    $unique = @($listeners | Select-Object -ExpandProperty LocalPort -Unique)
    $e = ($unique -join ", ")
    New-ASRENetworkResult "Listening TCP ports" "INFO" "High" "UniqueListeningPorts=$($unique.Count); Ports=$e" "Review listening services against the approved endpoint baseline and disable unnecessary exposure." "ISO/IEC 27001:2022-aligned network security"
}

function Test-ASREIPConfiguration {
    $cfg = @(Get-NetIPConfiguration -All -ErrorAction Stop)
    $e = ($cfg | ForEach-Object { "$($_.InterfaceAlias):IPv4=$($_.IPv4Address.IPAddress); Gateway=$($_.IPv4DefaultGateway.NextHop)" }) -join "; "
    New-ASRENetworkResult "IP configuration" "INFO" "Info" $e "Record network configuration as audit evidence and investigate unexpected interfaces or addresses." "ISO/IEC 27001:2022-aligned asset and network evidence"
}

function Test-ASREDnsServers {
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop)
    $e = ($dns | Where-Object { $_.ServerAddresses } | ForEach-Object { "$($_.InterfaceAlias):$([string]::Join(',', [string[]]$_.ServerAddresses))" }) -join "; " 
    New-ASRENetworkResult "Configured DNS servers" "INFO" "Medium" $e "Validate DNS server addresses against approved enterprise or trusted resolver configuration." "ISO/IEC 27001:2022-aligned network security"
}

function Test-ASRESmbClientConfiguration {
    $cmd = Get-Command Get-SmbClientConfiguration -ErrorAction SilentlyContinue
    if ($cmd) {
        $s = Get-SmbClientConfiguration -ErrorAction Stop
        $e = "EnableSecuritySignature=$($s.EnableSecuritySignature); RequireSecuritySignature=$($s.RequireSecuritySignature); EnableInsecureGuestLogons=$($s.EnableInsecureGuestLogons)"
        $status = if ($s.EnableSecuritySignature -and $s.RequireSecuritySignature -and (-not $s.EnableInsecureGuestLogons)) { "PASS" } else { "WARN" }
        New-ASRENetworkResult "SMB client security configuration" $status "High" $e "Prefer SMB signing and avoid insecure guest logons where compatible with the environment." "ISO/IEC 27001:2022-aligned network security"
    } else {
        New-ASRENetworkResult "SMB client security configuration" "INFO" "Info" "Get-SmbClientConfiguration is not available on this endpoint." "Document unsupported SMB controls and assess them through available operating-system policy evidence." "ISO/IEC 27001:2022-aligned network security"
    }
}

Export-ModuleMember -Function "Test-ASRENetworkProfiles", "Test-ASREListeningTcpPorts", "Test-ASREIPConfiguration", "Test-ASREDnsServers", "Test-ASRESmbClientConfiguration"
