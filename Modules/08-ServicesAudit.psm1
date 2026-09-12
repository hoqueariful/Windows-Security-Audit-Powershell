# Services Audit

function New-ASREServicesResult {
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

function Test-ASRECriticalServices {
    $names = "EventLog","WinDefend","wuauserv","W32Time"
    $rows = foreach ($n in $names) {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($s) { "$n=Status:$($s.Status);Start:$($s.StartType)" } else { "$n=NotPresent" }
    }
    New-ASREServicesResult "Critical Windows services" "INFO" "Medium" ($rows -join "; ") "Confirm security-relevant services are running and appropriately configured." "ISO/IEC 27001:2022-aligned operational controls"
}

function Test-ASREAutomaticRunningServices {
    $s = @(Get-CimInstance Win32_Service -Filter 'StartMode = "Auto" AND State = "Running"' -ErrorAction Stop)
    New-ASREServicesResult "Automatic running services" "INFO" "Medium" "Count=$($s.Count)" "Review the automatic service inventory for unnecessary or unexpected services." "ISO/IEC 27001:2022-aligned configuration management"
}

function Test-ASREUnquotedServicePaths {
    $s = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.PathName -and $_.PathName -notmatch '^\s*"' -and $_.PathName -match '"' })
    $candidates = @($s | Where-Object { $_.PathName -match '\s' -and $_.PathName -notmatch '^\s*"' })
    $e = ($candidates | Select-Object -First 10 | ForEach-Object { "$($_.Name):$($_.PathName)" }) -join "; "
    $status = if ($candidates.Count -eq 0) { "PASS" } else { "WARN" }
    New-ASREServicesResult "Potential unquoted service paths" $status "Medium" "CandidateCount=$($candidates.Count); $e" "Review flagged service executable paths and quote paths containing spaces where required by the actual executable structure." "ISO/IEC 27001:2022-aligned secure configuration"
}

function Test-ASREWinRMService {
    $s = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($s) {
        $status = if ($s.Status -eq "Running") { "WARN" } else { "PASS" }
        New-ASREServicesResult "Windows Remote Management service" $status "Medium" "Present=True; Status=$($s.Status);StartType=$($s.StartType)" "Restrict remote administration services to approved administrative workflows and network paths." "ISO/IEC 27001:2022-aligned remote administration"
    } else {
        New-ASREServicesResult "Windows Remote Management service" "INFO" "Info" "WinRM service not present." "Document remote-management tooling used by the endpoint." "ISO/IEC 27001:2022-aligned remote administration"
    }
}

function Test-ASRERemoteRegistryService {
    $s = Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue
    if ($s) {
        $status = if ($s.Status -eq "Running") { "WARN" } else { "PASS" }
        New-ASREServicesResult "Remote Registry service" $status "Medium" "Present=True; Status=$($s.Status);StartType=$($s.StartType)" "Disable the legacy Remote Registry service where it is not required by an approved operational dependency." "ISO/IEC 27001:2022-aligned secure configuration"
    } else {
        New-ASREServicesResult "Remote Registry service" "INFO" "Info" "Remote Registry service not present." "Document service state as part of the endpoint baseline." "ISO/IEC 27001:2022-aligned secure configuration"
    }
}

Export-ModuleMember -Function "Test-ASRECriticalServices", "Test-ASREAutomaticRunningServices", "Test-ASREUnquotedServicePaths", "Test-ASREWinRMService", "Test-ASRERemoteRegistryService"
