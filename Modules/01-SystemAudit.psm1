# System Audit

function New-ASRESystemResult {
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

function Test-ASRESystemIdentity {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $e = "Computer=$($env:COMPUTERNAME); OS=$($os.Caption); Build=$($os.BuildNumber); Architecture=$($os.OSArchitecture); Domain=$($cs.Domain)"
    New-ASRESystemResult "System identity" "INFO" "Info" $e "Record the endpoint identity and baseline before assessment." "ISO/IEC 27001:2022-aligned asset and configuration evidence"
}

function Test-ASREOperatingSystemBaseline {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $pass = ($os.Caption -match "Windows 10") -and ([Environment]::Is64BitOperatingSystem)
    $status = if ($pass) { "PASS" } else { "WARN" }
    $e = "Caption=$($os.Caption); Version=$($os.Version); Build=$($os.BuildNumber); Architecture=$($os.OSArchitecture)"
    New-ASRESystemResult "Windows operating system baseline" $status "Medium" $e "Confirm the endpoint OS and architecture are supported and within the organisation baseline." "ISO/IEC 27001:2022-aligned configuration management"
}

function Test-ASRESystemUptime {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $boot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
    $uptime = (Get-Date) - $boot
    $status = if ($uptime.TotalDays -le 30) { "PASS" } else { "WARN" }
    $e = "LastBoot=$boot; UptimeDays=$([math]::Round($uptime.TotalDays,2))"
    New-ASRESystemResult "System uptime" $status "Low" $e "Review prolonged uptime where it may indicate delayed patching or maintenance windows." "ISO/IEC 27001:2022-aligned operational procedures"
}

function Test-ASREInstalledUpdates {
    $updates = Get-HotFix | Sort-Object InstalledOn -Descending
    $latest = $updates | Select-Object -First 5
    $count = @($updates).Count
    $dates = ($latest | ForEach-Object { "$($_.HotFixID)=$($_.InstalledOn)" }) -join "; "
    New-ASRESystemResult "Installed Windows updates" "INFO" "Info" "UpdateCount=$count; Latest=$dates" "Review update recency against the organisation patching policy; this check reports inventory rather than declaring compliance." "ISO/IEC 27001:2022-aligned technical vulnerability management"
}

function Test-ASRETimeConfiguration {
    $service = Get-Service -Name W32Time -ErrorAction Stop
    $status = if ($service.Status -eq "Running") { "PASS" } else { "WARN" }
    $e = "Windows Time service=$($service.Status)"
    New-ASRESystemResult "Windows Time service" $status "Low" $e "Maintain time synchronisation because reliable timestamps support authentication and event correlation." "ISO/IEC 27001:2022-aligned event logging and monitoring"
}

Export-ModuleMember -Function "Test-ASRESystemIdentity", "Test-ASREOperatingSystemBaseline", "Test-ASRESystemUptime", "Test-ASREInstalledUpdates", "Test-ASRETimeConfiguration"
