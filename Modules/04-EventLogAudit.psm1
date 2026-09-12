# Event Log Audit

function New-ASREEventResult {
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

function Test-ASRESecurityLogHealth {
    $log = Get-WinEvent -ListLog "Security" -ErrorAction Stop
    $status = if ($log.IsEnabled) { "PASS" } else { "FAIL" }
    $e = "Enabled=$($log.IsEnabled); RecordCount=$($log.RecordCount); MaxSizeBytes=$($log.MaximumSizeInBytes)"
    New-ASREEventResult "Security log health" $status "High" $e "Ensure the Security log is enabled, appropriately sized and retained according to policy." "ISO/IEC 27001:2022-aligned logging and monitoring"
}

function Test-ASREFailedLogons {
    $start = (Get-Date).AddDays(-7)
    $events = @(Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625; StartTime=$start} -ErrorAction Stop)
    $status = if ($events.Count -eq 0) { "PASS" } else { "WARN" }
    New-ASREEventResult "Failed logon activity, last 7 days" $status "Medium" "Event4625Count=$($events.Count); WindowStart=$start" "Investigate unusual failed-logon volume and correlate source accounts, hosts and times before treating activity as malicious." "ISO/IEC 27001:2022-aligned monitoring"
}

function Test-ASRESuccessfulLogons {
    $start = (Get-Date).AddDays(-7)
    $events = @(Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624; StartTime=$start} -ErrorAction Stop)
    New-ASREEventResult "Successful logon activity, last 7 days" "INFO" "Info" "Event4624Count=$($events.Count); WindowStart=$start" "Use successful-logon volume for baseline and correlation with identity activity." "ISO/IEC 27001:2022-aligned monitoring"
}

function Test-ASREAccountManagementEvents {
    $ids = 4720,4726,4732,4733
    $start = (Get-Date).AddDays(-30)
    $events = @(Get-WinEvent -FilterHashtable @{LogName="Security"; Id=$ids; StartTime=$start} -ErrorAction Stop)
    New-ASREEventResult "Account and group management events, last 30 days" "INFO" "Medium" "EventCount=$($events.Count); EventIDs=$($ids -join ","); WindowStart=$start" "Review account and privileged-group changes for approved administrative activity." "ISO/IEC 27001:2022-aligned identity lifecycle"
}

function Test-ASREProcessCreationEvents {
    $start = (Get-Date).AddDays(-7)
    $events = @(Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4688; StartTime=$start} -ErrorAction SilentlyContinue)
    New-ASREEventResult "Process creation auditing, last 7 days" "INFO" "Medium" "Event4688Count=$($events.Count)" "Confirm process creation auditing is enabled where required and use the data for investigation and detection engineering." "ISO/IEC 27001:2022-aligned logging and monitoring"
}

Export-ModuleMember -Function "Test-ASRESecurityLogHealth", "Test-ASREFailedLogons", "Test-ASRESuccessfulLogons", "Test-ASREAccountManagementEvents", "Test-ASREProcessCreationEvents"
