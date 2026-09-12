# Microsoft Defender Audit

function New-ASREDefenderResult {
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

function Test-ASREDefenderService {
    $s = Get-Service -Name WinDefend -ErrorAction Stop
    $status = if ($s.Status -eq "Running") { "PASS" } else { "FAIL" }
    New-ASREDefenderResult "Microsoft Defender Antivirus service" $status "High" "ServiceStatus=$($s.Status)" "Ensure endpoint malware protection is active and operational." "ISO/IEC 27001:2022-aligned malware protection"
}

function Test-ASRERTPStatus {
    $d = Get-MpComputerStatus -ErrorAction Stop
    $status = if ($d.RealTimeProtectionEnabled) { "PASS" } else { "FAIL" }
    New-ASREDefenderResult "Defender real-time protection" $status "High" "RealTimeProtectionEnabled=$($d.RealTimeProtectionEnabled)" "Keep real-time protection enabled unless an approved compensating control exists." "ISO/IEC 27001:2022-aligned malware protection"
}

function Test-ASREDefenderSignatures {
    $d = Get-MpComputerStatus -ErrorAction Stop
    $sig = $d.AntivirusSignatureLastUpdated
    $hours = if ($sig) { ((Get-Date) - $sig).TotalHours } else { 9999 }
    $status = if ($hours -le 48) { "PASS" } else { "WARN" }
    New-ASREDefenderResult "Defender signature recency" $status "Medium" "LastSignatureUpdate=$sig; AgeHours=$([math]::Round($hours,1))" "Investigate stale malware definitions and confirm update connectivity." "ISO/IEC 27001:2022-aligned malware protection"
}

function Test-ASREDefenderScanStatus {
    $s = Get-MpComputerStatus -ErrorAction Stop
    $quick = $s.QuickScanEndTime
    $full = $s.FullScanEndTime
    New-ASREDefenderResult "Defender scan history" "INFO" "Info" "QuickScanEnd=$quick; FullScanEnd=$full" "Review scan cadence against endpoint protection policy." "ISO/IEC 27001:2022-aligned malware protection"
}

function Test-ASREDefenderTamperProtection {
    $d = Get-MpComputerStatus -ErrorAction Stop
    $value = $d.IsTamperProtected
    $status = if ($value -eq $true) { "PASS" } elseif ($value -eq $false) { "WARN" } else { "INFO" }
    New-ASREDefenderResult "Defender tamper protection" $status "Medium" "IsTamperProtected=$value" "Where supported, maintain tamper protection to reduce unauthorised security-control changes." "ISO/IEC 27001:2022-aligned malware protection"
}

Export-ModuleMember -Function "Test-ASREDefenderService", "Test-ASRERTPStatus", "Test-ASREDefenderSignatures", "Test-ASREDefenderScanStatus", "Test-ASREDefenderTamperProtection"
