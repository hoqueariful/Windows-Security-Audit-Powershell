# Hardening Audit

function New-ASREHardeningResult {
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

function Test-ASREUACConfiguration {
    $p = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
    $status = if ($p.EnableLUA -eq 1) { "PASS" } else { "FAIL" }
    New-ASREHardeningResult "User Account Control" $status "High" "EnableLUA=$($p.EnableLUA); ConsentPromptBehaviorAdmin=$($p.ConsentPromptBehaviorAdmin)" "Maintain UAC and review administrative elevation behaviour against the endpoint baseline." "ISO/IEC 27001:2022-aligned secure configuration"
}

function Test-ASREBitLockerStatus {
    $cmd = Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue
    if (-not $cmd) {
        New-ASREHardeningResult "BitLocker status" "INFO" "Medium" "Get-BitLockerVolume is not available." "Document disk-encryption capability and assess through the available Windows management interface." "ISO/IEC 27001:2022-aligned cryptographic controls"
    } else {
        $v = @(Get-BitLockerVolume -ErrorAction Stop)
        $system = $v | Where-Object { $_.MountPoint -eq "C:" } | Select-Object -First 1
        if ($system) {
            $status = if ($system.ProtectionStatus -eq "On" -and $system.VolumeStatus -eq "FullyEncrypted") { "PASS" } else { "WARN" }
            $e = "MountPoint=$($system.MountPoint); VolumeStatus=$($system.VolumeStatus); ProtectionStatus=$($system.ProtectionStatus); EncryptionPercentage=$($system.EncryptionPercentage)"
            New-ASREHardeningResult "BitLocker system-volume status" $status "High" $e "Enable and maintain full-disk encryption and key recovery controls for protected endpoints." "ISO/IEC 27001:2022-aligned cryptographic controls"
        } else {
            New-ASREHardeningResult "BitLocker system-volume status" "INFO" "Medium" "C: volume not returned by Get-BitLockerVolume." "Document the endpoint encryption state using the available management source." "ISO/IEC 27001:2022-aligned cryptographic controls"
        }
    }
}

function Test-ASRESecureBoot {
    try {
        $secure = Confirm-SecureBootUEFI -ErrorAction Stop
        $status = if ($secure) { "PASS" } else { "WARN" }
        New-ASREHardeningResult "Secure Boot" $status "Medium" "SecureBoot=$secure" "Use Secure Boot where supported by the hardware and operating-system configuration." "ISO/IEC 27001:2022-aligned secure configuration"
    } catch {
        New-ASREHardeningResult "Secure Boot" "INFO" "Info" "Secure Boot state could not be queried: $($_.Exception.Message)" "Record whether the device uses UEFI/Secure Boot and assess through firmware or hardware-management evidence." "ISO/IEC 27001:2022-aligned secure configuration"
    }
}

function Test-ASRESMBv1 {
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        $status = if ($f.State -eq "Disabled") { "PASS" } else { "WARN" }
        New-ASREHardeningResult "SMBv1 Windows optional feature" $status "High" "State=$($f.State)" "Keep SMBv1 disabled unless an approved legacy dependency exists and compensating controls are documented." "ISO/IEC 27001:2022-aligned secure configuration"
    } catch {
        New-ASREHardeningResult "SMBv1 Windows optional feature" "INFO" "Info" "Unable to query SMB1Protocol: $($_.Exception.Message)" "Document SMB legacy-protocol state with the available Windows feature-management tooling." "ISO/IEC 27001:2022-aligned secure configuration"
    }
}

function Test-ASREScreenLockConfiguration {
    $p = Get-ItemProperty "HKCU:\Control Panel\Desktop" -ErrorAction Stop
    $active = [string]$p.ScreenSaveActive
    $secure = [string]$p.ScreenSaverIsSecure
    $timeout = [string]$p.ScreenSaveTimeOut
    $status = if ($active -eq "1" -and $secure -eq "1" -and [int]$timeout -gt 0 -and [int]$timeout -le 900) { "PASS" } else { "WARN" }
    New-ASREHardeningResult "User screen-lock configuration" $status "Medium" "ScreenSaveActive=$active; ScreenSaverIsSecure=$secure; TimeoutSeconds=$timeout" "Apply an enforced inactivity lock baseline appropriate to the organisation and avoid relying solely on per-user settings." "ISO/IEC 27001:2022-aligned secure configuration"
}

Export-ModuleMember -Function "Test-ASREUACConfiguration", "Test-ASREBitLockerStatus", "Test-ASRESecureBoot", "Test-ASRESMBv1", "Test-ASREScreenLockConfiguration"
