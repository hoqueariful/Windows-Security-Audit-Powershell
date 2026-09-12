# Account Audit

function New-ASREAccountResult {
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

function Test-ASRELocalUsers {
    $users = Get-LocalUser -ErrorAction Stop
    $enabled = @($users | Where-Object { $_.Enabled -eq $true }).Count
    $e = ($users | ForEach-Object { "$($_.Name):Enabled=$($_.Enabled)" }) -join "; "
    New-ASREAccountResult "Local user inventory" "INFO" "Info" "EnabledUsers=$enabled; $e" "Review local accounts and remove or disable accounts that are no longer justified." "ISO/IEC 27001:2022-aligned identity lifecycle"
}

function Test-ASREGuestAccount {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($null -eq $guest) {
        New-ASREAccountResult "Guest account" "INFO" "Info" "Guest account not found." "Record the platform state; do not assume absence alone represents a control outcome." "ISO/IEC 27001:2022-aligned identity management"
    } else {
        $status = if ($guest.Enabled) { "WARN" } else { "PASS" }
        New-ASREAccountResult "Guest account" $status "Medium" "Guest Enabled=$($guest.Enabled)" "Disable the built-in Guest account unless an approved business requirement exists." "ISO/IEC 27001:2022-aligned access control"
    }
}

function Test-ASREAdministratorAccount {
    $admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    if ($null -eq $admin) {
        New-ASREAccountResult "Built-in Administrator account" "INFO" "Info" "Built-in Administrator account not found." "Document the account state and confirm equivalent privileged-account controls." "ISO/IEC 27001:2022-aligned privileged access"
    } else {
        $status = if ($admin.Enabled) { "WARN" } else { "PASS" }
        New-ASREAccountResult "Built-in Administrator account" $status "Medium" "Administrator Enabled=$($admin.Enabled)" "Prefer named administrative accounts and apply least privilege; disable the built-in account where operationally appropriate." "ISO/IEC 27001:2022-aligned privileged access"
    }
}

function Test-ASREPasswordPolicy {
    $net = net accounts 2>&1
    $text = ($net | Out-String).Trim()
    $lines = ($net | Select-String "Minimum password length|Maximum password age|Minimum password age|Password history").Line
    $e = ($lines -join "; ")
    New-ASREAccountResult "Local password policy" "INFO" "Info" $e "Review the local password and account policy against the organisation baseline; localisation may change command output labels." "ISO/IEC 27001:2022-aligned authentication information"
}

function Test-ASRELockoutPolicy {
    $net = net accounts 2>&1
    $lines = ($net | Select-String "Lockout threshold|Lockout duration|Lockout observation window").Line
    $e = ($lines -join "; ")
    New-ASREAccountResult "Account lockout policy" "INFO" "Info" $e "Review lockout settings against the organisation risk appetite and authentication policy." "ISO/IEC 27001:2022-aligned access control"
}

Export-ModuleMember -Function "Test-ASRELocalUsers", "Test-ASREGuestAccount", "Test-ASREAdministratorAccount", "Test-ASREPasswordPolicy", "Test-ASRELockoutPolicy"
