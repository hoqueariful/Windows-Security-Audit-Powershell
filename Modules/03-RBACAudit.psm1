# RBAC Audit

function New-ASRERBACResult {
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

function Test-ASREAdministratorsGroup {
    $m = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop)
    $e = ($m | ForEach-Object { "$($_.Name) [$($_.ObjectClass)]" }) -join "; "
    $status = if ($m.Count -le 2) { "PASS" } else { "WARN" }
    New-ASRERBACResult "Local Administrators membership" $status "High" "MemberCount=$($m.Count); $e" "Validate every privileged member, remove unnecessary access and prefer role-based named administration." "ISO/IEC 27001:2022-aligned access rights management"
}

function Test-ASRERemoteDesktopGroup {
    $m = @(Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue)
    $e = ($m | ForEach-Object { "$($_.Name) [$($_.ObjectClass)]" }) -join "; "
    New-ASRERBACResult "Remote Desktop Users membership" "INFO" "Medium" "MemberCount=$($m.Count); $e" "Validate whether each remote-access user has a documented business requirement." "ISO/IEC 27001:2022-aligned access control"
}

function Test-ASREBackupOperatorsGroup {
    $m = @(Get-LocalGroupMember -Group "Backup Operators" -ErrorAction SilentlyContinue)
    $e = ($m | ForEach-Object { "$($_.Name) [$($_.ObjectClass)]" }) -join "; "
    New-ASRERBACResult "Backup Operators membership" "INFO" "Medium" "MemberCount=$($m.Count); $e" "Review membership because backup privileges can enable access to protected data." "ISO/IEC 27001:2022-aligned privileged access"
}

function Test-ASREPowerUsersGroup {
    $m = @(Get-LocalGroupMember -Group "Power Users" -ErrorAction SilentlyContinue)
    $e = ($m | ForEach-Object { "$($_.Name) [$($_.ObjectClass)]" }) -join "; "
    New-ASRERBACResult "Power Users membership" "INFO" "Low" "MemberCount=$($m.Count); $e" "Confirm the legacy Power Users group is required and appropriately governed." "ISO/IEC 27001:2022-aligned least privilege"
}

function Test-ASREPrivilegedLocalGroups {
    $groups = @("Administrators","Remote Desktop Users","Backup Operators","Power Users","Network Configuration Operators")
    $rows = foreach ($g in $groups) {
        $members = @(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue)
        "$g=$($members.Count)"
    }
    New-ASRERBACResult "Privileged local group inventory" "INFO" "Info" ($rows -join "; ") "Retain a documented privileged-group review record." "ISO/IEC 27001:2022-aligned access rights management"
}

Export-ModuleMember -Function "Test-ASREAdministratorsGroup", "Test-ASRERemoteDesktopGroup", "Test-ASREBackupOperatorsGroup", "Test-ASREPowerUsersGroup", "Test-ASREPrivilegedLocalGroups"
