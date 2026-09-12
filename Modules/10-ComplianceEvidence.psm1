# Compliance Evidence

function New-ASREEvidenceResult {
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

function Test-ASREAuditPolicy {
    $projectRoot = Split-Path $PSScriptRoot -Parent
    $evidenceDir = Join-Path $projectRoot "Evidence"
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
    $evidencePath = Join-Path $evidenceDir "audit-policy.txt"

    $output = & auditpol.exe /get /category:* 2>&1
    $exit = $LASTEXITCODE
    ($output | Out-String).Trim() | Set-Content -Path $evidencePath -Encoding UTF8

    $status = if ($exit -eq 0) { "PASS" } else { "WARN" }
    $text = ($output | Out-String).Trim().Replace("`r"," ").Replace("`n"," ")
    if ($text.Length -gt 1000) { $text = $text.Substring(0,1000) + "..." }

    New-ASREEvidenceResult "Windows audit policy collection" $status "High" "ExitCode=$exit; EvidenceFile=$evidencePath; Preview=$text" "Retain the audit-policy output as evidence and compare required subcategories with the organisation logging baseline." "ISO/IEC 27001:2022-aligned logging and monitoring"
}

function Test-ASRESecurityPolicyExport {
    $projectRoot = Split-Path $PSScriptRoot -Parent
    $evidenceDir = Join-Path $projectRoot "Evidence"
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null

    $tempDir = Join-Path $env:TEMP "ASRE-Audit"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    $tempCfg = Join-Path $tempDir "security-policy.inf"
    $output = & secedit.exe /export /cfg $tempCfg /areas SECURITYPOLICY 2>&1
    $exit = $LASTEXITCODE
    $exists = Test-Path $tempCfg

    $savedCfg = Join-Path $evidenceDir "security-policy.inf"
    if ($exists) {
        Copy-Item -Path $tempCfg -Destination $savedCfg -Force
    }

    $status = if ($exit -eq 0 -and (Test-Path $savedCfg)) { "PASS" } else { "WARN" }
    $e = "ExitCode=$exit; EvidenceFile=$savedCfg; Exists=$([bool](Test-Path $savedCfg))"
    New-ASREEvidenceResult "Local security policy export" $status "High" $e "Retain the exported local security-policy evidence inside the audit artefact set and protect it from unauthorised modification." "ISO/IEC 27001:2022-aligned documented evidence"
}

function Test-ASREInventorySnapshot {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $e = "Manufacturer=$($cs.Manufacturer); Model=$($cs.Model); BIOS=$($bios.SMBIOSBIOSVersion); OS=$($os.Caption); Build=$($os.BuildNumber)"
    New-ASREEvidenceResult "Asset inventory snapshot" "PASS" "Info" $e "Store the endpoint inventory snapshot with the assessment timestamp and asset identifier." "ISO/IEC 27001:2022-aligned asset inventory"
}

function Test-ASRECollectionMetadata {
    $is64 = [Environment]::Is64BitOperatingSystem
    $ps = $PSVersionTable.PSVersion.ToString()
    $e = "CollectionTime=$(Get-Date -Format o); Computer=$env:COMPUTERNAME; User=$env:USERNAME; PowerShell=$ps; OSArchitecture=$([Environment]::OSArchitecture); Is64Bit=$is64"
    New-ASREEvidenceResult "Collection metadata" "PASS" "Info" $e "Retain collection context so the evidence can be traced to the assessed endpoint and time." "ISO/IEC 27001:2022-aligned documented information"
}

function Test-ASREEvidenceManifest {
    $files = @(Get-ChildItem -Path (Join-Path (Split-Path $PSScriptRoot -Parent) "Evidence") -File -ErrorAction SilentlyContinue)
    $e = ($files | ForEach-Object { "$($_.Name)=$($_.Length) bytes" }) -join "; "
    New-ASREEvidenceResult "Evidence directory manifest" "INFO" "Info" "EvidenceFiles=$($files.Count); $e" "Keep collected evidence separated from source code and document what each file supports." "ISO/IEC 27001:2022-aligned documented information"
}

Export-ModuleMember -Function "Test-ASREAuditPolicy", "Test-ASRESecurityPolicyExport", "Test-ASREInventorySnapshot", "Test-ASRECollectionMetadata", "Test-ASREEvidenceManifest"
