#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) "Reports")
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$ModuleRoot = Join-Path $ProjectRoot "Modules"
$EvidenceRoot = Join-Path $ProjectRoot "Evidence"

Write-Host "Windows Security Audit - Al Shad Real Estate (fictional lab)" -ForegroundColor Cyan
Write-Host "PowerShell: $($PSVersionTable.PSVersion)"

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "This project expects 64-bit Windows PowerShell on a 64-bit Windows system."
}

$os = Get-CimInstance Win32_OperatingSystem
if ($os.Caption -notmatch "Windows 10") {
    Write-Warning "This project was designed for the user's Windows 10 baseline. Detected: $($os.Caption)"
}

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null

Get-ChildItem -Path $ModuleRoot -Filter "*.psm1" -File |
    Sort-Object Name |
    ForEach-Object {
        Import-Module $_.FullName -Force
    }

$checks = @(Get-Command -Name "Test-ASRE*" -CommandType Function | Sort-Object Name)

if ($checks.Count -ne 50) {
    throw "Preflight failed: expected 50 exported audit functions, detected $($checks.Count)."
}

Write-Host "Verified exported audit functions: $($checks.Count)" -ForegroundColor Green

$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$runRoot = Join-Path $OutputRoot $runId
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null

# ডাইনামিক রিপোর্ট পাথ ডিফাইন করা (FIXED: পূর্বের স্ক্রিপ্টে অনুপস্থিত ছিল)
$csvPath     = Join-Path $runRoot "audit_report.csv"
$jsonPath    = Join-Path $runRoot "audit_report.json"
$summaryPath = Join-Path $runRoot "summary.json"
$htmlPath    = Join-Path $runRoot "audit_report.html"

$results = New-Object System.Collections.Generic.List[object]

foreach ($check in $checks) {
    Write-Host ("Running {0}" -f $check.Name)
    try {
        $result = & $check.Name
        foreach ($item in @($result)) {
            $results.Add([pscustomobject]@{
                Check          = $item.Check
                Status         = $item.Status
                Severity       = $item.Severity
                Evidence       = $item.Evidence
                Recommendation = $item.Recommendation
                ControlRef     = $item.ControlRef
                Function       = $check.Name
            })
        }
    } catch {
        $results.Add([pscustomobject]@{
            Check          = $check.Name
            Status         = "ERROR"
            Severity       = "High"
            Evidence       = $_.Exception.Message
            Recommendation = "Investigate the collection error before treating the check as complete."
            ControlRef     = "Audit collection error"
            Function       = $check.Name
        })
    }
}

# ডেটা ক্লিনিং এবং প্রপার্টি ম্যাপিং (FIXED: $resultsArray বদলে $results ব্যবহার এবং Description প্রপার্টি অবজেক্টের সাথে সামঞ্জস্য করা হয়েছে)
$cleanedResults = foreach ($r in $results) {
    [PSCustomObject]@{
        Function       = $r.Function
        ControlRef     = $r.ControlRef
        Status         = if ($r.Status) { $r.Status } else { "ERROR" }
        Check          = $r.Check
        Severity       = $r.Severity
        Evidence       = $r.Evidence
        Recommendation = $r.Recommendation
    }
}

$cleanedResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
$cleanedResults | ConvertTo-Json -Depth 4 | Set-Content -Path $jsonPath -Encoding UTF8

$summary = [pscustomobject]@{
    Assessment      = "Windows Security Audit"
    Organisation    = "Al Shad Real Estate (fictional lab)"
    Computer        = "$env:COMPUTERNAME"
    OperatingSystem = if ($os.Caption) { "$($os.Caption)" } else { "Unknown OS" }
    Build           = if ($os.BuildNumber) { "$($os.BuildNumber)" } else { "Unknown Build" }
    Architecture    = if ($os.OSArchitecture) { "$($os.OSArchitecture)" } else { "Unknown Arch" }
    PowerShell      = $PSVersionTable.PSVersion.ToString()
    Collected       = (Get-Date -Format o)
    FunctionCount   = $checks.Count
    ResultCount     = $cleanedResults.Count
    Pass            = @($cleanedResults | Where-Object Status -eq "PASS").Count
    Warn            = @($cleanedResults | Where-Object Status -eq "WARN").Count
    Fail            = @($cleanedResults | Where-Object Status -eq "FAIL").Count
    Info            = @($cleanedResults | Where-Object Status -eq "INFO").Count
    Error           = @($cleanedResults | Where-Object Status -eq "ERROR").Count
}

$summary | ConvertTo-Json | Set-Content -Path $summaryPath -Encoding UTF8

$title = "Windows Security Audit - Al Shad Real Estate"
$css = @"
<style>
    body { font-family: Arial, sans-serif; margin: 30px; background-color: #f9f9f9; }
    h1 { color: #333; }
    p { font-size: 14px; color: #555; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; background: #fff; }
    th, td { border: 1px solid #cccccc; padding: 10px; text-align: left; vertical-align: top; font-size: 13px; }
    th { background: #0078d4; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
</style>
"@

$preContent = @"
<h1>$title</h1>
<p>Fictional laboratory assessment. ISO/IEC 27001:2022-aligned evidence mapping; not a certification or conformity assessment.</p>
<p>Computer: $env:COMPUTERNAME | OS: $($os.Caption) | Build: $($os.BuildNumber) | Collected: $(Get-Date -Format o)</p>
"@

# HTML তৈরি (FIXED: ConvertTo-Html এর স্ট্যান্ডার্ড আর্কিটেকচার অনুযায়ী CSS এবং বডি ইনজেক্ট করা হয়েছে)
$cleanedResults |
    Select-Object Check, Status, Severity, Evidence, Recommendation, ControlRef, Function |
    ConvertTo-Html -Title $title -Head $css -PreContent $preContent |
    Set-Content -Path $htmlPath -Encoding UTF8

$manifest = [pscustomobject]@{
    AssessmentFolder = $runRoot
    Csv              = $csvPath
    Json             = $jsonPath
    Summary          = $summaryPath
    Html             = $htmlPath
}
$manifest | ConvertTo-Json | Set-Content -Path (Join-Path $runRoot "manifest.json") -Encoding UTF8

Write-Host ""
Write-Host "AUDIT COMPLETE" -ForegroundColor Green
$summary | Format-List
Write-Host "Reports: $runRoot" -ForegroundColor Cyan
