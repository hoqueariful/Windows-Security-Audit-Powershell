#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path $PSScriptRoot -Parent)
)

$ErrorActionPreference = "Stop"

$moduleRoot = Join-Path $ProjectRoot "Modules"
$modules = @(Get-ChildItem -Path $moduleRoot -Filter "*.psm1" -File | Sort-Object Name)

if ($modules.Count -ne 10) {
    throw "Validation failed: expected 10 module files, found $($modules.Count)."
}

Write-Host "Module count: $($modules.Count) [OK]" -ForegroundColor Green

foreach ($module in $modules) {
    try {
        Remove-Module -Name ([IO.Path]::GetFileNameWithoutExtension($module.Name)) -Force -ErrorAction SilentlyContinue
        $imported = Import-Module $module.FullName -Force -PassThru -ErrorAction Stop
        $exported = @(Get-Command -Module $imported.Name -CommandType Function | Where-Object { $_.Name -like "Test-ASRE*" })

        if ($exported.Count -ne 5) {
            throw "Expected 5 Test-ASRE functions from $($module.Name), found $($exported.Count)."
        }

        Write-Host "$($module.Name): 5 exported audit functions [OK]" -ForegroundColor Green
    }
    catch {
        throw "Validation failed in $($module.Name): $($_.Exception.Message)"
    }
}

$total = @(Get-Command -Name "Test-ASRE*" -CommandType Function).Count

if ($total -ne 50) {
    throw "Validation failed: expected 50 total Test-ASRE functions, found $total."
}

Write-Host ""
Write-Host "TOTAL EXPORTED AUDIT FUNCTIONS: $total [OK]" -ForegroundColor Green
Write-Host "Syntax/import validation completed for all 10 modules." -ForegroundColor Green
