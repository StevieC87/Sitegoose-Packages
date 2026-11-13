# Runs every test of the Windows agent. No Windows needed: the Windows and IIS
# calls are mocked. In Docker (from the sdk folder):
#
#   docker run --rm -v "$PWD:/sdk:ro" mcr.microsoft.com/powershell \
#     pwsh -NoProfile -File /sdk/windows-agent/tests/run.ps1
#
# Pester 5 must be on PSModulePath (Install-Module Pester, or Save-Module
# Pester -Path <folder> and add the folder to PSModulePath).
param([string]$Filter = '*.Tests.ps1')
$ErrorActionPreference = 'Stop'
Import-Module Pester -MinimumVersion 5.0
$config = New-PesterConfiguration
$config.Run.Path = @(Get-ChildItem -Path $PSScriptRoot -Filter $Filter | ForEach-Object { $_.FullName })
$config.Run.Exit = $true
$config.Output.Verbosity = 'Normal'
Invoke-Pester -Configuration $config
