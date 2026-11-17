param([string]$PythonExe = "", [switch]$Offline)
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
if (-not $PythonExe) { $PythonExe = Join-Path $PSScriptRoot '.venv312/Scripts/python.exe' }
$arguments = @('tools/acceptance.py')
if ($Offline) { $arguments += '--offline' }
& $PythonExe @arguments
if ($LASTEXITCODE -ne 0) { throw "验收出现 FAIL，请检查 output/acceptance 中的日志" }
