param([string]$PythonExe = "")
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
if (-not $PythonExe) { $PythonExe = Join-Path $PSScriptRoot '.venv312/Scripts/python.exe' }
if (-not (Test-Path -LiteralPath $PythonExe)) { throw "Python 环境不存在，请先执行 setup.ps1" }
& $PythonExe -m labsniffer.gui
if ($LASTEXITCODE -ne 0) { throw "程序退出，代码 $LASTEXITCODE；请检查 output/application.log" }
