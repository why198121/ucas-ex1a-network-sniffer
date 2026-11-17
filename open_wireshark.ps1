param([Parameter(Mandatory=$true)][string]$Capture, [switch]$TShark, [string]$PythonExe = "")
$ErrorActionPreference = "Stop"
$capturePath = (Resolve-Path -LiteralPath $Capture).Path
Set-Location -LiteralPath $PSScriptRoot
if (-not $PythonExe) { $PythonExe = Join-Path $PSScriptRoot '.venv312/Scripts/python.exe' }
$arguments = @('-m', 'labsniffer.cli', 'wireshark', $capturePath)
if (-not $TShark) { $arguments += '--gui' }
& $PythonExe @arguments
if ($LASTEXITCODE -ne 0) { throw "Wireshark 启动或文件配对校验失败" }
