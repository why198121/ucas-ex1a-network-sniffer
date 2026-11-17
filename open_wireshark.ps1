param([string]$Capture = "", [switch]$TShark, [string]$PythonExe = "")
$ErrorActionPreference = "Stop"
$capturePath = if ($Capture) { (Resolve-Path -LiteralPath $Capture).Path } else { $null }
if ($TShark -and -not $capturePath) { throw "TShark 离线分析需要指定 -Capture" }
Set-Location -LiteralPath $PSScriptRoot
if (-not $PythonExe) { $PythonExe = Join-Path $PSScriptRoot '.venv312/Scripts/python.exe' }
$arguments = @('-m', 'labsniffer.cli', 'wireshark')
if ($capturePath) { $arguments += $capturePath }
if (-not $TShark) { $arguments += '--gui' }
& $PythonExe @arguments
if ($LASTEXITCODE -ne 0) { throw "Wireshark 启动或文件配对校验失败" }
