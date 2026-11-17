param([string]$PythonExe = "python", [switch]$Development)
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
& $PythonExe -c "import sys,struct; assert sys.platform == 'win32' and struct.calcsize('P') == 8; assert (3,12) <= sys.version_info[:2] < (3,14), '需要 Python 3.12 或 3.13 x64'"
if ($LASTEXITCODE -ne 0) { throw "请通过 -PythonExe 指定 Python 3.12/3.13 x64" }
New-Item -ItemType Directory -Path '.work/install-temp' -Force | Out-Null
$env:TEMP = Join-Path $PSScriptRoot '.work/install-temp'
$env:TMP = $env:TEMP
& $PythonExe -m venv .venv312
if ($LASTEXITCODE -ne 0) { throw "创建虚拟环境失败，请检查 Python 的 ensurepip 是否可用" }
$requirements = if ($Development) { 'requirements-dev.txt' } else { 'requirements.txt' }
& '.\.venv312\Scripts\python.exe' -m pip install -r $requirements
if ($LASTEXITCODE -ne 0) { throw "依赖安装失败" }
& '.\.venv312\Scripts\python.exe' -c "from PySide6.QtCore import qVersion; import scapy,lark,psutil; print('Qt', qVersion())"
if ($LASTEXITCODE -ne 0) { throw "Qt 加载失败，请核对 Python 自带或系统 Microsoft Visual C++ x64 运行库版本" }
Write-Output '依赖检查通过。启动：.\start.ps1；验收：.\run_tests.ps1'
