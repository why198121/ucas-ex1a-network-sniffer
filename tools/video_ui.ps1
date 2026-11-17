param([Parameter(Mandatory=$true)][int]$ProcessId, [ValidateSet('Inspect','Expand','Filter','Statistics','LastPacket')][string]$Action='Inspect', [string]$Value='', [Parameter(Mandatory=$true)][string]$OutputFile)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class VideoInput {
    [StructLayout(LayoutKind.Sequential)] public struct Point { public int x; public int y; }
    [DllImport("user32.dll")] public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr window, IntPtr after, int x, int y, int width, int height, uint flags);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr window, int command);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out Point point);
    [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(Point point);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint x, uint y, uint data, UIntPtr extra);
    [DllImport("user32.dll")] public static extern void keybd_event(byte key, byte scan, uint flags, UIntPtr extra);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
}
'@
[VideoInput]::SetThreadDpiAwarenessContext([IntPtr](-4)) | Out-Null
if ($Action -ne 'Inspect') {
    $targetWindow = (Get-Process -Id $ProcessId).MainWindowHandle
    if ([VideoInput]::IsIconic($targetWindow)) { [VideoInput]::ShowWindow($targetWindow,9) | Out-Null }
    if (-not [VideoInput]::SetWindowPos($targetWindow,[IntPtr](-1),0,0,0,0,67)) { throw '无法将目标软件窗口显示在前方' }
    [VideoInput]::SetForegroundWindow($targetWindow) | Out-Null
    Start-Sleep -Milliseconds 250
}
function Get-Controls {
    $windows = [System.Windows.Automation.AutomationElement]::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children,[System.Windows.Automation.Condition]::TrueCondition)
    foreach ($window in $windows) {
        if ($window.Current.ProcessId -eq $ProcessId) {
            $window
            foreach ($item in $window.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)) { $item }
        }
    }
}
function Click-Control($control) {
    if (-not $control -or $control.Current.IsOffscreen) { throw '目标控件未显示' }
    $rectangle = $control.Current.BoundingRectangle
    if ($rectangle.Width -lt 1 -or $rectangle.Height -lt 1) { throw '控件没有有效区域' }
    [VideoInput]::SetCursorPos([int]($rectangle.X + [Math]::Min(100,$rectangle.Width / 2)),[int]($rectangle.Y + $rectangle.Height / 2)) | Out-Null
    $point = [VideoInput+Point]::new()
    [VideoInput]::GetCursorPos([ref]$point) | Out-Null
    [uint32]$pointOwner = 0
    [VideoInput]::GetWindowThreadProcessId([VideoInput]::WindowFromPoint($point),[ref]$pointOwner) | Out-Null
    if ($pointOwner -ne $ProcessId) { throw "目标控件被其他窗口覆盖：期望 PID=$ProcessId，实际 PID=$pointOwner，位置=$($point.x),$($point.y)" }
    [VideoInput]::mouse_event(2,0,0,0,[UIntPtr]::Zero)
    [VideoInput]::mouse_event(4,0,0,0,[UIntPtr]::Zero)
    Start-Sleep -Milliseconds 180
}
function Press-Key([byte]$Key) {
    [uint32]$owner = 0
    [VideoInput]::GetWindowThreadProcessId([VideoInput]::GetForegroundWindow(),[ref]$owner) | Out-Null
    if ($owner -ne $ProcessId) { throw "键盘焦点没有位于目标 Wireshark 窗口；实际 PID=$owner，目标 PID=$ProcessId" }
    [VideoInput]::keybd_event($Key,0,0,[UIntPtr]::Zero)
    [VideoInput]::keybd_event($Key,0,2,[UIntPtr]::Zero)
    Start-Sleep -Milliseconds 300
}
$controls = @(Get-Controls)
if ($Action -eq 'Expand') {
    $node = $controls | Where-Object { $_.Current.Name -eq $Value -and $_.Current.ControlType.ProgrammaticName -eq 'ControlType.TreeItem' -and -not $_.Current.IsOffscreen } | Select-Object -First 1
    if (-not $node) { throw "没有找到可见协议节点：$Value" }
    Click-Control $node
    Press-Key 39
    $node = @(Get-Controls) | Where-Object { $_.Current.Name -eq $Value -and $_.Current.ControlType.ProgrammaticName -eq 'ControlType.TreeItem' -and -not $_.Current.IsOffscreen } | Select-Object -First 1
    $expansion = $node.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern)
    if ($expansion.Current.ExpandCollapseState -ne [System.Windows.Automation.ExpandCollapseState]::Expanded) { throw "协议节点没有展开：$Value" }
} elseif ($Action -eq 'Filter') {
    $edit = $controls | Where-Object { $_.Current.ClassName -eq 'DisplayFilterEdit' -and -not $_.Current.IsOffscreen } | Select-Object -First 1
    if (-not $edit) { throw '没有找到显示过滤输入框' }
    $edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($Value)
    Click-Control $edit
    Press-Key 13
} elseif ($Action -eq 'LastPacket') {
    $packetList = $controls | Where-Object { $_.Current.ClassName -eq 'PacketList' -and -not $_.Current.IsOffscreen } | Select-Object -First 1
    Click-Control $packetList
    Press-Key 35
} elseif ($Action -eq 'Statistics') {
    $menu = $controls | Where-Object { $_.Current.ControlType.ProgrammaticName -eq 'ControlType.MenuItem' -and $_.Current.Name -match '^(统计|Statistics)' -and -not $_.Current.IsOffscreen } | Select-Object -First 1
    Click-Control $menu
    $menu = @(Get-Controls) | Where-Object { $_.Current.Name -eq 'UCAS' -and -not $_.Current.IsOffscreen } | Select-Object -First 1
    Click-Control $menu
    $menu = @(Get-Controls) | Where-Object { $_.Current.Name -eq 'LABDEMO request response statistics' -and -not $_.Current.IsOffscreen } | Select-Object -First 1
    Click-Control $menu
}
$items = foreach ($control in @(Get-Controls)) {
    $current = $control.Current
    if (-not $current.IsOffscreen -and ($current.Name -or $current.ClassName -in @('DisplayFilterEdit','QMessageBox','QPlainTextEdit','QTextEdit'))) {
        $content = ''
        $pattern = $null
        if ($control.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern,[ref]$pattern)) { $content = $pattern.Current.Value }
        $rectangle = $current.BoundingRectangle
        [PSCustomObject]@{Name=$current.Name;Class=$current.ClassName;Type=$current.ControlType.ProgrammaticName;Value=$content;Id=$current.AutomationId;Bounds=@($rectangle.X,$rectangle.Y,$rectangle.Width,$rectangle.Height)}
    }
}
[PSCustomObject]@{PID=$ProcessId;Action=$Action;Value=$Value;Controls=@($items)} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputFile -Encoding utf8
Write-Output $OutputFile
