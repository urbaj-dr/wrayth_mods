$csvPath      = "wrayth-counters.csv"
$pollInterval = 1  # seconds

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Gui {
    [DllImport("user32.dll")]
    public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

$header = "Timestamp,PID,VirtualSize_KB,PrivateBytes_KB,WorkingSet_KB,Handles,GDIObjects,USERObjects,ProcessExists"
if (-not (Test-Path $csvPath)) {
    Add-Content -Path $csvPath -Value $header
}

Write-Host "Logging Wrayth counters to $csvPath every $pollInterval seconds."
Write-Host "Press Ctrl+C to stop."

while ($true) {
    $procs = Get-Process -Name "Wrayth" -ErrorAction SilentlyContinue

    if (-not $procs) {
        Add-Content -Path $csvPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),,,,,,,,False"
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Wrayth not running - waiting..."
    } else {
        foreach ($proc in $procs) {
            $pid_val = $proc.Id
            $vs_kb   = [math]::Round($proc.VirtualMemorySize64  / 1KB)
            $pb_kb   = [math]::Round($proc.PrivateMemorySize64  / 1KB)
            $ws_kb   = [math]::Round($proc.WorkingSet64         / 1KB)
            $handles = $proc.HandleCount

            $gdi = -1; $user = -1
            $h = [Gui]::OpenProcess(0x0400, $false, $pid_val)
            if ($h -ne [IntPtr]::Zero) {
                try {
                    $gdi  = [Gui]::GetGuiResources($h, 0)
                    $user = [Gui]::GetGuiResources($h, 1)
                } finally {
                    [Gui]::CloseHandle($h) | Out-Null
                }
            }

            $row = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$pid_val,$vs_kb,$pb_kb,$ws_kb,$handles,$gdi,$user,True"
            Add-Content -Path $csvPath -Value $row

            $vs_mb = [math]::Round($vs_kb / 1024)
            $pb_mb = [math]::Round($pb_kb / 1024)
            $ws_mb = [math]::Round($ws_kb / 1024)
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] PID=$pid_val VS=${vs_mb}MB PB=${pb_mb}MB WS=${ws_mb}MB H=$handles GDI=$gdi USER=$user"
        }
    }
    Start-Sleep -Seconds $pollInterval
}