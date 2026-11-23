<#
  Rolls out dist\ADAudit.exe to:
    1. this PC                 (viewer)
    2. the PCs in -Viewers     (viewer, via PowerShell remoting)
    3. the DC in -Dc           (service)
  Run in an elevated PowerShell as a Domain Admin. The audit database, bookmarks and settings are kept.
  Example:  .\Update-ADAudit.ps1 -Dc DC01.corp.local -Viewers ADMIN-PC1.corp.local,ADMIN-PC2.corp.local
#>
param(
    [string]   $Exe     = "$PSScriptRoot\dist\ADAudit.exe",
    [Parameter(Mandatory)] [string] $Dc,
    [string[]] $Viewers = @()
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Exe)) { throw "Not found: $Exe" }

# replaces the exe even while a viewer is open (a running exe can be renamed, not overwritten)
$swap = {
    param($newFile)
    $dir = "C:\Program Files\ADAudit"; $exe = Join-Path $dir "ADAudit.exe"
    New-Item -ItemType Directory -Force $dir | Out-Null
    Get-ChildItem "$dir\*.old" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    if (Test-Path $exe) { Rename-Item $exe ("ADAudit.exe.{0:yyyyMMddHHmmss}.old" -f (Get-Date)) }
    Copy-Item $newFile $exe
    $lnk = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) "AD Audit Trail.lnk"
    if (-not (Test-Path $lnk)) {
        $l = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
        $l.TargetPath = $exe; $l.WorkingDirectory = $dir; $l.Description = "AD Audit Trail (requires administrator)"; $l.Save()
    }
    "$env:COMPUTERNAME : viewer updated ($((Get-Item $exe).LastWriteTime))"
}

# ── 1. this PC ──────────────────────────────────────────────
Write-Host "`n[1] Local viewer" -ForegroundColor Cyan
Get-Process ADAudit -ErrorAction SilentlyContinue | Where-Object SessionId -ne 0 | Stop-Process -Force -ErrorAction SilentlyContinue
& $swap $Exe

# ── 2. other viewer PCs ─────────────────────────────────────
foreach ($pc in $Viewers) {
    Write-Host "`n[2] Viewer on $pc" -ForegroundColor Cyan
    $s = New-PSSession -ComputerName $pc
    try {
        Copy-Item $Exe -Destination "C:\Windows\Temp\ADAudit.new.exe" -ToSession $s
        Invoke-Command -Session $s -ScriptBlock $swap -ArgumentList "C:\Windows\Temp\ADAudit.new.exe"
        Invoke-Command -Session $s { Remove-Item "C:\Windows\Temp\ADAudit.new.exe" -ErrorAction SilentlyContinue }
    } finally { Remove-PSSession $s }
}

# ── 3. service on the DC ────────────────────────────────────
Write-Host "`n[3] Service on $Dc" -ForegroundColor Cyan
$s = New-PSSession -ComputerName $Dc
try {
    Copy-Item $Exe -Destination "C:\Windows\Temp\ADAudit.new.exe" -ToSession $s
    Invoke-Command -Session $s -ScriptBlock {
        $open     = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
        $hardened = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
        $dir = "C:\Program Files\ADAudit"; $exe = Join-Path $dir "ADAudit.exe"
        sc.exe sdset ADAudit $open | Out-Null
        Stop-Service ADAudit -Force
        (Get-Service ADAudit).WaitForStatus('Stopped', '00:02:00')
        Get-ChildItem "$dir\*.old" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        Rename-Item $exe ("ADAudit.exe.{0:yyyyMMddHHmmss}.old" -f (Get-Date))
        Copy-Item "C:\Windows\Temp\ADAudit.new.exe" $exe
        Remove-Item "C:\Windows\Temp\ADAudit.new.exe"
        sc.exe sdset ADAudit $hardened | Out-Null
        Start-Service ADAudit
        Start-Sleep 8
        "$env:COMPUTERNAME : service $((Get-Service ADAudit).Status)"
        Get-Content C:\ProgramData\ADAudit\logs\service.log -Tail 6
    }
} finally { Remove-PSSession $s }

Write-Host "`nDone." -ForegroundColor Green
