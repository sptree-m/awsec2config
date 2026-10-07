#requires -Version 5.1
#requires -RunAsAdministrator
$ErrorActionPreference='Stop'
$directory=Join-Path $env:ProgramData 'awsec2config'
if (-not (Test-Path $directory)) { throw 'Run Ec2Logging Apply first' }
$failures=@()
foreach ($name in @('EventLog','MpsSvc','AmazonCloudWatchAgent')) {
    try { if ((Get-Service $name).Status -ne 'Running') { $failures += $name } }
    catch { $failures += $name }
}
$disk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
$auditDisabled=$false
$temp=Join-Path $env:TEMP ('awsec2-heartbeat-'+[guid]::NewGuid().ToString()+'.csv')
try {
    $null=& auditpol.exe /backup "/file:$temp" 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'audit backup failed' }
    $rows=@([IO.File]::ReadAllText($temp) | ConvertFrom-Csv)
    foreach ($guid in @('{0CCE9215-69AE-11D9-BED3-505054503030}','{0CCE922F-69AE-11D9-BED3-505054503030}','{0CCE9235-69AE-11D9-BED3-505054503030}','{0CCE9237-69AE-11D9-BED3-505054503030}')) {
        $match=@($rows | Where-Object { @($_.PSObject.Properties.Value) -contains $guid })
        if ($match.Count -eq 0 -or @($match[0].PSObject.Properties.Value)[-1] -ne '3') { $auditDisabled=$true }
    }
    foreach ($channel in @('Security','Microsoft-Windows-PowerShell/Operational')) {
        if (-not (Get-WinEvent -ListLog $channel).IsEnabled) { $auditDisabled=$true }
    }
} catch { $auditDisabled=$true; $failures += 'audit-status-unknown' }
finally { Remove-Item -LiteralPath $temp -ErrorAction SilentlyContinue }
$record=@{type='heartbeat';time_utc=(Get-Date).ToUniversalTime().ToString('o');disk_free_percent=[int]($disk.FreeSpace*100/$disk.Size);audit_lost=0;audit_disabled=$auditDisabled;service_failures=$failures}
$record | ConvertTo-Json -Compress | Add-Content -Path (Join-Path $directory 'heartbeat.jsonl') -Encoding UTF8
