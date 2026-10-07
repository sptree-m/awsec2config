#requires -Version 5.1
#requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][ValidateSet('Apply','Restore')][string]$Mode,[switch]$Execute)
$ErrorActionPreference='Stop'
$name='AWSEC2configHeartbeat'
$state=Join-Path $env:ProgramData 'awsec2config\heartbeat-task.json'
function Hash-Xml([string]$Value) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))) }
    finally { $sha.Dispose() }
}
if ($Mode -eq 'Apply') {
    if (-not (Test-Path (Split-Path $state))) { throw 'Run Ec2Logging Apply first' }
    if ((Test-Path $state) -or (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)) { throw 'Dedicated task/state already exists; refusing overwrite' }
    $script=Join-Path $PSScriptRoot 'Heartbeat.ps1'
    $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -File `"$script`""
    $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
    $principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
    # Record intent first. A partial registration without final hash requires manual review.
    @{Phase='registering';TaskName=$name} | ConvertTo-Json | Set-Content $state -Encoding UTF8
    $null=Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    $xml=Export-ScheduledTask -TaskName $name
    @{Phase='applied';TaskName=$name;Hash=(Hash-Xml $xml)} | ConvertTo-Json | Set-Content $state -Encoding UTF8
    Start-ScheduledTask -TaskName $name
} else {
    $before=Get-Content $state -Raw | ConvertFrom-Json
    if ($before.Phase -eq 'restored') { Write-Output 'Already restored'; exit 0 }
    $task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($task -and ($before.Phase -ne 'applied' -or (Hash-Xml (Export-ScheduledTask -TaskName $name)) -ne $before.Hash)) { throw 'Task changed or registration interrupted; manual review required' }
    Write-Output 'Remove dedicated heartbeat task; preserve logs and state'
    if ($Execute) {
        if ($task) { Stop-ScheduledTask -TaskName $name; Unregister-ScheduledTask -TaskName $name -Confirm:$false }
        $before.Phase='restored'; $before | ConvertTo-Json | Set-Content $state -Encoding UTF8
    }
}
