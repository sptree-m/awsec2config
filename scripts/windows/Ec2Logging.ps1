#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Apply','Audit','Daily','Restore')][string]$Mode,
    [string]$StateDirectory = "$env:ProgramData\awsec2config",
    [string]$OutputDirectory,
    [ValidateRange(1,168)][int]$Hours = 24,
    [switch]$Execute
)
$ErrorActionPreference = 'Stop'
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$Channels = @('Security','System','Microsoft-Windows-PowerShell/Operational')
# GUIDs avoid localized auditpol subcategory names.
$Subcategories = @(
    '{0CCE9215-69AE-11D9-BED3-505054503030}', # Logon
    '{0CCE9216-69AE-11D9-BED3-505054503030}', # Logoff
    '{0CCE9217-69AE-11D9-BED3-505054503030}', # Account lockout
    '{0CCE921B-69AE-11D9-BED3-505054503030}', # Special logon
    '{0CCE9210-69AE-11D9-BED3-505054503030}', # Security state change
    '{0CCE9211-69AE-11D9-BED3-505054503030}', # Security system extension
    '{0CCE9212-69AE-11D9-BED3-505054503030}', # System integrity
    '{0CCE922F-69AE-11D9-BED3-505054503030}', # Audit policy change
    '{0CCE9235-69AE-11D9-BED3-505054503030}', # User account management
    '{0CCE9237-69AE-11D9-BED3-505054503030}'  # Security group management
)
function Native([string]$File, [string[]]$Arguments) {
    $result = & $File @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "$File failed ($LASTEXITCODE): $result" }
    return ($result | Out-String)
}
function Save-State($State) {
    $temporary = Join-Path $StateDirectory 'state.tmp'
    Normalize $State | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination (Join-Path $StateDirectory 'state.json') -Force
}
function Protect-Directory([string]$Path) {
    # Restrict potentially sensitive logs to SYSTEM and local Administrators (SID, locale independent).
    $null = Native 'icacls.exe' @($Path,'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
}
function Read-Registry {
    if (Test-Path $RegistryPath) {
        $key = Get-Item $RegistryPath
        if ($key.GetValueNames() -contains 'EnableScriptBlockLogging') {
            return @{ Exists=$true; Value=$key.GetValue('EnableScriptBlockLogging'); Kind=$key.GetValueKind('EnableScriptBlockLogging').ToString() }
        }
    }
    return @{ Exists=$false; Value=$null; Kind=$null }
}
function Snapshot {
    $logs = @{}
    foreach ($channel in $Channels) {
        $log = Get-WinEvent -ListLog $channel
        $logs[$channel] = @{ Enabled=$log.IsEnabled; Size=$log.MaximumSizeInBytes; LogMode=$log.LogMode.ToString() }
    }
    $fw = @(Get-NetFirewallProfile | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{ Name=$_.Name.ToString(); LogBlocked=$_.LogBlocked.ToString(); LogAllowed=$_.LogAllowed.ToString(); LogMaxSizeKilobytes=[int]$_.LogMaxSizeKilobytes }
    })
    $temporary=Join-Path $env:TEMP (('awsec2config-' + [guid]::NewGuid().ToString()) + '.csv')
    try {
        $null=Native 'auditpol.exe' @('/backup',"/file:$temporary")
        # Windows PowerShell 5.1 serializes Get-Content's provider metadata recursively.
        # Read a plain .NET string to keep both backups and state JSON bounded.
        $backup=[IO.File]::ReadAllText($temporary)
    } finally { Remove-Item -LiteralPath $temporary -ErrorAction SilentlyContinue }
    return @{ Logs=$logs; Firewall=$fw; Registry=(Read-Registry); Audit=(Native 'auditpol.exe' @('/get','/category:*','/r')); AuditBackup=$backup }
}
function Normalize($Value, [int]$Depth=0) {
    if ($Depth -gt 12) { throw 'Unexpected recursive state value; comparison stopped' }
    if ($null -eq $Value) { return $null }
    # Get-Content annotates strings with ETS properties; serialize their scalar value.
    if ($Value -is [string]) { return [string]::new($Value.ToCharArray()) }
    if ($Value.GetType().IsValueType) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $sorted=[ordered]@{}
        foreach ($key in @($Value.Keys | Sort-Object)) { $sorted[$key]=Normalize $Value[$key] ($Depth + 1) }
        return $sorted
    }
    if ($Value.GetType() -eq [System.Management.Automation.PSCustomObject]) {
        $sorted=[ordered]@{}
        foreach ($p in @($Value.PSObject.Properties | Sort-Object Name)) { $sorted[$p.Name]=Normalize $p.Value ($Depth + 1) }
        return $sorted
    }
    if ($Value -is [array]) { return ,@($Value | ForEach-Object { Normalize $_ ($Depth + 1) }) }
    return $Value
}
function Canonical($Value) { return (Normalize $Value | ConvertTo-Json -Depth 15 -Compress) }
function Audit-Enabled([string]$Backup) {
    # auditpol backup's final CSV column is the numeric Setting Value (3 = success + failure).
    # First matching row is the system policy; later per-user rows cannot substitute for it.
    $rows=@($Backup | ConvertFrom-Csv)
    foreach ($guid in $Subcategories) {
        $matches=@($rows | Where-Object { @($_.PSObject.Properties.Value) -contains $guid })
        if ($matches.Count -eq 0 -or @($matches[0].PSObject.Properties.Value)[-1] -ne '3') { return $false }
    }
    return $true
}

try {
    if ($Mode -eq 'Apply') {
        $os = Get-CimInstance Win32_OperatingSystem
        if ($os.Caption -notmatch 'Windows Server 2025') { throw 'Windows Server 2025 のみ対応しています' }
        if (Test-Path $StateDirectory) { throw '状態ディレクトリが存在します。Audit / Restore で確認してください' }
        $before = Snapshot
        $null = New-Item -ItemType Directory -Path $StateDirectory
        Protect-Directory $StateDirectory
        $null = Native 'auditpol.exe' @('/backup',"/file:$StateDirectory\audit-before.csv")
        $state = @{ Version=1; Phase='applying'; CreatedAt=(Get-Date).ToUniversalTime().ToString('o'); Before=$before; Expected=$null }
        Save-State $state
        # Expected full state is persisted before mutation, allowing safe recovery from interruptions.
        $expected = Snapshot
        foreach ($channel in $Channels) { $expected.Logs[$channel].Enabled=$true; $expected.Logs[$channel].Size=268435456 }
        foreach ($profile in $expected.Firewall) { $profile.LogBlocked='True'; $profile.LogAllowed='True'; $profile.LogMaxSizeKilobytes=32767 }
        $expected.Registry=@{ Exists=$true; Value=1; Kind='DWord' }
        $state.Expected=$expected
        Save-State $state
        foreach ($category in $Subcategories) {
            $null = Native 'auditpol.exe' @('/set',"/subcategory:$category",'/success:enable','/failure:enable')
        }
        # Snapshot full audit policy after applying; restore only if it still matches.
        $state.Expected.Audit = Native 'auditpol.exe' @('/get','/category:*','/r')
        $state.Expected.AuditBackup = (Snapshot).AuditBackup
        Save-State $state
        if (-not (Audit-Enabled $state.Expected.AuditBackup)) { throw '監査の Success / Failure を確認できません。Audit と正管理者の確認が必要です' }
        foreach ($channel in $Channels) {
            $null = Native 'wevtutil.exe' @('sl',$channel,'/e:true','/ms:268435456')
        }
        Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 32767
        if (-not (Test-Path $RegistryPath)) { $null = New-Item -Path $RegistryPath -Force }
        $null = New-ItemProperty -Path $RegistryPath -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force
        $actual = Snapshot
        if ((Canonical $actual) -ne (Canonical $state.Expected)) { throw '反映後の設定が期待値と一致しません。Audit を確認してください' }
        $state.Phase='applied'
        Save-State $state
        Write-Output '導入完了。Audit と試験イベントで有効設定を確認してください。'
    } elseif ($Mode -eq 'Restore') {
        $state = Get-Content (Join-Path $StateDirectory 'state.json') -Raw | ConvertFrom-Json
        if ($state.Phase -eq 'restored') { Write-Output '復元済みです'; exit 0 }
        $current = Snapshot
        # Interrupted apply may have a mix of before/expected values. Full audit policy must match
        # either snapshot; partial auditpol application is escalated for manual review.
        foreach ($channel in $Channels) {
            $b=$state.Before.Logs.$channel; $e=$state.Expected.Logs.$channel; $c=$current.Logs[$channel]
            foreach ($property in @('Enabled','Size','LogMode')) {
                if ($c[$property] -ne $b.$property -and $c[$property] -ne $e.$property) { throw "導入後の変更を検出: $channel $property" }
            }
        }
        if ($current.Audit -ne $state.Before.Audit -and $current.Audit -ne $state.Expected.Audit) { throw '監査ポリシーに別の変更があります。正管理者による手動確認が必要です' }
        if ($current.AuditBackup -ne $state.Before.AuditBackup -and $current.AuditBackup -ne $state.Expected.AuditBackup) { throw '監査ポリシーの完全バックアップに変更があります。正管理者に確認してください' }
        foreach ($profile in $current.Firewall) {
            $b=@($state.Before.Firewall | Where-Object Name -eq $profile.Name)[0]
            $e=@($state.Expected.Firewall | Where-Object Name -eq $profile.Name)[0]
            foreach ($property in @('LogBlocked','LogAllowed','LogMaxSizeKilobytes')) {
                if ($profile.$property -ne $b.$property -and $profile.$property -ne $e.$property) { throw "Firewall 設定の競合: $($profile.Name)" }
            }
        }
        $r=$current.Registry
        if ((Canonical $r) -ne (Canonical $state.Before.Registry) -and (Canonical $r) -ne (Canonical $state.Expected.Registry)) { throw 'ScriptBlockLogging 設定の競合' }
        Write-Output '復元対象: 監査ポリシー、イベントログ容量・有効状態、Firewallログ設定、ScriptBlockLogging値。ログは保持。'
        if (-not $Execute) { Write-Output '実行には -Execute を指定してください'; exit 0 }
        $null = Native 'auditpol.exe' @('/restore',"/file:$StateDirectory\audit-before.csv")
        foreach ($channel in $Channels) {
            $b=$state.Before.Logs.$channel
            $enabled=$b.Enabled.ToString().ToLowerInvariant()
            $null = Native 'wevtutil.exe' @('sl',$channel,"/e:$enabled","/ms:$($b.Size)")
        }
        foreach ($p in $state.Before.Firewall) {
            Set-NetFirewallProfile -Profile $p.Name -LogBlocked $p.LogBlocked -LogAllowed $p.LogAllowed -LogMaxSizeKilobytes $p.LogMaxSizeKilobytes
        }
        if ($state.Before.Registry.Exists) {
            $null = New-ItemProperty -Path $RegistryPath -Name EnableScriptBlockLogging -Value $state.Before.Registry.Value -PropertyType $state.Before.Registry.Kind -Force
        } else { Remove-ItemProperty -Path $RegistryPath -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue }
        if ((Canonical (Snapshot)) -ne (Canonical $state.Before)) { throw '復元後の設定が元の値と一致しません' }
        $state.Phase='restored'; Save-State $state
        Write-Output '復元完了。状態記録と取得済みログは保持しました。'
    } else {
        if (-not $OutputDirectory) { throw '-OutputDirectory に新しい出力先を指定してください' }
        if (Test-Path $OutputDirectory) { throw '出力先が既に存在します' }
        $null = New-Item -ItemType Directory -Path $OutputDirectory
        Protect-Directory $OutputDirectory
        $checks = [System.Collections.Generic.List[object]]::new()
        $evidence = @{}
        function Check($Name,$Status,$Detail) { $checks.Add([pscustomobject]@{ Name=$Name; Status=$Status; Detail=$Detail }) }
        try {
            $current=Snapshot; $evidence.Settings=$current
            $state=Get-Content (Join-Path $StateDirectory 'state.json') -Raw | ConvertFrom-Json
            Check '導入状態' $(if ($state.Phase -eq 'applied') {'PASS'} else {'FAIL'}) $state.Phase
            foreach ($channel in $Channels) {
                $expected=$state.Expected.Logs.$channel
                $actual=$current.Logs[$channel]
                $ok=($actual.Enabled -eq $expected.Enabled -and $actual.Size -eq $expected.Size)
                Check $channel $(if ($ok) {'PASS'} else {'FAIL'}) (Canonical $actual)
            }
            Check '監査ポリシー一致' $(if ($current.Audit -eq $state.Expected.Audit) {'PASS'} else {'FAIL'}) 'auditpol /get /category:* /r の全項目比較'
            Check '監査 Success / Failure' $(if (Audit-Enabled $current.AuditBackup) {'PASS'} else {'FAIL'}) '対象10サブカテゴリのバックアップCSV Setting Value=3を確認'
            Check 'Firewall ログ設定' $(if ((Canonical $current.Firewall) -eq (Canonical $state.Expected.Firewall)) {'PASS'} else {'FAIL'}) (Canonical $current.Firewall)
            Check 'ScriptBlockLogging' $(if ((Canonical $current.Registry) -eq (Canonical $state.Expected.Registry)) {'PASS'} else {'FAIL'}) (Canonical $current.Registry)
        } catch { Check '設定取得' 'UNKNOWN' $_.Exception.Message }
        $index=0
        foreach ($channel in $Channels) {
            try {
                $evtx=Join-Path $OutputDirectory "events-$index.evtx"
                $milliseconds=$Hours * 3600000
                $query="*[System[TimeCreated[timediff(@SystemTime) <= $milliseconds]]]"
                $null=Native 'wevtutil.exe' @('epl',$channel,$evtx,"/q:$query")
                $evidence["events-$index"]=$channel
                Check "$channel イベント取得" 'PASS' "過去 $Hours 時間の EVTX。ゼロ件でも侵害なしを意味しません"
            } catch { Check "$channel イベント取得" 'UNKNOWN' $_.Exception.Message }
            $index++
        }
        try {
            $firewall=@(Get-NetFirewallProfile | Select-Object Name,Enabled,LogFileName,LogBlocked,LogAllowed)
            $evidence.FirewallRuntime=$firewall
            $i=0
            foreach ($profile in $firewall) {
                $path=[Environment]::ExpandEnvironmentVariables($profile.LogFileName)
                if (Test-Path $path) {
                    Copy-Item -LiteralPath $path -Destination (Join-Path $OutputDirectory "firewall-$i.log")
                    Check "Firewall $($profile.Name) ファイル" 'PASS' '現在のログファイルを保存'
                } else { Check "Firewall $($profile.Name) ファイル" 'UNKNOWN' 'ログが未生成、または取得不可' }
                if (-not $profile.Enabled) { Check "Firewall $($profile.Name) 有効状態" 'FAIL' 'Firewall が無効です。正管理者へ確認してください' }
                $i++
            }
            $evidence.Disk=Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,Size,FreeSpace
            $evidence.Services=Get-Service EventLog,MpsSvc | Select-Object Name,Status
            foreach ($s in $evidence.Services) { Check $s.Name $(if ($s.Status -eq 'Running') {'PASS'} else {'FAIL'}) $s.Status.ToString() }
        } catch { Check '運用情報取得' 'UNKNOWN' $_.Exception.Message }
        Check '侵害判定' 'UNKNOWN' '自動判定しません。4625/4624/4672/4720/4732/4719/1102 と PowerShell 4104 を確認してください'
        $report=@{ SchemaVersion=1; Mode=$Mode; TimeUtc=(Get-Date).ToUniversalTime().ToString('o'); Host=$env:COMPUTERNAME; Hours=$Hours; Checks=$checks; Evidence=$evidence }
        $report | ConvertTo-Json -Depth 15 | Set-Content (Join-Path $OutputDirectory 'report.json') -Encoding UTF8
        $checks | ConvertTo-Html -Title 'Windows Server 2025 logging evidence' -PreContent '<h1>ログ収集監査</h1><p>PASS は個別確認です。侵害なしの証明ではありません。生ログは同じフォルダーの EVTX を参照してください。</p>' |
            Set-Content (Join-Path $OutputDirectory 'report.html') -Encoding UTF8
        Get-ChildItem $OutputDirectory -File | Get-FileHash -Algorithm SHA256 | Select-Object @{n='File';e={Split-Path $_.Path -Leaf}},Hash |
            ConvertTo-Json | Set-Content (Join-Path $OutputDirectory 'sha256.json') -Encoding UTF8
        Write-Output $OutputDirectory
        if (@($checks | Where-Object { $_.Status -ne 'PASS' -and $_.Name -ne '侵害判定' }).Count -gt 0) { exit 2 }
    }
} catch { Write-Error $_; exit 1 }
