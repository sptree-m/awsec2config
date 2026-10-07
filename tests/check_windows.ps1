param([string]$Script = (Join-Path $PSScriptRoot '../scripts/windows/Ec2Logging.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Script),[ref]$tokens,[ref]$errors)
if ($errors.Count) { $errors | Format-List; throw 'PowerShell parse failed' }
# Extract only pure helpers / snapshot; never execute the system-changing entry point.
foreach ($name in @('Normalize','Canonical','Snapshot','Audit-Enabled')) {
    $node=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    Invoke-Expression $node.Extent.Text
}
Write-Output "Checking canonical state round-trip"
$a=@{ Logs=@{ Security=@{Enabled=$true;Size=268435456} }; Registry=@{Exists=$true;Value=1;Kind='DWord'} }
$b=$a | ConvertTo-Json -Depth 15 | ConvertFrom-Json
if ((Canonical $a) -ne (Canonical $b)) { throw 'State JSON round-trip changed canonical values' }
$b.Logs.Security.Size=65536
if ((Canonical $a) -eq (Canonical $b)) { throw 'State drift not detected' }
# NetSecurity GpoBoolean is an enum, not a bool. Snapshot must normalize to stable strings.
enum TestGpoBoolean {
    NotConfigured = 0
    True = 1
    False = 2
}
function Get-NetFirewallProfile {
    [pscustomobject]@{Name='Public';LogBlocked=[TestGpoBoolean]::True;LogAllowed=[TestGpoBoolean]::True;LogMaxSizeKilobytes=32767}
}
function Get-WinEvent { [pscustomobject]@{IsEnabled=$true;MaximumSizeInBytes=268435456;LogMode='Circular'} }
function Read-Registry { @{Exists=$true;Value=1;Kind='DWord'} }
function Native($File,$Arguments) {
    if ($Arguments[0] -eq '/backup') {
        Set-Content -LiteralPath $Arguments[1].Substring(6) -Value 'stable audit backup'
    }
    return 'stable audit policy'
}
$Channels=@('Security','System','Microsoft-Windows-PowerShell/Operational')
if (-not $env:TEMP) { $env:TEMP=[IO.Path]::GetTempPath() }
Write-Output "Checking snapshot round-trip"
$snapshot=Snapshot
if ($snapshot.Firewall[0].LogBlocked -cne 'True') { throw 'Firewall enum normalization failed' }
if ((Canonical $snapshot) -ne (Canonical ($snapshot | ConvertTo-Json -Depth 15 | ConvertFrom-Json))) { throw 'Full snapshot round-trip failed' }
Write-Output "Checking audit setting values"
$Subcategories=@('{0CCE9215-69AE-11D9-BED3-505054503030}')
$header='Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
$enabled=$header + "`n" + ('HOST,System,Logon,' + $Subcategories[0] + ',Success and Failure,,3')
if (-not (Audit-Enabled $enabled)) { throw 'Enabled audit policy not recognized' }
$disabled=$header + "`n" + ('HOST,System,Logon,' + $Subcategories[0] + ',No Auditing,,0')
if (Audit-Enabled $disabled) { throw 'Disabled audit policy incorrectly accepted' }
foreach ($file in @(Get-ChildItem (Join-Path $PSScriptRoot '../scripts/windows') -Filter '*.ps1')) {
    $parseTokens=$null; $parseErrors=$null
    $null=[System.Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$parseTokens,[ref]$parseErrors)
    if ($parseErrors.Count) { $parseErrors | Format-List; throw ('Parse failed: '+$file.Name) }
}
Write-Output 'PowerShell syntax and state snapshot regressions: PASS'
