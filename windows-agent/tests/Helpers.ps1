# Shared by the tests: loads the agent's functions (nothing runs) and a few helpers.
. (Join-Path $PSScriptRoot '../analytics-agent.ps1') -Command lib
$script:Quiet = $true
$script:LogFile = $null
$script:ProtocolsDir = Join-Path $PSScriptRoot '../../protocols'

function Get-Cases {
    return ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $script:ProtocolsDir 'challenge-cases.json')))
}

function Get-CloudflareRanges {
    $j = ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $script:ProtocolsDir 'cloudflare-ranges.json')))
    return @($j.ranges)
}

function Test-InRanges {
    # Linear membership, the slow obvious way, to check the fast ways against.
    param([object[]]$Ranges, [int]$F, [System.Numerics.BigInteger]$N)
    foreach ($r in @($Ranges)) { if ($r.F -eq $F -and $r.S -le $N -and $r.E -ge $N) { return $true } }
    return $false
}

function Invoke-RewriteRule {
    # URL Rewrite's evaluation of a rule's conditions (logicalGrouping
    # MatchAll), with .NET's ECMAScript regular expressions.
    param($Rule, [hashtable]$Vars)
    $conds = @(@($Rule.Children | Where-Object { $_.Name -eq 'conditions' })[0].Items)
    foreach ($c in $conds) {
        $name = $c.Attrs.input.Trim('{', '}')
        $text = ''
        if ($Vars.ContainsKey($name)) { $text = [string]$Vars[$name] }
        $opts = [System.Text.RegularExpressions.RegexOptions]::ECMAScript
        if ($c.Attrs.ignoreCase) { $opts = $opts -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
        $m = [regex]::IsMatch($text, $c.Attrs.pattern, $opts)
        if ($c.Attrs.negate) { $m = -not $m }
        if (-not $m) { return $false }
    }
    return $true
}

function New-TestConfig {
    param([string]$Dir)
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    return @{
        site_id = 'aaaaaaaaaaaaaaaaaaaaaaaa'; secret = 'test-secret-0123456789abcdef'; endpoint = 'https://collector.example'
        ports = @(80, 443); state_dir = (Join-Path $Dir 'state'); page_dir = (Join-Path $Dir 'www'); iis_log_dirs = @()
        windows_firewall = $true; iis_limits = $true; iis_check = $true; logs = $true; firewall_chunk = 500
        check_substatus = 71; flush_log_buffer = $false; config_path = (Join-Path $Dir 'config.json')
    }
}

function New-TestAgent {
    param([string]$Dir, $Rules = $null)
    $cfg = New-TestConfig $Dir
    if (-not (Test-Path $cfg.state_dir)) { New-Item -ItemType Directory -Path $cfg.state_dir -Force | Out-Null }
    $a = New-Agent $cfg
    if ($null -ne $Rules) {
        $json = $Rules
        if ($Rules -isnot [string]) { $json = ConvertTo-Json -InputObject $Rules -Depth 6 -Compress }
        $a.RulesJson = $json
        $a.Rules = ConvertFrom-Json $json
        Set-AgentPlan $a
    }
    return $a
}

function New-TestDir {
    $d = Join-Path ([IO.Path]::GetTempPath()) ('agent-test-' + [guid]::NewGuid().ToString('N').Substring(0, 10))
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    return $d
}

function New-LogEntry {
    param([string]$Ip, [string]$Path = '/', [int]$Status = 200, [int]$Sub = 0, [double]$Time = 0, [string]$Method = 'GET')
    return @{ Ip = (ConvertTo-IpNumber $Ip); Method = $Method; Path = $Path; Status = $Status; SubStatus = $Sub; Ua = 'curl'; Time = $Time }
}
