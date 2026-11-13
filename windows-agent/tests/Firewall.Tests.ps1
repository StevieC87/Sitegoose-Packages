BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
    function New-Rules([string]$Mode = 'block', [hashtable]$Extra = @{}) {
        $r = @{ v = 1; enabled = $true; mode = $Mode; sync = 60; allow = @('198.51.100.0/24'); deny = @('203.0.113.0/24', '2001:db8::/32')
            lists = @('192.0.2.0/24'); shared = @('192.0.2.128/25', '100.20.0.0/16'); banned = @('203.0.113.9'); goodbots = @() }
        foreach ($k in $Extra.Keys) { $r[$k] = $Extra[$k] }
        return $r
    }
    function Get-Plan([string]$Mode = 'block', [hashtable]$Extra = @{}) {
        return Get-AgentPlan (ConvertFrom-Json (ConvertTo-Json -Depth 5 -InputObject (New-Rules $Mode $Extra)))
    }
    function New-Op([string]$Name = 'AnalyticsAgent-Lists-TCP-001', [object[]]$Ports = @(80, 443), [string[]]$Addresses = @('192.0.2.0/24'), [string]$Op = 'New', [string]$Protocol = 'TCP') {
        return @{ Op = $Op; Name = $Name; Protocol = $Protocol; Ports = $Ports; Addresses = $Addresses }
    }
    function New-FwRule([string]$Name, [string[]]$Remote, [string[]]$Ports = @('80', '443'), [string]$Protocol = 'TCP') {
        return [pscustomobject]@{ Name = $Name; Protocol = $Protocol; Ports = $Ports; Remote = $Remote; Action = 'Block'; Direction = 'Inbound'; Enabled = 'True' }
    }
    $script:GoodInfo = @{ Service = 'Running'; Active = @('Public'); Profiles = @(
            @{ Name = 'Domain'; Enabled = 'False'; AllowLocalFirewallRules = 'True' },
            @{ Name = 'Public'; Enabled = 'True'; AllowLocalFirewallRules = 'NotConfigured' }) }
}

Describe 'the last check before Windows Firewall' {
    It 'passes a block of web ports for named addresses' {
        { Assert-SafeFirewallRule (New-Op) } | Should -Not -Throw
        { Assert-SafeFirewallRule (New-Op -Op 'Set' -Protocol 'UDP') } | Should -Not -Throw
        { Assert-SafeFirewallRule @{ Op = 'Remove'; Name = 'AnalyticsAgent-Origin-UDP-012' } } | Should -Not -Throw
    }
    It 'never touches a rule that is not ours' {
        { Assert-SafeFirewallRule (New-Op -Name 'Remote Desktop - User Mode (TCP-In)') } | Should -Throw
        { Assert-SafeFirewallRule @{ Op = 'Remove'; Name = 'RemoteDesktop-UserMode-In-TCP' } } | Should -Throw
        { Assert-SafeFirewallRule @{ Op = 'Remove'; Name = 'AnalyticsAgent-Other-TCP-001' } } | Should -Throw
        { Assert-SafeFirewallRule @{ Op = 'Remove'; Name = 'xAnalyticsAgent-Lists-TCP-001' } } | Should -Throw
        { Assert-SafeFirewallRule @{ Op = 'Remove'; Name = 'AnalyticsAgent-Lists-TCP-001 ' } } | Should -Throw
    }
    It 'never blocks RDP, WinRM, SSH or SMB, and never every port' {
        foreach ($p in 3389, 5985, 5986, 22, 445, 135, 139) { { Assert-SafeFirewallRule (New-Op -Ports @(443, $p)) } | Should -Throw -Because "port $p" }
        { Assert-SafeFirewallRule (New-Op -Ports @()) } | Should -Throw
        { Assert-SafeFirewallRule (New-Op -Ports @('Any')) } | Should -Throw
        { Assert-SafeFirewallRule (New-Op -Ports @('1-65535')) } | Should -Throw
        { Assert-SafeFirewallRule (New-Op -Ports @(0)) } | Should -Throw
    }
    It 'never blocks every address, or anything not an address' {
        { Assert-SafeFirewallRule (New-Op -Addresses @()) } | Should -Throw
        { Assert-SafeFirewallRule (New-Op -Addresses @('Any')) } | Should -Throw
        { Assert-SafeFirewallRule (New-Op -Addresses @('LocalSubnet')) } | Should -Throw
        { Assert-SafeFirewallRule (New-Op -Addresses @('Internet')) } | Should -Throw
        { Assert-SafeFirewallRule (New-Op -Addresses @('*')) } | Should -Throw
        { Assert-SafeFirewallRule (New-Op -Addresses @(1..1001 | ForEach-Object { '10.0.{0}.{1}' -f [math]::Floor($_ / 256), ($_ % 256) })) } | Should -Throw
        { Assert-SafeFirewallRule (New-Op -Protocol 'Any') } | Should -Throw
        { Assert-SafeFirewallRule (New-Op -Op 'Disable') } | Should -Throw
    }
    It 'takes management ports out of the configured ports' {
        Get-SafePorts @(443, 3389, 80, 80, 5985, '8080', 0, 70000, 'x', 8443.5) | Should -Be @(80, 443)
        @(Get-SafePorts @(3389)).Count | Should -Be 0
    }
}

Describe 'what the firewall should block' {
    It 'blocks nothing in monitor mode, or when the firewall is off' {
        $w = Get-FirewallWanted (Get-Plan 'monitor' @{ origin = @{ only = @('173.245.48.0/20') } }) @('192.0.2.77') @()
        @($w.Lists).Count + @($w.Bans).Count + @($w.Origin).Count | Should -Be 0
        $w = Get-FirewallWanted (Get-Plan 'block' @{ enabled = $false }) @('192.0.2.77') @()
        @($w.Lists).Count + @($w.Bans).Count | Should -Be 0
    }
    It 'blocks the lists in block mode, with allow carved out' {
        $w = Get-FirewallWanted (Get-Plan) @() @()
        $w.Lists | Should -Be @('100.20.0.0/16', '192.0.2.0/24', '203.0.113.0/24', '2001:db8::/32')
        $w2 = Get-FirewallWanted (Get-Plan 'block' @{ allow = @('192.0.2.64/26') }) @() @()
        $w2.Lists | Should -Contain '192.0.2.0/26'
        $w2.Lists | Should -Contain '192.0.2.128/25'
        $w2.Lists | Should -Not -Contain '192.0.2.0/24'
    }
    It 'blocks local bans, but never an allowed address' {
        $w = Get-FirewallWanted (Get-Plan 'block' @{ allow = @('198.51.100.7') }) @('192.0.2.77', '2001:db8:1:2::/64', '198.51.100.7', 'junk') @()
        $w.Bans | Should -Be @('192.0.2.77', '2001:db8:1:2::/64')
    }
    It 'locks to the origin: everything but only, allow, local and own, in both families' {
        $plan = Get-Plan 'block' @{ origin = @{ only = @('173.245.48.0/20', '2400:cb00::/32') } }
        $own = @(ConvertTo-IpRange '203.0.113.50')
        $w = Get-FirewallWanted $plan @() $own
        $blocked = @($w.Origin | ForEach-Object { ConvertTo-IpRange $_ -FirewallForms })
        $ip = { param($t) $n = ConvertTo-IpNumber $t -NoMap; Test-InRanges $blocked $n.F $n.N }
        & $ip '8.8.8.8' | Should -BeTrue
        & $ip '173.245.48.1' | Should -BeFalse
        & $ip '173.245.64.0' | Should -BeTrue
        & $ip '198.51.100.20' | Should -BeFalse    # allow
        & $ip '10.1.2.3' | Should -BeFalse
        & $ip '127.0.0.1' | Should -BeFalse
        & $ip '203.0.113.50' | Should -BeFalse
        & $ip '203.0.113.51' | Should -BeTrue
        & $ip '2400:cb00::1' | Should -BeFalse
        & $ip '2a00:1450::1' | Should -BeTrue
        & $ip '::1' | Should -BeFalse
        & $ip 'fe80::1' | Should -BeFalse
        & $ip '::ffff:8.8.8.8' | Should -BeFalse   # IPv4 traffic: the IPv4 rules see it
        foreach ($t in $w.Origin) { ConvertTo-IpRange $t -FirewallForms | Should -Not -BeNullOrEmpty }
    }
    It 'does not lock to an origin with no valid range' {
        $w = Get-FirewallWanted (Get-Plan 'block' @{ origin = @{ only = @('junk', '') } }) @() @()
        @($w.Origin).Count | Should -Be 0
        $w = Get-FirewallWanted (Get-Plan 'block' @{ origin = @{ only = @() } }) @() @()
        @($w.Origin).Count | Should -Be 0
    }
}

Describe 'rules in chunks' {
    It 'keeps addresses where they are, refills the gaps, then adds rules' {
        $cur = @{ 1 = @('a', 'b', 'c'); 2 = @('d', 'e') }
        $r = Get-ChunkAssignment $cur @('a', 'c', 'd', 'e', 'f', 'g', 'h') 3
        $r[1] | Should -Be @('a', 'c', 'f')
        $r[2] | Should -Be @('d', 'e', 'g')
        $r[3] | Should -Be @('h')
    }
    It 'drops emptied rules and never holds an address twice' {
        $cur = @{ 1 = @('a', 'b'); 2 = @('b', 'c'); 4 = @('x') }
        $r = Get-ChunkAssignment $cur @('a', 'b', 'c') 2
        $r.Keys.Count | Should -Be 2
        $r[1] | Should -Be @('a', 'b')
        $r[2] | Should -Be @('c')
    }
    It 'splits a long list under the per-rule limit' {
        $wanted = @(1..2300 | ForEach-Object { '10.{0}.{1}.0/24' -f [math]::Floor($_ / 256), ($_ % 256) })
        $r = Get-ChunkAssignment @{} $wanted 500
        $r.Keys.Count | Should -Be 5
        @($r.Values | ForEach-Object { $_ }).Count | Should -Be 2300
        foreach ($k in $r.Keys) { $r[$k].Count | Should -BeLessOrEqual 500 }
    }
}

Describe 'changing the rules in place' {
    It 'writes TCP and UDP rules for each chunk' {
        $d = Get-FirewallDesired @{ Lists = @('192.0.2.0/24'); Bans = @(); Origin = @() } @() @(443, 80) 500
        @($d.Keys) | Should -Be @('AnalyticsAgent-Lists-TCP-001', 'AnalyticsAgent-Lists-UDP-001')
        $d['AnalyticsAgent-Lists-UDP-001'].Ports | Should -Be @(80, 443)
        (Get-FirewallDesired @{ Lists = @('192.0.2.0/24'); Bans = @(); Origin = @() } @() @() 500).Count | Should -Be 0
    }
    It "does nothing when Windows has the rules, in its own way of writing them" {
        $cur = @(
            (New-FwRule 'AnalyticsAgent-Lists-TCP-001' @('192.0.2.0/255.255.255.0', '203.0.113.9', '10.0.0.1-10.0.0.3', '2001:db8::/32')),
            (New-FwRule 'AnalyticsAgent-Lists-UDP-001' @('2001:DB8::/32', '10.0.0.1-10.0.0.3', '192.0.2.0/24', '203.0.113.9/255.255.255.255') @('443', '80') 'UDP'))
        $wanted = @{ Lists = @('192.0.2.0/24', '203.0.113.9', '10.0.0.1-10.0.0.3', '2001:db8::/32'); Bans = @(); Origin = @() }
        $d = Get-FirewallDesired $wanted $cur @(80, 443) 500
        @(Get-FirewallOps $d $cur).Count | Should -Be 0
    }
    It 'sets a changed rule in place, adds new ones, removes emptied ones' {
        $cur = @(
            (New-FwRule 'AnalyticsAgent-Lists-TCP-001' @('192.0.2.0/24')), (New-FwRule 'AnalyticsAgent-Lists-UDP-001' @('192.0.2.0/24') -Protocol 'UDP'),
            (New-FwRule 'AnalyticsAgent-Bans-TCP-001' @('192.0.2.200')), (New-FwRule 'AnalyticsAgent-Bans-UDP-001' @('192.0.2.200') -Protocol 'UDP'))
        $wanted = @{ Lists = @('192.0.2.0/24', '198.51.100.0/24'); Bans = @(); Origin = @('8.0.0.0/8') }
        $ops = @(Get-FirewallOps (Get-FirewallDesired $wanted $cur @(80, 443) 500) $cur)
        @($ops | ForEach-Object { $_.Op + ' ' + $_.Name }) | Should -Be @(
            'Set AnalyticsAgent-Lists-TCP-001', 'Set AnalyticsAgent-Lists-UDP-001',
            'New AnalyticsAgent-Origin-TCP-001', 'New AnalyticsAgent-Origin-UDP-001',
            'Remove AnalyticsAgent-Bans-TCP-001', 'Remove AnalyticsAgent-Bans-UDP-001')
    }
    It 'puts back a rule someone disabled or turned into an allow' {
        $r = New-FwRule 'AnalyticsAgent-Lists-TCP-001' @('192.0.2.0/24'); $r.Enabled = 'False'
        $u = New-FwRule 'AnalyticsAgent-Lists-UDP-001' @('192.0.2.0/24') -Protocol 'UDP'; $u.Action = 'Allow'
        $ops = @(Get-FirewallOps (Get-FirewallDesired @{ Lists = @('192.0.2.0/24'); Bans = @(); Origin = @() } @($r, $u) @(80, 443) 500) @($r, $u))
        @($ops | ForEach-Object { $_.Op }) | Should -Be @('Set', 'Set')
    }
    It 'with -BansOnly, leaves the other kinds alone' {
        $cur = @((New-FwRule 'AnalyticsAgent-Lists-TCP-001' @('192.0.2.0/24')), (New-FwRule 'AnalyticsAgent-Origin-TCP-001' @('8.0.0.0/8')))
        $d = Get-FirewallDesired @{ Bans = @('192.0.2.9') } $cur @(80) 500 @('Bans')
        $ops = @(Get-FirewallOps $d $cur @('Bans'))
        @($ops | ForEach-Object { $_.Op + ' ' + $_.Name }) | Should -Be @('New AnalyticsAgent-Bans-TCP-001', 'New AnalyticsAgent-Bans-UDP-001')
    }
}

Describe 'the firewall layer' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:Written = New-Object System.Collections.ArrayList
        Mock Get-FirewallInfo { return $script:GoodInfo }
        Mock Invoke-FirewallBatch {
            param($Ops)
            foreach ($o in $Ops) { [void]$script:Written.Add($o) }
            return @($Ops | ForEach-Object { @{ Name = $_.Name; Ok = $true; Error = '' } })
        }
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'writes the lists in block mode and reports the layer' {
        Mock Get-FirewallRules { return , @() }
        $a = New-TestAgent $script:Dir (New-Rules)
        Update-Firewall $a 1000 | Should -BeTrue
        @($script:Written | ForEach-Object { $_.Name }) | Should -Be @('AnalyticsAgent-Lists-TCP-001', 'AnalyticsAgent-Lists-UDP-001')
        $a.Running['windows-firewall'] | Should -BeTrue
        $a.Running['origin'] | Should -BeFalse
        @($a.FwCurrent).Count | Should -Be 2
    }
    It 'removes every rule of ours in monitor mode, and does not report the layer' {
        Mock Get-FirewallRules { return , @((New-FwRule 'AnalyticsAgent-Lists-TCP-001' @('192.0.2.0/24')), (New-FwRule 'AnalyticsAgent-Origin-UDP-003' @('8.0.0.0/8') -Protocol 'UDP')) }
        $a = New-TestAgent $script:Dir (New-Rules 'monitor')
        Update-Firewall $a 1000 | Should -BeTrue
        @($script:Written | ForEach-Object { $_.Op }) | Should -Be @('Remove', 'Remove')
        $a.Running['windows-firewall'] | Should -BeFalse
        $a.FwUsable | Should -BeTrue
    }
    It 'reports the origin layer only while its rules are in place' {
        Mock Get-FirewallRules { return , @() }
        $a = New-TestAgent $script:Dir (New-Rules 'block' @{ origin = @{ only = @('173.245.48.0/20') } })
        Update-Firewall $a 1000 | Should -BeTrue
        $a.Running['origin'] | Should -BeTrue
        Mock Invoke-FirewallBatch { param($Ops) return @($Ops | ForEach-Object { @{ Name = $_.Name; Ok = ($_.Name -notmatch 'Origin'); Error = 'access denied' } }) }
        $b = New-TestAgent $script:Dir (New-Rules 'block' @{ origin = @{ only = @('173.245.48.0/20') } })
        Update-Firewall $b 1000 | Should -BeFalse
        $b.Running['origin'] | Should -BeFalse
        $b.Running['windows-firewall'] | Should -BeTrue
    }
    It "changes nothing and reports nothing when the rules can't be read" {
        Mock Get-FirewallRules { return $null }
        $a = New-TestAgent $script:Dir (New-Rules)
        $a.Running['windows-firewall'] = $true
        Update-Firewall $a 1000 | Should -BeFalse
        $script:Written.Count | Should -Be 0
        $a.Running['windows-firewall'] | Should -BeFalse
    }
    It "doesn't report the layer when the firewall is off for the active profile" {
        Mock Get-FirewallRules { return , @() }
        Mock Get-FirewallInfo { return @{ Service = 'Running'; Active = @('Public'); Profiles = @(@{ Name = 'Public'; Enabled = 'False'; AllowLocalFirewallRules = 'True' }) } }
        $a = New-TestAgent $script:Dir (New-Rules)
        [void](Update-Firewall $a 1000)
        $a.Running['windows-firewall'] | Should -BeFalse
        $a.Notes['firewall'] | Should -Match 'off for the Public profile'
    }
    It 'with -BansOnly, works from what it read last and writes only the ban rules' {
        Mock Get-FirewallRules { return , @() }
        $a = New-TestAgent $script:Dir (New-Rules)
        [void](Update-Firewall $a 1000)
        $script:Written.Clear()
        $a.Bans['192.0.2.77'] = @{ rule = 'rate'; first = 990; until = 2000; hits = 99; reported = $false; enforced = $true }
        $a.Bans['192.0.2.78'] = @{ rule = 'rate'; first = 990; until = 2000; hits = 99; reported = $false; enforced = $false }
        $a.Bans['192.0.2.79'] = @{ rule = 'rate'; first = 100; until = 900; hits = 99; reported = $false; enforced = $true }
        Update-Firewall $a 1000 -BansOnly | Should -BeTrue
        Should -Invoke Get-FirewallRules -Times 1 -Exactly
        @($script:Written | ForEach-Object { $_.Name }) | Should -Be @('AnalyticsAgent-Bans-TCP-001', 'AnalyticsAgent-Bans-UDP-001')
        $script:Written[0].Addresses | Should -Be @('192.0.2.77')
    }
    It 'never asks for a rule on a management port, even if configured' {
        Mock Get-FirewallRules { return , @() }
        $a = New-TestAgent $script:Dir (New-Rules)
        $a.Config.ports = @(Get-SafePorts @(443, 3389, 5985))
        [void](Update-Firewall $a 1000)
        foreach ($o in $script:Written) { $o.Ports | Should -Be @(443) }
    }
}

Describe 'whether the firewall enforces' {
    It 'says why not' {
        Test-FirewallEnforces $script:GoodInfo | Should -Be ''
        Test-FirewallEnforces $null | Should -Match "can't be read"
        Test-FirewallEnforces @{ Service = 'Stopped'; Profiles = @(); Active = @() } | Should -Match 'mpssvc'
        Test-FirewallEnforces @{ Service = 'Running'; Active = @(); Profiles = @(@{ Name = 'Domain'; Enabled = 'True'; AllowLocalFirewallRules = 'False' }) } | Should -Match 'group policy'
    }
}
