BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
    function New-Rules([string]$Mode = 'block', [hashtable]$Extra = @{}) {
        $r = @{ v = 1; enabled = $true; mode = $Mode; sync = 120; allow = @('198.51.100.7'); deny = @('203.0.113.0/24'); banned = @(); lists = @(); shared = @()
            goodbots = @('66.249.64.0/27'); flood = @{ req_rate = 2; req_burst = 3; ban = 300; exempt = @('173.245.48.0/20') } }
        foreach ($k in $Extra.Keys) { $r[$k] = $Extra[$k] }
        return $r
    }
}

Describe 'reading the rules' {
    It 'follows the protocol for flood: burst three times the rate, ban 600, exempt with allow, goodbots and local' {
        $p = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":true,"mode":"block","allow":["198.51.100.7"],"goodbots":["66.249.64.0/27"],"flood":{"req_rate":5,"conn_max":30}}')
        $p.block | Should -BeTrue
        $p.flood.req_burst | Should -Be 15
        $p.flood.ban | Should -Be 600
        $p.flood.conn_rate | Should -BeNullOrEmpty
        $s = New-IpSet $p.flood.exempt
        foreach ($ip in '198.51.100.7', '66.249.64.9', '10.9.9.9', '::1', 'fe80::2') { Test-IpSet $s (ConvertTo-IpNumber $ip) | Should -BeTrue -Because $ip }
        Test-IpSet $s (ConvertTo-IpNumber '8.8.8.8') | Should -BeFalse
    }
    It 'takes nothing from a malformed answer' {
        $p = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":"true","mode":"block","flood":{"req_rate":5}}')
        $p.enabled | Should -BeFalse
        $p.block | Should -BeFalse
        $p.flood | Should -BeNullOrEmpty
        $p = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":true,"mode":"BLOCK"}')
        $p.block | Should -BeFalse
        $p = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":true,"mode":"block","flood":{"req_rate":"5","req_burst":-1,"conn_max":2.5,"ban":0}}')
        $p.flood.req_rate | Should -BeNullOrEmpty
        $p.flood.conn_max | Should -BeNullOrEmpty
        $p.flood.ban | Should -Be 600
        $p = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":true,"mode":"block","flood":[1],"origin":"x","challenge":true}')
        $p.flood | Should -BeNullOrEmpty
        $p.origin | Should -BeNullOrEmpty
        $p.challenge | Should -BeNullOrEmpty
    }
    It 'reads one-entry lists as lists' {
        $p = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":true,"mode":"block","lists":["192.0.2.0/24"],"challenge":{"skip":["/api/"],"exempt":["66.249.64.0/27"]}}')
        @($p.list).Count | Should -Be 1
        @($p.challenge.skip) | Should -Be @('/api/')
        @($p.challenge.exempt).Count | Should -Be 1
    }
    It 'keeps only plain path prefixes to skip, lower-cased' {
        $p = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":true,"mode":"block","challenge":{"skip":["/API/","api/","/a b","/a\"b","/x(y)","/ok~%:@,=+-._/",5,"/API/"]}}')
        @($p.challenge.skip) | Should -Be @('/api/', '/ok~%:@,=+-._/')
    }
    It 'locks to the origin with allow added, and ignores an origin with no valid range' {
        $p = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":true,"mode":"block","allow":["198.51.100.7"],"origin":{"only":["173.245.48.0/20"]}}')
        @($p.origin.only).Count | Should -Be 2
        (Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":true,"mode":"block","origin":{"only":["nope"]}}')).origin | Should -BeNullOrEmpty
    }
    It 'turns everything off with the firewall off' {
        $p = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":false,"mode":"block","deny":["1.2.3.4"],"flood":{"req_rate":5},"challenge":{}}')
        $p.flood | Should -BeNullOrEmpty
        $p.challenge | Should -BeNullOrEmpty
        $p.block | Should -BeFalse
    }
}

Describe 'talking to the collector' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:Calls = New-Object System.Collections.ArrayList
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'sends the layers, the server name, the ETag and the user agent' {
        Mock Invoke-Collector {
            param($Config, $Method, $PathAndQuery, $Body, $Headers, $UserAgent)
            [void]$script:Calls.Add(@{ Method = $Method; Path = $PathAndQuery; Headers = $Headers; Ua = $UserAgent })
            return @{ Status = 304; Headers = @{}; Body = '' }
        }
        $a = New-TestAgent $script:Dir (New-Rules)
        $a.ETag = '"abc"'
        $a.Running['windows-firewall'] = $true; $a.Running['iis-check'] = $true
        Invoke-RulesFetch $a
        $c = $script:Calls[0]
        $c.Path | Should -Be '/events/firewall/rules?site_id=aaaaaaaaaaaaaaaaaaaaaaaa'
        $c.Headers['X-Firewall-Layers'] | Should -Be 'windows-firewall iis-check'
        $c.Headers['If-None-Match'] | Should -Be '"abc"'
        $c.Headers['X-Server-Name'] | Should -Not -BeNullOrEmpty
        $c.Ua | Should -Be 'analytics-platform-agent-windows/0.3.0 (windows; no-rate)'
        $a.Running['logs'] = $true
        Get-AgentUserAgent $a | Should -Be 'analytics-platform-agent-windows/0.3.0 (windows)'
        $a.Rules.v | Should -Be 1
    }
    It 'takes new rules with their ETag, and keeps the old on an unknown version, bad JSON or an error' {
        $script:Answer = @{ Status = 200; Headers = @{ etag = '"v2"' }; Body = (ConvertTo-Json -Depth 5 -Compress (New-Rules 'monitor')) }
        Mock Invoke-Collector { return $script:Answer }
        $a = New-TestAgent $script:Dir (New-Rules)
        Invoke-RulesFetch $a
        $a.Rules.mode | Should -Be 'monitor'
        $a.ETag | Should -Be '"v2"'
        foreach ($bad in @(
                @{ Status = 200; Headers = @{}; Body = '{"v":2,"enabled":false}' },
                @{ Status = 200; Headers = @{}; Body = '{"v":"1","enabled":false}' },
                @{ Status = 200; Headers = @{}; Body = 'not json' },
                @{ Status = 500; Headers = @{}; Body = '' },
                @{ Status = 0; Headers = @{}; Body = '' })) {
            $script:Answer = $bad
            Invoke-RulesFetch $a
            $a.Rules.mode | Should -Be 'monitor'
            $a.ETag | Should -Be '"v2"'
        }
    }
    It 'groups events into rows with hits, at most 2,000 waiting, sent 200 at a time' {
        Mock Invoke-Collector {
            param($Config, $Method, $PathAndQuery, $Body)
            [void]$script:Calls.Add(@{ Path = $PathAndQuery; Body = $Body })
            return @{ Status = 202; Headers = @{}; Body = '' }
        }
        $a = New-TestAgent $script:Dir (New-Rules)
        for ($i = 0; $i -lt 5; $i++) { Add-AgentEvent $a '192.0.2.1' 'deny' 'monitor' 'GET' '/x' 'curl' 1 1000 }
        Add-AgentEvent $a '192.0.2.1' 'deny' 'monitor' 'GET' '/y' 'curl' 1 1000
        $a.Events.Count | Should -Be 2
        for ($i = 0; $i -lt 2500; $i++) { Add-AgentEvent $a ('10.0.{0}.{1}' -f [math]::Floor($i / 256), ($i % 256)) 'rate' 'block' '' '' '' 1 1000 }
        $a.Events.Count | Should -Be 2000
        Add-AgentEvent $a '192.0.2.1' 'deny' 'monitor' 'GET' ('/' + ('a' * 400)) '' 1 1000
        $a.Events.Count | Should -Be 2000
        Send-AgentEvents $a
        $script:Calls.Count | Should -Be 10
        $script:Calls[0].Path | Should -Be '/events/firewall/events'
        $script:Calls[0].Body.site_id | Should -Be 'aaaaaaaaaaaaaaaaaaaaaaaa'
        @($script:Calls[0].Body.events).Count | Should -Be 200
        $row = @($script:Calls | ForEach-Object { $_.Body.events } | Where-Object { $_.path -eq '/x' })[0]
        $row.hits | Should -Be 5
        $row.at | Should -Be '1970-01-01T00:16:40.000Z'
        @($row.Keys) | Should -Be @('at', 'ip', 'rule', 'action', 'method', 'path', 'user_agent', 'hits')
        $a.Events.Count | Should -Be 0
    }
    It 'cuts a path to 300 characters' {
        $a = New-TestAgent $script:Dir (New-Rules)
        Add-AgentEvent $a '192.0.2.1' 'deny' 'monitor' 'GET' ('/' + ('a' * 400)) '' 1 1000
        @($a.Events.Values)[0].path.Length | Should -Be 300
    }
}

Describe 'the page limit and the logs' {
    BeforeEach {
        $script:Dir = New-TestDir
        Mock Update-Firewall { return $true }
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'in block mode, bans an address over the limit and reports it once as rate, blocked' {
        $a = New-TestAgent $script:Dir (New-Rules)
        $a.FwUsable = $true
        for ($i = 0; $i -lt 4; $i++) { Invoke-LogEntry $a (New-LogEntry '192.0.2.50' '/p' 200 0 1000) 1000 }
        $a.Bans.Count | Should -Be 0
        Invoke-LogEntry $a (New-LogEntry '192.0.2.50' '/p' 200 0 1000) 1000
        $a.Bans['192.0.2.50'].rule | Should -Be 'rate'
        $a.Bans['192.0.2.50'].enforced | Should -BeTrue
        $a.Bans['192.0.2.50'].until | Should -Be 1300
        for ($i = 0; $i -lt 20; $i++) { Invoke-LogEntry $a (New-LogEntry '192.0.2.50' '/p' 200 0 1001) 1001 }
        Get-DueBans $a 1005
        $a.Events.Count | Should -Be 0
        Get-DueBans $a 1010
        $row = @($a.Events.Values)[0]
        $row.rule | Should -Be 'rate'; $row.action | Should -Be 'block'; $row.ip | Should -Be '192.0.2.50'; $row.hits | Should -Be 21
        $a.Events.Clear()
        Get-DueBans $a 1200
        $a.Events.Count | Should -Be 0
        Get-DueBans $a 1303
        $a.Bans.Count | Should -Be 0
    }
    It 'in monitor mode, bans nothing and reports once per ban period' {
        $a = New-TestAgent $script:Dir (New-Rules 'monitor')
        $a.FwUsable = $true
        for ($i = 0; $i -lt 30; $i++) { Invoke-LogEntry $a (New-LogEntry '192.0.2.51' '/p' 200 0 1000) 1000 }
        $a.Bans['192.0.2.51'].enforced | Should -BeFalse
        Get-EnforcedBanKeys $a 1001 | Should -BeNullOrEmpty
        Get-DueBans $a 1010
        @($a.Events.Values | Where-Object { $_.rule -eq 'rate' })[0].action | Should -Be 'monitor'
        $a.Events.Clear()
        for ($i = 0; $i -lt 30; $i++) { Invoke-LogEntry $a (New-LogEntry '192.0.2.51' '/p' 200 0 1100) 1100 }
        Get-DueBans $a 1200
        $a.Events.Count | Should -Be 0
        Get-DueBans $a 1303
        for ($i = 0; $i -lt 30; $i++) { Invoke-LogEntry $a (New-LogEntry '192.0.2.51' '/p' 200 0 1400) 1400 }
        Get-DueBans $a 1410
        $a.Events.Count | Should -Be 1
    }
    It 'counts an IPv6 /64 as one, and never exempt, static or allowed addresses' {
        $a = New-TestAgent $script:Dir (New-Rules)
        $a.FwUsable = $true
        for ($i = 1; $i -le 6; $i++) { Invoke-LogEntry $a (New-LogEntry ('2001:db8:1:2::' + $i) '/p' 200 0 1000) 1000 }
        $a.Bans.ContainsKey('2001:db8:1:2::/64') | Should -BeTrue
        foreach ($ip in '173.245.48.9', '66.249.64.3', '198.51.100.7', '10.1.1.1', '127.0.0.1') {
            for ($i = 0; $i -lt 30; $i++) { Invoke-LogEntry $a (New-LogEntry $ip '/p' 200 0 1000) 1000 }
        }
        for ($i = 0; $i -lt 30; $i++) { Invoke-LogEntry $a (New-LogEntry '192.0.2.60' '/app.JS' 200 0 1000) 1000 }
        $a.Bans.Count | Should -Be 1
    }
    It "follows the log's own time, so a backlog read at once is not a flood" {
        $a = New-TestAgent $script:Dir (New-Rules)
        $a.FwUsable = $true
        for ($i = 0; $i -lt 60; $i++) { Invoke-LogEntry $a (New-LogEntry '192.0.2.61' '/p' 200 0 (1000 + $i)) 2000 }
        $a.Bans.Count | Should -Be 0
    }
    It "reports what IIS's limits turned away as flood, monitor, and bans nothing for it" {
        $a = New-TestAgent $script:Dir (New-Rules)
        $a.FwUsable = $true
        Invoke-LogEntry $a (New-LogEntry '192.0.2.70' '/p' 403 501 1000) 1000
        Invoke-LogEntry $a (New-LogEntry '192.0.2.70' '/p' 403 501 1001) 1001
        Invoke-LogEntry $a (New-LogEntry '192.0.2.71' '/p' 403 502 1000) 1000
        Invoke-LogEntry $a (New-LogEntry '173.245.48.1' '/p' 403 502 1000) 1000
        Invoke-LogEntry $a (New-LogEntry '192.0.2.72' '/p' 403 0 1000) 1000
        $a.Bans.Count | Should -Be 0
        $a.IisDenied.Count | Should -Be 2
        Get-DueBans $a 1011
        $rows = @($a.Events.Values)
        $rows.Count | Should -Be 2
        foreach ($r in $rows) { $r.rule | Should -Be 'flood'; $r.action | Should -Be 'monitor' }
        @($rows | Where-Object { $_.ip -eq '192.0.2.70' })[0].hits | Should -Be 2
        $a.Events.Clear()
        Get-DueBans $a 1200
        $a.Events.Count | Should -Be 0
        Get-DueBans $a 1301
        $a.IisDenied.Count | Should -Be 0
        # The page limit still bans the same address for its own reason.
        for ($i = 0; $i -lt 6; $i++) { Invoke-LogEntry $a (New-LogEntry '192.0.2.71' '/p' 200 0 1000) 1000 }
        $a.Bans['192.0.2.71'].rule | Should -Be 'rate'
        $m = New-TestAgent $script:Dir (New-Rules 'monitor')
        Invoke-LogEntry $m (New-LogEntry '192.0.2.70' '/p' 403 501 1000) 1000
        $m.IisDenied.Count | Should -Be 0
    }
    It 'in monitor mode, reports list matches and visitors outside the origin, not in block mode' {
        $rules = New-Rules 'monitor' @{ shared = @('192.0.2.0/24'); origin = @{ only = @('173.245.48.0/20') } }
        $a = New-TestAgent $script:Dir $rules
        Invoke-LogEntry $a (New-LogEntry '203.0.113.5' '/login' 200 0 1000) 1000
        Invoke-LogEntry $a (New-LogEntry '203.0.113.5' '/login' 200 0 1000) 1000
        Invoke-LogEntry $a (New-LogEntry '192.0.2.5' '/' 200 0 1000) 1000
        Invoke-LogEntry $a (New-LogEntry '173.245.48.5' '/' 200 0 1000) 1000
        Invoke-LogEntry $a (New-LogEntry '198.51.100.7' '/' 200 0 1000) 1000
        $rows = @($a.Events.Values)
        @($rows | Where-Object { $_.rule -eq 'deny' })[0].hits | Should -Be 2
        @($rows | Where-Object { $_.rule -eq 'deny' })[0].path | Should -Be '/login'
        @($rows | Where-Object { $_.rule -eq 'shared' }).Count | Should -Be 1
        @($rows | Where-Object { $_.rule -eq 'origin' } | ForEach-Object { $_.ip }) | Sort-Object | Should -Be @('192.0.2.5', '203.0.113.5')
        @($rows | Where-Object { $_.ip -eq '198.51.100.7' }).Count | Should -Be 0
        $b = New-TestAgent $script:Dir (New-Rules 'block' @{ origin = @{ only = @('173.245.48.0/20') } })
        Invoke-LogEntry $b (New-LogEntry '203.0.113.5' '/login' 200 0 1000) 1000
        $b.Events.Count | Should -Be 0
    }
    It "counts the browser check's 503s per address and reports the busiest" {
        $a = New-TestAgent $script:Dir (New-Rules 'block' @{ challenge = @{ skip = @(); exempt = @() } })
        for ($i = 0; $i -lt 3; $i++) { Invoke-LogEntry $a (New-LogEntry '192.0.2.80' '/' 503 71 1000) 1000 }
        Invoke-LogEntry $a (New-LogEntry '192.0.2.81' '/' 503 71 1000) 1000
        Invoke-LogEntry $a (New-LogEntry '192.0.2.82' '/' 503 0 1000) 1000
        $a.Challenged['192.0.2.80'] | Should -Be 3
        $a.Challenged.Count | Should -Be 2
        $a.Bans.Count | Should -Be 0
        Mock Send-AgentEvents { }
        Invoke-AgentTick $a 1000
        $row = @($a.Events.Values | Where-Object { $_.ip -eq '192.0.2.80' })[0]
        $row.rule | Should -Be 'challenge'; $row.action | Should -Be 'block'; $row.hits | Should -Be 3
        $a.Challenged.Count | Should -Be 0
    }
    It 'keeps its caches bounded' {
        $a = New-TestAgent $script:Dir (New-Rules)
        $a.FwUsable = $true
        $script:BansMax = 50; $script:ClassCacheMax = 40
        try {
            for ($i = 0; $i -lt 120; $i++) {
                $ip = '192.0.{0}.{1}' -f [math]::Floor($i / 200), ($i % 200)
                for ($k = 0; $k -lt 6; $k++) { Invoke-LogEntry $a (New-LogEntry $ip '/p' 200 0 (1000 + $i)) (1000 + $i) }
            }
            $a.Bans.Count | Should -BeLessOrEqual 50
            $a.ClassCache.Count | Should -BeLessOrEqual 40
        } finally { $script:BansMax = 10000; $script:ClassCacheMax = 20000 }
    }
}

Describe 'the bans across rounds and restarts' {
    BeforeEach { $script:Dir = New-TestDir }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'writes the ban rules when the bans change, once' {
        $script:Fw = 0
        Mock Update-Firewall { param($Agent, $Now, [switch]$BansOnly) if ($BansOnly) { $script:Fw++ }; return $true }
        Mock Send-AgentEvents { }
        $a = New-TestAgent $script:Dir (New-Rules)
        $a.FwUsable = $true
        $a.BansApplied = ''
        Invoke-AgentTick $a 1000
        $script:Fw | Should -Be 0
        for ($i = 0; $i -lt 6; $i++) { Invoke-LogEntry $a (New-LogEntry '192.0.2.90' '/p' 200 0 1000) 1000 }
        Invoke-AgentTick $a 1001
        $script:Fw | Should -Be 1
        Invoke-AgentTick $a 1002
        $script:Fw | Should -Be 1
        Invoke-AgentTick $a 1400
        $script:Fw | Should -Be 2
    }
    It 'keeps bans over a restart, and drops broken ones' {
        $a = New-TestAgent $script:Dir (New-Rules)
        $a.Bans['192.0.2.91'] = @{ rule = 'rate'; first = 1000; until = 99999999999; hits = 4; reported = $true; enforced = $true }
        Save-AgentBans $a
        $text = [IO.File]::ReadAllText($a.BansFile)
        [IO.File]::WriteAllText($a.BansFile, $text.Replace('}}}', '},"x":{"rule":"rate","first":"soon","until":1,"hits":1},"y":5}}'))
        $b = New-TestAgent $script:Dir (New-Rules)
        @($b.Bans.Keys) | Should -Be @('192.0.2.91')
        $b.Bans['192.0.2.91'].enforced | Should -BeTrue
    }
    It 'saves its state over the old one (File.Replace with no backup)' {
        $a = New-TestAgent $script:Dir (New-Rules)
        Save-AgentState $a
        $a.ETag = '"two"'
        Save-AgentState $a
        (ConvertFrom-Json ([IO.File]::ReadAllText($a.StateFile))).etag | Should -Be '"two"'
        @(Get-ChildItem $a.Config.state_dir -Filter '*.tmp*').Count | Should -Be 0
    }
}

Describe 'one round' {
    BeforeEach {
        $script:Dir = New-TestDir
        Mock Invoke-Collector { return @{ Status = 200; Headers = @{ etag = '"e"' }; Body = (ConvertTo-Json -Depth 5 -Compress (New-Rules 'monitor' @{ origin = @{ only = @('173.245.48.0/20') } })) } }
        Mock Get-FirewallRules { return , @() }
        Mock Get-FirewallInfo { return @{ Service = 'Running'; Active = @(); Profiles = @(@{ Name = 'Public'; Enabled = 'True'; AllowLocalFirewallRules = 'True' }) } }
        Mock Invoke-FirewallBatch { param($Ops) return @($Ops | ForEach-Object { @{ Name = $_.Name; Ok = $true; Error = '' } }) }
        Mock Get-IisSnapshot { return @{ Installed = $false; Error = ''; Modules = @(); Paths = @(); LogDirs = @() } }
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'reports the monitor-mode layers only once a log has been read' {
        $logs = Join-Path $script:Dir 'W3SVC1'
        New-Item -ItemType Directory -Path $logs | Out-Null
        $a = New-TestAgent $script:Dir
        $a.Config.iis_log_dirs = @($logs)
        Invoke-AgentStep $a 1000 | Should -Be 120
        $a.Running['windows-firewall'] | Should -BeFalse
        $a.Running['origin'] | Should -BeFalse
        $a.Running['logs'] | Should -BeFalse
        [IO.File]::WriteAllText((Join-Path $logs 'u_ex261103.log'), "#Software: Microsoft Internet Information Services 10.0`r`n#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-substatus`r`n")
        Mock Send-AgentEvents { }
        Invoke-AgentTick $a 1001
        [void](Invoke-AgentStep $a 1100)
        $a.Running['windows-firewall'] | Should -BeTrue
        $a.Running['origin'] | Should -BeTrue
        $a.Running['logs'] | Should -BeTrue
        $a.Running['iis'] | Should -BeFalse
        $a.Running['iis-check'] | Should -BeFalse
        (ConvertFrom-Json ([IO.File]::ReadAllText($a.StateFile))).etag | Should -Be '"e"'
    }
    It 'waits and changes nothing with no rules yet' {
        Mock Invoke-Collector { return @{ Status = 0; Headers = @{}; Body = '' } }
        $a = New-TestAgent $script:Dir
        Invoke-AgentStep $a 1000 | Should -Be 60
        Should -Invoke Get-FirewallRules -Times 0 -Exactly
    }
}

Describe 'the config file' {
    BeforeEach { $script:Dir = New-TestDir; $script:Path = Join-Path $script:Dir 'config.json' }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'fills in the defaults and drops management ports' {
        [IO.File]::WriteAllText($script:Path, '{"site_id":"AAAAAAAAAAAAAAAAAAAAAAAA","secret":"abcDEF123456","endpoint":"https://c.example","ports":[443,3389],"logs":"yes","firewall_chunk":5000}')
        $c = Read-AgentConfig $script:Path
        $c.site_id | Should -Be 'aaaaaaaaaaaaaaaaaaaaaaaa'
        $c.ports | Should -Be @(443)
        $c.logs | Should -BeTrue
        $c.firewall_chunk | Should -Be 500
        $c.check_substatus | Should -Be 71
        $c.state_dir | Should -Be (Join-Path $script:Dir 'state')
        Test-Path $c.state_dir | Should -BeTrue
    }
    It 'refuses a config without a usable site, secret or endpoint' {
        foreach ($bad in '{"site_id":"x","secret":"abcDEF123456","endpoint":"https://c.example"}',
            '{"site_id":"aaaaaaaaaaaaaaaaaaaaaaaa","secret":"abc-DEF-123456","endpoint":"https://c.example"}',
            '{"site_id":"aaaaaaaaaaaaaaaaaaaaaaaa","secret":"abcDEF123456","endpoint":"c.example"}',
            'not json') {
            [IO.File]::WriteAllText($script:Path, $bad)
            { Read-AgentConfig $script:Path } | Should -Throw
        }
        { Read-AgentConfig (Join-Path $script:Dir 'none.json') } | Should -Throw
    }
}
