# What makes the agent safe to leave running: clearing up, IIS changes that
# check themselves, the origin lock's exceptions, the config's folders.
BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
    function New-Rules([string]$Mode = 'block', [hashtable]$Extra = @{}) {
        $r = @{ v = 1; enabled = $true; mode = $Mode; allow = @('198.51.100.7'); goodbots = @()
            flood = @{ req_rate = 2; req_burst = 3; ban = 300; exempt = @('173.245.48.0/20') } }
        foreach ($k in $Extra.Keys) { $r[$k] = $Extra[$k] }
        return $r
    }
    function New-Snap([hashtable]$Extra = @{}) {
        $s = @{ Installed = $true; Error = ''; Modules = @('IpRestrictionModule', 'RewriteModule')
            Dipr = @{ denyAction = 'Forbidden'; enableLoggingOnlyMode = $false; rateEnabled = $false; maxRequests = 20; intervalMs = 200; concEnabled = $false; maxConcurrent = 5 }
            IpSecurity = @{ AllowUnlisted = $true; Entries = @() }
            GlobalRules = @(); OutboundRules = @(); PreConditions = @(); ServerVariables = @(); HttpErrors = @(); Paths = @(); LogDirs = @()
            Sites = @(@{ Id = '1'; Name = 'A'; State = 'Started'; Bindings = @(@{ Protocol = 'http'; Ip = '*'; Port = 80; Host = '' }) }) }
        foreach ($k in $Extra.Keys) { $s[$k] = $Extra[$k] }
        return $s
    }
    function New-Path([string]$Id, [string[]]$HttpErrors) {
        return @{ Site = 'A'; SiteId = $Id; Path = '/'; ErrorMode = 'Custom'; ExistingResponse = 'Auto'; HttpErrors = $HttpErrors; Csp = '' }
    }
    function Get-FullSnap($Agent) {
        $page = Join-Path $Agent.Config.page_dir 'check.html'
        $mine = Get-HttpErrorKey 503 $Agent.Config.check_substatus $page
        return New-Snap @{ HttpErrors = @($mine); ServerVariables = @('SG_CHECK'); PreConditions = @('AnalyticsAgent-Check')
            OutboundRules = @('AnalyticsAgent-Check-Cache', 'AnalyticsAgent-Check-Robots', 'AnalyticsAgent-Check-Csp'); Paths = @((New-Path '1' @($mine))) }
    }
}

Describe 'clear' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:CommitOk = $true
        $script:Commits = New-Object System.Collections.ArrayList
        Mock Get-FirewallRules { return , @([pscustomobject]@{ Name = 'AnalyticsAgent-Lists-TCP-001' }) }
        Mock Invoke-FirewallBatch { param($Ops) return @($Ops | ForEach-Object { @{ Name = $_.Name; Ok = $true; Error = '' } }) }
        Mock Invoke-IisCommit { param($Changes, $Agent) if ($script:CommitOk) { [void]$script:Commits.Add(@($Changes)) }; return $script:CommitOk }
        $script:A = New-TestAgent $script:Dir (New-Rules)
        $script:Page = Join-Path $script:A.Config.page_dir 'check.html'
        Write-TextFile $script:Page 'page'
        $script:A.Iis.dipr_ours = $true
        $script:A.Iis.dipr_original = @{ denyAction = 'Forbidden'; enableLoggingOnlyMode = $false; rateEnabled = $true; maxRequests = 77; intervalMs = 200; concEnabled = $false; maxConcurrent = 5 }
        $script:A.Iis.check_page = $script:Page
        Save-AgentState $script:A
        $script:Snap = New-Snap @{ GlobalRules = @('AnalyticsAgent-Check'); HttpErrors = @((Get-HttpErrorKey 503 71 $script:Page)) }
        Mock Get-IisSnapshot { return $script:Snap }
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It "keeps the page and the state, and fails, when IIS can't be changed" {
        $script:CommitOk = $false
        Invoke-AgentClear $script:A | Should -Be 1
        Test-Path $script:Page | Should -BeTrue
        Test-Path $script:A.StateFile | Should -BeTrue
        (ConvertFrom-Json ([IO.File]::ReadAllText($script:A.StateFile))).iis.dipr_original.maxRequests | Should -Be 77
    }
    It "keeps them, and fails, when IIS's configuration can't be read or the firewall can't" {
        $script:Snap = New-Snap @{ Error = 'locked' }
        Invoke-AgentClear $script:A | Should -Be 1
        Test-Path $script:Page | Should -BeTrue
        $script:Snap = New-Snap
        Mock Get-FirewallRules { return $null }
        Invoke-AgentClear $script:A | Should -Be 1
        Test-Path $script:A.StateFile | Should -BeTrue
    }
    It 'takes everything out, then the page and the state, and succeeds' {
        $script:A.Iis.deny_added = @('192.0.2.9|255.255.255.255')
        $script:Snap.IpSecurity.Entries = @('192.0.2.9|255.255.255.255')
        Invoke-AgentClear $script:A | Should -Be 0
        $ops = @($script:Commits[0])
        @($ops | Where-Object { $_.Section -eq 'system.webServer/rewrite/globalRules' }).Count | Should -Be 1
        @($ops | Where-Object { $_.Section -eq 'system.webServer/httpErrors' }).Count | Should -Be 1
        @($ops | Where-Object { $_.Child -eq 'denyByRequestRate' })[0].Attrs.maxRequests | Should -Be 77
        @($ops | Where-Object { $_.Key.ipAddress -eq '192.0.2.9' }).Count | Should -Be 1
        Test-Path $script:Page | Should -BeFalse
        Test-Path $script:A.StateFile | Should -BeFalse
    }
    It 'clears with the default folders when the config is missing or broken' {
        $cfgPath = Join-Path $script:Dir 'config.json'
        [IO.File]::WriteAllText($cfgPath, '{"site_id":"broken", "check_substatus": 71')
        $code = @(Invoke-AgentMain 'clear' $cfgPath)
        $code[$code.Count - 1] | Should -Be 0
        @($script:Commits[0] | Where-Object { $_.Section -eq 'system.webServer/rewrite/globalRules' }).Count | Should -Be 1
        @($script:Commits[0] | Where-Object { $_.Child -eq 'denyByRequestRate' })[0].Attrs.maxRequests | Should -Be 77
        Test-Path $script:Page | Should -BeFalse
        Should -Invoke Invoke-FirewallBatch -Times 1
        (Get-FallbackConfig $cfgPath).check_substatus | Should -Be 71
    }
    It 'refuses once and clear while the agent runs, and runs again when it stops' {
        $cfgPath = Join-Path $script:Dir 'config.json'
        [IO.File]::WriteAllText($cfgPath, '{"site_id":"aaaaaaaaaaaaaaaaaaaaaaaa","secret":"abcDEF123456","endpoint":"https://127.0.0.1:1"}')
        $held = New-Object System.Threading.ManualResetEvent $false
        $done = New-Object System.Threading.ManualResetEvent $false
        $ps = [powershell]::Create().AddScript({
                param($held, $done)
                $m = New-Object System.Threading.Mutex($false, 'Global\AnalyticsAgentWindows')
                if (-not $m.WaitOne(5000)) { return }; [void]$held.Set(); [void]$done.WaitOne(10000); $m.ReleaseMutex() }).AddArgument($held).AddArgument($done)
        $h = $ps.BeginInvoke()
        try {
            $held.WaitOne(5000) | Should -BeTrue
            $code = @(Invoke-AgentMain 'clear' $cfgPath); $code[$code.Count - 1] | Should -Be 1
            $code = @(Invoke-AgentMain 'once' $cfgPath); $code[$code.Count - 1] | Should -Be 1
            $script:Commits.Count | Should -Be 0
        } finally { [void]$done.Set(); [void]$ps.EndInvoke($h); $ps.Dispose() }
        $code = @(Invoke-AgentMain 'clear' $cfgPath); $code[$code.Count - 1] | Should -Be 0
    }
}

Describe 'backups of IIS configuration' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:Ah = Join-Path $script:Dir 'applicationHost.config'
        [IO.File]::WriteAllText($script:Ah, '<configuration>original</configuration>')
        Mock Get-IisConfigFile { return $script:Ah }
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It "keeps the copy from before the agent's first change for good, and the last 10 others" {
        $a = New-TestAgent $script:Dir
        for ($i = 0; $i -lt 14; $i++) {
            [void](Backup-IisConfig $a)
            [IO.File]::WriteAllText($script:Ah, "<configuration>change $i</configuration>")
            Start-Sleep -Milliseconds 3
        }
        $dir = Join-Path $a.Config.state_dir 'iis-backups'
        [IO.File]::ReadAllText((Join-Path $dir 'applicationHost-before-agent.config')) | Should -Be '<configuration>original</configuration>'
        @(Get-ChildItem $dir -Filter 'applicationHost-2*.config').Count | Should -Be 10
    }
}

Describe 'an IIS change that checks itself' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:Ah = Join-Path $script:Dir 'applicationHost.config'
        [IO.File]::WriteAllText($script:Ah, 'before')
        Mock Get-IisConfigFile { return $script:Ah }
        # Just enough of Microsoft.Web.Administration for one attribute change.
        $section = New-Object psobject
        $section | Add-Member ScriptMethod SetAttributeValue { param($k, $v) [IO.File]::WriteAllText($script:Ah, 'after') }
        $ah = New-Object psobject
        $ah | Add-Member NoteProperty Section $section
        $ah | Add-Member ScriptMethod GetSection { param($s) return $this.Section }
        $script:Sm = New-Object psobject
        $script:Sm | Add-Member NoteProperty Ah $ah
        $script:Sm | Add-Member ScriptMethod GetApplicationHostConfiguration { return $this.Ah }
        $script:Sm | Add-Member ScriptMethod CommitChanges { }
        $script:Sm | Add-Member ScriptMethod Dispose { }
        Mock Get-IisServerManager { return $script:Sm }
        Mock Start-Sleep { }
        $script:A = New-TestAgent $script:Dir
        $script:A.ProbeTargets = @(@{ Url = 'http://127.0.0.1:80/'; Host = 'localhost' })
        $script:Change = @(@{ Op = 'Set'; Section = 'system.webServer/security/dynamicIpSecurity'; Child = ''; Attrs = [ordered]@{ denyAction = 'Forbidden' } })
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'puts the backup back when a site that answered now answers 500' {
        $script:Probes = 0
        Mock Invoke-LocalProbe { $script:Probes++; if ($script:Probes -eq 1) { return @{ Status = 200; Body = 'ok' } }; return @{ Status = 500; Body = 'HTTP Error 500.19 - Internal Server Error' } }
        Invoke-IisCommit $script:Change $script:A | Should -BeFalse
        [IO.File]::ReadAllText($script:Ah) | Should -Be 'before'
    }
    It 'keeps the change when the site answers as before' {
        Mock Invoke-LocalProbe { return @{ Status = 200; Body = 'ok' } }
        Invoke-IisCommit $script:Change $script:A | Should -BeTrue
        [IO.File]::ReadAllText($script:Ah) | Should -Be 'after'
    }
    It "doesn't blame the change for a site already broken, nor probe with -NoProbe" {
        Mock Invoke-LocalProbe { return @{ Status = 500; Body = '' } }
        Invoke-IisCommit $script:Change $script:A | Should -BeTrue
        Invoke-IisCommit $script:Change $script:A -NoProbe | Should -BeTrue
        Should -Invoke Invoke-LocalProbe -Times 2 -Exactly
    }
    It 'tells a configuration error from a page' {
        Test-ProbeBroken @{ Status = 200; Body = '' } @{ Status = 500; Body = '' } | Should -BeTrue
        Test-ProbeBroken @{ Status = 302; Body = '' } @{ Status = 200; Body = '<h3>HTTP Error 500.52 - URL Rewrite Module Error.</h3>' } | Should -BeTrue
        Test-ProbeBroken @{ Status = 200; Body = '' } @{ Status = 503; Body = '' } | Should -BeFalse
        Test-ProbeBroken @{ Status = 0; Body = '' } @{ Status = 0; Body = '' } | Should -BeFalse
        Test-ProbeBroken @{ Status = 500; Body = '' } @{ Status = 500; Body = '' } | Should -BeFalse
    }
    It 'probes one started site per binding on the web ports' {
        $snap = New-Snap @{ Sites = @(
                @{ Id = '1'; Name = 'A'; State = 'Started'; Bindings = @(@{ Protocol = 'https'; Ip = '*'; Port = 443; Host = 'a.example' }, @{ Protocol = 'http'; Ip = '10.0.0.5'; Port = 80; Host = 'a.example' }) },
                @{ Id = '2'; Name = 'B'; State = 'Stopped'; Bindings = @(@{ Protocol = 'http'; Ip = '*'; Port = 80; Host = '' }) },
                @{ Id = '3'; Name = 'C'; State = 'Started'; Bindings = @(@{ Protocol = 'https'; Ip = '*'; Port = 443; Host = '' }) },
                @{ Id = '4'; Name = 'D'; State = 'Started'; Bindings = @(@{ Protocol = 'http'; Ip = '*'; Port = 8530; Host = '' }) }) }
        $t = @(Get-ProbeTargets $snap @(80, 443))
        $t.Count | Should -Be 2
        $t[0].Url | Should -Be 'http://10.0.0.5:80/'; $t[0].Host | Should -Be 'a.example'
        $t[1].Url | Should -Be 'https://127.0.0.1:443/'; $t[1].Host | Should -Be 'localhost'
    }
}

Describe 'bans refused by IIS too' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:Commits = New-Object System.Collections.ArrayList
        Mock Invoke-IisCommit { param($Changes, $Agent, [switch]$NoProbe) [void]$script:Commits.Add(@{ Changes = @($Changes); NoProbe = [bool]$NoProbe }); return $true }
        $script:A = New-TestAgent $script:Dir (New-Rules)
        $script:A.FwUsable = $true
        foreach ($ip in '192.0.2.1', '192.0.2.2', '2001:db8:1:2::/64') { $script:A.Bans[$ip] = @{ rule = 'rate'; first = 900; until = 2000; hits = 9; reported = $false; enforced = $true } }
        $script:A.Bans['192.0.2.3'] = @{ rule = 'rate'; first = 900; until = 2000; hits = 9; reported = $false; enforced = $false }
        $script:A.LastSnap = New-Snap @{ IpSecurity = @{ AllowUnlisted = $true; Entries = @('192.0.2.2|255.255.255.255') } }
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'adds IPv4 bans in force as deny entries, last, never one the owner has' {
        Update-IisBans $script:A 1000
        $c = @($script:Commits[0].Changes)
        $c.Count | Should -Be 1
        $c[0].Op | Should -Be 'Add'; $c[0].Index | Should -Be -1
        $c[0].Item.Attrs.ipAddress | Should -Be '192.0.2.1'; $c[0].Item.Attrs.allowed | Should -BeFalse
        $script:Commits[0].NoProbe | Should -BeTrue
        $script:A.Iis.deny_added | Should -Be @('192.0.2.1|255.255.255.255')
        $script:A.LastSnap.IpSecurity.Entries | Should -Contain '192.0.2.1|255.255.255.255'
    }
    It 'takes its own entries away when the bans end, not the owner one' {
        Update-IisBans $script:A 1000
        $script:Commits.Clear()
        Update-IisBans $script:A 3000
        $c = @($script:Commits[0].Changes)
        $c.Count | Should -Be 1
        $c[0].Op | Should -Be 'Remove'; $c[0].Key.ipAddress | Should -Be '192.0.2.1'
        @($script:A.Iis.deny_added).Count | Should -Be 0
    }
    It "does nothing where IIS's IP restrictions aren't there, and keeps to the cap" {
        $script:A.LastSnap = New-Snap @{ Modules = @('RewriteModule'); IpSecurity = $null }
        Update-IisBans $script:A 1000
        $script:Commits.Count | Should -Be 0
        $script:A.LastSnap = New-Snap
        for ($i = 0; $i -lt 700; $i++) { $script:A.Bans[('10.9.{0}.{1}' -f [math]::Floor($i / 250), ($i % 250))] = @{ rule = 'rate'; first = 900; until = 2000 + $i; hits = 1; reported = $false; enforced = $true } }
        Update-IisBans $script:A 1000
        @($script:Commits[0].Changes).Count | Should -Be 500
    }
    It 'is written from the tick when the bans change, at most every 30 seconds' {
        Mock Update-Firewall { return $true }
        Mock Send-AgentEvents { }
        Mock Update-IisBans { param($Agent, $Now) $Agent.IisBansAt = $Now }
        $script:A.IisBansApplied = ''
        Invoke-AgentTick $script:A 1000
        Should -Invoke Update-IisBans -Times 1 -Exactly
        $script:A.Bans['192.0.2.4'] = @{ rule = 'rate'; first = 1001; until = 2000; hits = 1; reported = $false; enforced = $true }
        Invoke-AgentTick $script:A 1010
        Should -Invoke Update-IisBans -Times 1 -Exactly
        Invoke-AgentTick $script:A 1031
        Should -Invoke Update-IisBans -Times 2 -Exactly
    }
}

Describe 'the check page IIS has to be able to read' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:Commits = New-Object System.Collections.ArrayList
        Mock Invoke-IisCommit { param($Changes, $Agent) [void]$script:Commits.Add(@($Changes)); return $true }
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It "tells who may read it" {
        Test-PageReadable @{ Allow = @('S-1-5-32-568', 'S-1-5-17'); Deny = @() } | Should -BeTrue
        Test-PageReadable @{ Allow = @('S-1-5-32-545'); Deny = @() } | Should -BeTrue
        Test-PageReadable @{ Allow = @('S-1-5-32-568'); Deny = @() } | Should -BeFalse
        Test-PageReadable @{ Allow = @('S-1-5-18', 'S-1-5-32-544'); Deny = @() } | Should -BeFalse
        Test-PageReadable @{ Allow = @('S-1-1-0'); Deny = @('S-1-5-17') } | Should -BeFalse
    }
    It 'takes the rule out, and says so, when IIS cannot read the page' {
        $a = New-TestAgent $script:Dir (New-Rules 'block' @{ challenge = @{ skip = @(); exempt = @() } })
        $script:SnapNow = Get-FullSnap $a
        $script:SnapNow.GlobalRules = @('AnalyticsAgent-Check')
        Mock Get-IisSnapshot { return $script:SnapNow }
        Mock Get-PageReaders { return @{ Allow = @('S-1-5-18'); Deny = @() } }
        Update-IisCheck $a 1793750400
        $a.Running['iis-check'] | Should -BeFalse
        $a.Notes['check'] | Should -Match "can't read"
        @($script:Commits[0])[0].Op | Should -Be 'Remove'
        @($script:Commits[0])[0].Section | Should -Be 'system.webServer/rewrite/globalRules'
        Should -Invoke Get-PageReaders -Times 2 -Exactly
    }
    It "never checks the server's own addresses" {
        $a = New-TestAgent $script:Dir (New-Rules 'block' @{ challenge = @{ skip = @(); exempt = @() } })
        $a.Own = @(ConvertTo-IpRange '203.0.113.50')
        $script:SnapNow = Get-FullSnap $a
        Mock Get-IisSnapshot { return $script:SnapNow }
        Update-IisCheck $a 1793750400
        $rule = @($script:Commits[-1])[-1].Item
        $vars = @{ REQUEST_METHOD = 'GET'; HTTP_ACCEPT = 'text/html'; URL = '/'; HTTP_COOKIE = ''; INSTANCE_ID = '1' }
        $vars.REMOTE_ADDR = '203.0.113.50'; Invoke-RewriteRule $rule $vars | Should -BeFalse
        $vars.REMOTE_ADDR = '203.0.113.51'; Invoke-RewriteRule $rule $vars | Should -BeTrue
    }
    It 'moves the page entry when check_substatus changes, and clear takes every entry of the page' {
        $a = New-TestAgent $script:Dir (New-Rules 'block' @{ challenge = @{ skip = @(); exempt = @() } })
        $page = Join-Path $a.Config.page_dir 'check.html'
        $a.Config.check_substatus = 72
        $snap = New-Snap @{ HttpErrors = @((Get-HttpErrorKey 503 71 $page), (Get-HttpErrorKey 503 0 'C:\custom\busy.htm')); ServerVariables = @('SG_CHECK') }
        $s = Get-IisCheckSupportChanges $a $snap $page
        $s.Conflict | Should -Be ''
        @($s.Changes | Where-Object { $_.Section -eq 'system.webServer/httpErrors' } | ForEach-Object { '{0} {1}' -f $_.Op, $(if ($_.Key) { $_.Key.subStatusCode } else { $_.Item.Attrs.subStatusCode }) }) |
            Should -Be @('Remove 71', 'Add 72')
        $snap.HttpErrors = @((Get-HttpErrorKey 503 71 $page), (Get-HttpErrorKey 503 72 $page), (Get-HttpErrorKey 503 0 'C:\custom\busy.htm'))
        @(Get-IisCheckRemoval $a $snap $page | Where-Object { $_.Section -eq 'system.webServer/httpErrors' } | ForEach-Object { $_.Key.subStatusCode }) | Should -Be @(71, 72)
    }
}

Describe "folders that change IIS's settings below them" {
    BeforeEach { $script:Dir = New-TestDir; $script:WebConfigCache.Clear() }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'finds the folders with a web.config of their own, not too deep and not in node_modules' {
        $deep = Join-Path $script:Dir 'd1/d2/d3/d4/d5/d6/d7'
        foreach ($d in 'a', 'a/b', 'node_modules/x', 'c', $deep) { New-Item -ItemType Directory -Force -Path (Join-Path $script:Dir $d) | Out-Null }
        foreach ($d in '', 'a', 'a/b', 'node_modules/x', $deep) { [IO.File]::WriteAllText((Join-Path (Join-Path $script:Dir $d) 'web.config'), '<configuration />') }
        @(Find-WebConfigFolders $script:Dir) | Sort-Object | Should -Be @('/a', '/a/b')
        # Cached: a new one shows only once the cache is old.
        New-Item -ItemType Directory -Path (Join-Path $script:Dir 'c/e') | Out-Null
        [IO.File]::WriteAllText((Join-Path $script:Dir 'c/e/web.config'), '<configuration />')
        @(Find-WebConfigFolders $script:Dir).Count | Should -Be 2
    }
    It 'sees a web.config that clears or removes IP restriction entries' {
        $f = Join-Path $script:Dir 'web.config'
        [IO.File]::WriteAllText($f, '<configuration><system.webServer><security><ipSecurity><clear /></ipSecurity></security></system.webServer></configuration>')
        Test-ClearsIpSecurity $f | Should -BeTrue
        [IO.File]::WriteAllText($f, '<configuration><location path="x"><system.webServer><security><ipSecurity><remove ipAddress="1.2.3.4" /></ipSecurity></security></system.webServer></location></configuration>')
        Test-ClearsIpSecurity $f | Should -BeTrue
        [IO.File]::WriteAllText($f, '<configuration><system.webServer><httpErrors><clear /></httpErrors></system.webServer></configuration>')
        Test-ClearsIpSecurity $f | Should -BeFalse
        [IO.File]::WriteAllText($f, 'not xml')
        Test-ClearsIpSecurity $f | Should -BeFalse
    }
}

Describe "the origin lock's exceptions" {
    It 'reads the URLs HTTP.sys serves and the WinRM listeners' {
        $netsh = "Server session ID: FF00000220000001`r`n    URL groups:`r`n        Registered URLs:`r`n            HTTPS://+:443/SRA_{BA195980-CD49-458B-9E23-C84EE0ADCD75}/`r`n            HTTP://+:80/WSMAN/`r`n            HTTP://*:80/`r`n"
        ConvertFrom-NetshUrls $netsh | Should -Be @('https://+:443/sra_{ba195980-cd49-458b-9e23-c84ee0adcd75}/', 'http://+:80/wsman/', 'http://*:80/')
        $winrm = "Listener`r`n    Address = *`r`n    Transport = HTTP`r`n    Port = 5985`r`n`r`nListener`r`n    Address = *`r`n    Transport = HTTPS`r`n    Port = 443`r`n"
        ConvertFrom-WinrmListeners $winrm | Should -Be @(5985, 443)
    }
    It 'refuses the lock for a gateway, a VPN or WinRM on the web ports, and only then' {
        $none = @{ Services = @(); Urls = @('http://*:80/', 'https://+:443/'); WinrmPorts = @(5985); CompatHttp = $false; CompatHttps = $false }
        @(Get-OriginConflicts $none @(80, 443)).Count | Should -Be 0
        @(Get-OriginConflicts @{ Services = @('TSGateway') } @(80, 443)) | Should -Match 'Remote Desktop Gateway'
        @(Get-OriginConflicts @{ Services = @('ServerManagementGateway') } @(80, 443)) | Should -Match 'Windows Admin Center'
        @(Get-OriginConflicts @{ Urls = @('https://+:443/sra_{x}/') } @(80, 443)) | Should -Match 'SSTP'
        @(Get-OriginConflicts @{ Urls = @('https://+:8443/sra_{x}/') } @(80, 443)).Count | Should -Be 0
        @(Get-OriginConflicts @{ Urls = @('http://+:80/wsman/') } @(80, 443)) | Should -Match 'WinRM'
        @(Get-OriginConflicts @{ WinrmPorts = @(443) } @(80, 443)) | Should -Match 'WinRM listener is on port 443'
        @(Get-OriginConflicts @{ CompatHttp = $true } @(443)).Count | Should -Be 0
        @(Get-OriginConflicts @{ CompatHttp = $true } @(80)) | Should -Match 'compatibility'
    }
    It 'writes no origin rules, and reports no origin layer, while one is there' {
        $dir = New-TestDir
        try {
            Mock Get-GatewayFacts { return @{ Services = @('TSGateway'); Urls = @(); WinrmPorts = @() } }
            Mock Get-FirewallRules { return , @() }
            Mock Get-FirewallInfo { return @{ Service = 'Running'; Active = @(); Profiles = @(@{ Name = 'Public'; Enabled = 'True'; AllowLocalFirewallRules = 'True' }) } }
            $script:Written = New-Object System.Collections.ArrayList
            Mock Invoke-FirewallBatch { param($Ops) foreach ($o in $Ops) { [void]$script:Written.Add($o) }; return @($Ops | ForEach-Object { @{ Name = $_.Name; Ok = $true; Error = '' } }) }
            $a = New-TestAgent $dir (New-Rules 'block' @{ deny = @('192.0.2.0/24'); origin = @{ only = @('173.245.48.0/20') } })
            Update-OriginConflicts $a 1000
            $a.Notes['origin'] | Should -Match 'origin lock left off: Remote Desktop Gateway'
            Update-Firewall $a 1000 | Should -BeTrue
            @($script:Written | Where-Object { $_.Name -match 'Origin' }).Count | Should -Be 0
            @($script:Written | Where-Object { $_.Name -match 'Lists' }).Count | Should -Be 2
            $a.Running['origin'] | Should -BeFalse
            $a.Running['windows-firewall'] | Should -BeTrue
            # Looked at again only after 10 minutes.
            Update-OriginConflicts $a 1300
            Should -Invoke Get-GatewayFacts -Times 1 -Exactly
            Update-OriginConflicts $a 1601
            Should -Invoke Get-GatewayFacts -Times 2 -Exactly
        } finally { Remove-Item -Recurse -Force $dir }
    }
    It "never locks out Azure's platform address" {
        $plan = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":true,"mode":"block","origin":{"only":["173.245.48.0/20"]}}')
        $w = Get-FirewallWanted $plan @() @()
        $blocked = @($w.Origin | ForEach-Object { ConvertTo-IpRange $_ -FirewallForms })
        Test-InRanges $blocked 4 (ConvertTo-IpNumber '168.63.129.16').N | Should -BeFalse
        Test-InRanges $blocked 4 (ConvertTo-IpNumber '168.63.129.17').N | Should -BeTrue
    }
}

Describe 'block lists the agent refuses' {
    It 'drops ranges wider than /8 (IPv6 /32) from the block lists, not from allow' {
        $p = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":true,"mode":"block","deny":["10.0.0.0/7","11.0.0.0/8","2001::/31","2001:db8::/32"],"shared":["0.0.0.0/0"],"allow":["0.0.0.0/1"]}')
        @($p.deny | ForEach-Object { Format-IpRange $_ }) | Should -Be @('11.0.0.0/8', '2001:db8::/32')
        @($p.shared).Count | Should -Be 0
        @($p.allow).Count | Should -Be 1
        # Two neighbours are each fine, even though they add up to a /7.
        $p = Get-AgentPlan (ConvertFrom-Json '{"v":1,"enabled":true,"mode":"block","lists":["10.0.0.0/8","11.0.0.0/8"]}')
        @($p.list | ForEach-Object { Format-IpRange $_ }) | Should -Be @('10.0.0.0/7')
    }
    It 'drops an IPv6 range that covers every IPv4 address, from every list' {
        foreach ($e in '::/0', '::/1', '::ffff:0:0/96', '::/64') { @(Get-Networks @($e)).Count | Should -Be 0 -Because $e }
        @(Get-Networks @('::ffff:192.0.2.0/120')).Count | Should -Be 1
        @(Get-Networks @('2001:db8::/32')).Count | Should -Be 1
    }
}

Describe 'the check rule and the caches' {
    BeforeEach { $script:Dir = New-TestDir }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'matches a percent-encoded skip prefix against the decoded path' {
        $rule = Get-CheckRule @{ skip = @('/caf%C3%A9/', '/a%20b/'); exempt = @() } @('t1') @('1') 71
        $vars = @{ REQUEST_METHOD = 'GET'; HTTP_ACCEPT = 'text/html'; HTTP_COOKIE = ''; INSTANCE_ID = '1'; REMOTE_ADDR = '192.0.2.1' }
        $vars.URL = '/caf' + [char]0xE9 + '/menu'; Invoke-RewriteRule $rule $vars | Should -BeFalse
        $vars.URL = '/a b/x'; Invoke-RewriteRule $rule $vars | Should -BeFalse
        $vars.URL = '/cafe/menu'; Invoke-RewriteRule $rule $vars | Should -BeTrue
    }
    It 'makes room for new bans a tenth at a time, the soonest to end first' {
        $a = New-TestAgent $script:Dir (New-Rules)
        $old = $script:BansMax; $script:BansMax = 50
        try {
            for ($i = 0; $i -lt 50; $i++) { $a.Bans["10.0.0.$i"] = @{ rule = 'rate'; first = 0; until = 2000 + $i; hits = 1; reported = $false; enforced = $true } }
            Add-AgentBan $a '192.0.2.9' 'rate' 1000
            $a.Bans.Count | Should -Be 46
            $a.Bans.ContainsKey('10.0.0.4') | Should -BeFalse
            $a.Bans.ContainsKey('10.0.0.5') | Should -BeTrue
            Add-AgentBan $a '192.0.2.10' 'rate' 1000
            $a.Bans.Count | Should -Be 47
        } finally { $script:BansMax = $old }
    }
    It "keeps what IIS's limits turned away bounded too" {
        $a = New-TestAgent $script:Dir (New-Rules)
        $old = $script:IisDeniedMax; $script:IisDeniedMax = 20
        try {
            for ($i = 0; $i -lt 60; $i++) { Add-IisDenied $a "10.1.0.$i" (1000 + $i) }
            $a.IisDenied.Count | Should -BeLessOrEqual 20
            $a.IisDenied.ContainsKey('10.1.0.59') | Should -BeTrue
        } finally { $script:IisDeniedMax = $old }
    }
}

Describe 'where the config may send the agent' {
    BeforeEach { $script:Dir = New-TestDir; $script:Path = Join-Path $script:Dir 'config.json' }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'keeps state_dir and page_dir inside the config folder' {
        $base = '{"site_id":"aaaaaaaaaaaaaaaaaaaaaaaa","secret":"abcDEF123456","endpoint":"https://c.example"'
        foreach ($bad in ',"state_dir":"/tmp"}', ',"page_dir":"/etc/x"}', (',"state_dir":"' + $script:Dir + '/../x"}')) {
            [IO.File]::WriteAllText($script:Path, $base + $bad)
            { Read-AgentConfig $script:Path } | Should -Throw -Because $bad
        }
        [IO.File]::WriteAllText($script:Path, $base + ',"page_dir":"' + $script:Dir + '/www2"}')
        (Read-AgentConfig $script:Path).page_dir | Should -Be ($script:Dir + '/www2')
    }
    It 'refuses a junction or link for its folders' {
        $target = New-TestDir
        try {
            New-Item -ItemType SymbolicLink -Path (Join-Path $script:Dir 'www') -Target $target | Out-Null
            [IO.File]::WriteAllText($script:Path, '{"site_id":"aaaaaaaaaaaaaaaaaaaaaaaa","secret":"abcDEF123456","endpoint":"https://c.example"}')
            { Read-AgentConfig $script:Path } | Should -Throw '*junction or link*'
        } finally { Remove-Item -Recurse -Force $target }
    }
    It 'accepts only SYSTEM, Administrators or TrustedInstaller as the owner' {
        Test-ConfigOwner 'S-1-5-18' | Should -BeTrue
        Test-ConfigOwner 'S-1-5-32-544' | Should -BeTrue
        Test-ConfigOwner 'S-1-5-21-1-2-3-1001' | Should -BeFalse
        Test-ConfigOwner 'S-1-5-32-545' | Should -BeFalse
    }
}

Describe 'calls that can hang' {
    It 'disposes of a timed-out run once it ends, without piling them up' {
        $script:Abandoned.Clear()
        { Invoke-WithTimeout -Seconds 1 -ScriptBlock { Start-Sleep -Seconds 2 } } | Should -Throw '*timed out*'
        $script:Abandoned.Count | Should -Be 1
        [System.Threading.Thread]::Sleep(2500)
        (Invoke-WithTimeout -ScriptBlock { 5 }).Output[0] | Should -Be 5
        $script:Abandoned.Count | Should -Be 0
    }
    It "gives IIS's snapshot a time limit" {
        $dir = New-TestDir
        $oldWindir = $env:windir; $oldPath = $script:AgentPath; $oldLimit = $script:SnapshotTimeout
        try {
            $fake = Join-Path $dir 'fake.ps1'
            [IO.File]::WriteAllText($fake, "param([string]`$Command)`nfunction Get-IisSnapshotCore { param(`$c) [System.Threading.Thread]::Sleep(3000); @{ Installed = `$true } }")
            $env:windir = $dir; $script:AgentPath = $fake; $script:SnapshotTimeout = 1
            $s = Get-IisSnapshot @{}
            $s.Installed | Should -BeTrue
            $s.Error | Should -Match 'took too long'
        } finally {
            $env:windir = $oldWindir; $script:AgentPath = $oldPath; $script:SnapshotTimeout = $oldLimit
            [System.Threading.Thread]::Sleep(2500)
            Remove-Item -Recurse -Force $dir
        }
    }
}
