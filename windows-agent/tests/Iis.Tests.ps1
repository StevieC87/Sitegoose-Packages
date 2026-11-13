BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
    function New-Rules([string]$Mode = 'block', [hashtable]$Extra = @{}) {
        $r = @{ v = 1; enabled = $true; mode = $Mode; allow = @('198.51.100.7'); goodbots = @('66.249.64.0/27')
            flood = @{ conn_max = 40; req_rate = 20; exempt = @('173.245.48.0/20', '2400:cb00::/32') } }
        foreach ($k in $Extra.Keys) { $r[$k] = $Extra[$k] }
        return $r
    }
    function New-Path([string]$Site = 'Default Web Site', [string]$Id = '1', [string]$Path = '/', [string[]]$HttpErrors = @(), [hashtable]$Extra = @{}) {
        $p = @{ Site = $Site; SiteId = $Id; Path = $Path; ErrorMode = 'DetailedLocalOnly'; ExistingResponse = 'Auto'; HttpErrors = $HttpErrors; Csp = '' }
        foreach ($k in $Extra.Keys) { $p[$k] = $Extra[$k] }
        return $p
    }
    function New-Snap([hashtable]$Extra = @{}) {
        $s = @{ Installed = $true; Error = ''; Modules = @('IpRestrictionModule', 'RewriteModule', 'CustomErrorModule')
            Dipr = @{ denyAction = 'Forbidden'; enableLoggingOnlyMode = $false; rateEnabled = $false; maxRequests = 20; intervalMs = 200; concEnabled = $false; maxConcurrent = 5 }
            IpSecurity = @{ AllowUnlisted = $true; Entries = @() }
            GlobalRules = @(); OutboundRules = @(); PreConditions = @(); ServerVariables = @(); HttpErrors = @(); Paths = @(); LogDirs = @()
            Sites = @(1..12 | ForEach-Object { @{ Id = [string]$_; Name = "S$_"; State = 'Started'; Bindings = @(@{ Protocol = 'http'; Ip = '*'; Port = 80; Host = '' }) } }) }
        foreach ($k in $Extra.Keys) { $s[$k] = $Extra[$k] }
        return $s
    }
    function Get-Ops { return @($script:Commits | ForEach-Object { $_ } | ForEach-Object { '{0} {1}{2}' -f $_.Op, $_.Section, $(if ($_.Child) { '/' + $_.Child } else { '' }) }) }
}

Describe 'the IIS request limits' {
    It 'counts every request over ten seconds, 20 a page, never under 500, and at least 100 open at once' {
        $d = Get-DiprDesired @{ req_rate = 20; req_burst = 60; conn_max = 400 }
        $d.maxRequests | Should -Be 5200
        $d.intervalMs | Should -Be 10000
        $d.maxConcurrent | Should -Be 400
        (Get-DiprDesired @{ req_rate = 20; req_burst = 60; conn_max = 40 }).maxConcurrent | Should -Be 100
        $d.denyAction | Should -Be 'Forbidden'
        $d.enableLoggingOnlyMode | Should -BeFalse
        (Get-DiprDesired @{ req_rate = 1; req_burst = 1 }).maxRequests | Should -Be 500
        (Get-DiprDesired @{ req_rate = 2; req_burst = 6 }).maxRequests | Should -Be 520
        (Get-DiprDesired @{ req_rate = 2; req_burst = 6 }).concEnabled | Should -BeFalse
        (Get-DiprDesired @{ conn_max = 3 }).maxConcurrent | Should -Be 100
        (Get-DiprDesired @{ conn_max = 3 }).rateEnabled | Should -BeFalse
    }
    It 'gives the exempt IPv4 ranges as allow entries with masks, and no IPv6' {
        $e = @(Get-ExemptAllowEntries @(Get-Networks @('173.245.48.0/20', '10.0.0.1', '10.0.0.2', '2400:cb00::/32')))
        @($e | ForEach-Object { $_.ipAddress + '/' + $_.subnetMask }) | Should -Be @('10.0.0.1/255.255.255.255', '10.0.0.2/255.255.255.255', '173.245.48.0/255.255.240.0')
        $e[2].Key | Should -Be '173.245.48.0|255.255.240.0'
    }
    It 'says why it stays off' {
        Get-IisLimitsBlocker (New-Snap @{ Installed = $false }) $false $false | Should -Match "isn't installed"
        Get-IisLimitsBlocker (New-Snap @{ Modules = @('RewriteModule') }) $false $false | Should -Match 'Web-IP-Security'
        Get-IisLimitsBlocker (New-Snap @{ Error = 'locked' }) $false $false | Should -Match 'locked'
        $owner = New-Snap; $owner.Dipr.rateEnabled = $true
        Get-IisLimitsBlocker $owner $false $false | Should -Match 'someone else'
        Get-IisLimitsBlocker $owner $true $false | Should -Be ''
        Get-IisLimitsBlocker (New-Snap @{ IpSecurity = @{ AllowUnlisted = $false; Entries = @() } }) $false $false | Should -Match 'deny unlisted'
        Get-IisLimitsBlocker (New-Snap @{ Paths = @(@{ Site = 'Admin'; Path = '/'; AllowUnlisted = $false }) }) $false $false | Should -Match '^Admin/ denies unlisted'
        Get-IisLimitsBlocker (New-Snap) $false $true | Should -Match 'public IPv6'
        # Before anything is written: a path whose effective entries lack a
        # server-level one, or that clears them, keeps the layer off.
        $s = New-Snap @{ IpSecurity = @{ AllowUnlisted = $true; Entries = @('10.0.0.0|255.0.0.0') } }
        $s.Paths = @(@{ Site = 'Shop'; SiteId = '2'; Path = '/'; AllowUnlisted = $true; IpEntries = @() })
        Get-IisLimitsBlocker $s $false $false | Should -Match '^Shop/ clears or removes'
        $s.Paths = @(@{ Site = 'Shop'; SiteId = '2'; Path = '/'; AllowUnlisted = $true; IpEntries = @('10.0.0.0|255.0.0.0') })
        Get-IisLimitsBlocker $s $false $false | Should -Be ''
        $s.Paths = @(@{ Site = 'Shop'; SiteId = '2'; Path = '/old'; AllowUnlisted = $true; IpEntries = @('10.0.0.0|255.0.0.0'); IpCleared = $true })
        Get-IisLimitsBlocker $s $false $false | Should -Match '^Shop/old clears or removes'
        Get-IisLimitsBlocker (New-Snap) $false $false $true | Should -Match 'dropped the exempt ranges'
        Get-IisLimitsBlocker (New-Snap) $false $false | Should -Be ''
    }
    It 'treats only global IPv6 as public' {
        Test-PublicIPv6 @(Get-Networks @('10.0.0.5', 'fe80::1', '::1', 'fd00::5', '2001:0:1::1', '2002:abcd::1')) | Should -BeFalse
        Test-PublicIPv6 @(Get-Networks @('10.0.0.5', '2a01:4f8::1')) | Should -BeTrue
    }
}

Describe 'putting the IIS request limits in place' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:Commits = New-Object System.Collections.ArrayList
        $script:CommitOk = $true
        $script:Snap = New-Snap
        Mock Get-IisSnapshot { return $script:Snap }
        Mock Invoke-IisCommit { param($Changes, $Agent) if ($script:CommitOk) { [void]$script:Commits.Add(@($Changes)) }; return $script:CommitOk }
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'in block mode: allow entries for the exempt ranges and the limits, with the owner values saved first' {
        $a = New-TestAgent $script:Dir (New-Rules)
        Update-IisLimits $a
        $a.Running['iis'] | Should -BeTrue
        $ops = @($script:Commits[0])
        @($ops | Where-Object { $_.Op -eq 'Add' } | ForEach-Object { $_.Item.Attrs.ipAddress + '/' + $_.Item.Attrs.subnetMask }) |
            Should -Be @('10.0.0.0/255.0.0.0', '66.249.64.0/255.255.255.224', '100.64.0.0/255.192.0.0', '127.0.0.0/255.0.0.0', '169.254.0.0/255.255.0.0',
                '172.16.0.0/255.240.0.0', '173.245.48.0/255.255.240.0', '192.168.0.0/255.255.0.0', '198.51.100.7/255.255.255.255')
        foreach ($o in @($ops | Where-Object { $_.Op -eq 'Add' })) { $o.Item.Attrs.allowed | Should -BeTrue }
        $rate = @($ops | Where-Object { $_.Child -eq 'denyByRequestRate' })[0]
        $rate.Attrs.maxRequests | Should -Be 5200
        $rate.Attrs.enabled | Should -BeTrue
        $a.Iis.dipr_ours | Should -BeTrue
        $a.Iis.dipr_original.maxRequests | Should -Be 20
        @($a.Iis.allow_added).Count | Should -Be 9
        # Saved to disk before the write.
        (ConvertFrom-Json ([IO.File]::ReadAllText($a.StateFile))).iis.dipr_ours | Should -BeTrue
    }
    It "never adds an allow entry the owner already has, and never takes one away" {
        $script:Snap.IpSecurity.Entries = @('173.245.48.0|255.255.240.0')
        $a = New-TestAgent $script:Dir (New-Rules)
        Update-IisLimits $a
        @($script:Commits[0] | Where-Object { $_.Op -eq 'Add' }).Count | Should -Be 8
        $a.Iis.allow_added | Should -Not -Contain '173.245.48.0|255.255.240.0'
        $script:Commits.Clear()
        $script:Snap = New-Snap @{ IpSecurity = @{ AllowUnlisted = $true; Entries = @(@($a.Iis.allow_added) + '173.245.48.0|255.255.240.0') } }
        $script:Snap.Dipr = Get-DiprDesired $a.Plan.flood
        Update-IisLimits (New-TestAgent $script:Dir (New-Rules 'monitor'))
        $removed = @($script:Commits | ForEach-Object { $_ } | Where-Object { $_.Op -eq 'Remove' } | ForEach-Object { $_.Key.ipAddress })
        $removed | Should -Not -Contain '173.245.48.0'
        $removed | Should -Contain '66.249.64.0'
    }
    It 'in monitor mode, or without flood, puts the owner values back' {
        $a = New-TestAgent $script:Dir (New-Rules)
        Update-IisLimits $a
        $script:Snap = New-Snap @{ IpSecurity = @{ AllowUnlisted = $true; Entries = @($a.Iis.allow_added) } }
        $script:Snap.Dipr = Get-DiprDesired $a.Plan.flood
        $script:Commits.Clear()
        $m = New-TestAgent $script:Dir (New-Rules 'monitor')
        $m.Iis.dipr_ours | Should -BeTrue
        Update-IisLimits $m
        $m.Running['iis'] | Should -BeFalse
        $ops = @($script:Commits[0])
        @($ops | Where-Object { $_.Op -eq 'Remove' }).Count | Should -Be 9
        $rate = @($ops | Where-Object { $_.Child -eq 'denyByRequestRate' })[0]
        $rate.Attrs.maxRequests | Should -Be 20
        $rate.Attrs.enabled | Should -BeFalse
        $m.Iis.dipr_ours | Should -BeFalse
    }
    It 'changes nothing again when everything is in place' {
        $a = New-TestAgent $script:Dir (New-Rules)
        Update-IisLimits $a
        $script:Snap = New-Snap @{ IpSecurity = @{ AllowUnlisted = $true; Entries = @($a.Iis.allow_added) } }
        $script:Snap.Dipr = Get-DiprDesired $a.Plan.flood
        $script:Commits.Clear()
        Update-IisLimits $a
        $script:Commits.Count | Should -Be 0
        $a.Running['iis'] | Should -BeTrue
    }
    It 'reports the feature missing rather than failing' {
        $script:Snap = New-Snap @{ Modules = @('RewriteModule'); Dipr = $null; IpSecurity = $null }
        $a = New-TestAgent $script:Dir (New-Rules)
        Update-IisLimits $a
        $a.Running['iis'] | Should -BeFalse
        $a.Notes['iis'] | Should -Match 'Install-WindowsFeature Web-IP-Security'
        $script:Commits.Count | Should -Be 0
    }
    It 'leaves the owner its own Dynamic IP Restrictions' {
        $script:Snap.Dipr.concEnabled = $true
        $a = New-TestAgent $script:Dir (New-Rules)
        Update-IisLimits $a
        $a.Running['iis'] | Should -BeFalse
        $script:Commits.Count | Should -Be 0
    }
    It 'takes the limits away once if a site clears the entries unseen, and stays off until the sites change' {
        $a = New-TestAgent $script:Dir (New-Rules)
        $script:Snap.Paths = @(@{ Site = 'Shop'; SiteId = '2'; Path = '/'; AllowUnlisted = $true; IpEntries = @() })
        Update-IisLimits $a
        $a.Running['iis'] | Should -BeFalse
        $a.Notes['iis'] | Should -Match "Shop/ clears the server's IP restrictions"
        $script:Commits.Count | Should -Be 2
        $a.Iis.dipr_ours | Should -BeFalse
        $a.Iis.limits_held | Should -Not -BeNullOrEmpty
        # The next rounds write nothing: no switching on and off.
        $script:Commits.Clear()
        Update-IisLimits $a
        Update-IisLimits $a
        $script:Commits.Count | Should -Be 0
        $a.Notes['iis'] | Should -Match 'dropped the exempt ranges'
        # Held across a restart too.
        $b = New-TestAgent $script:Dir (New-Rules)
        Update-IisLimits $b
        $script:Commits.Count | Should -Be 0
        # Once the sites change, it is tried again.
        $script:Snap.Paths = @(@{ Site = 'Shop'; SiteId = '2'; Path = '/'; AllowUnlisted = $true })
        Update-IisLimits $b
        $b.Running['iis'] | Should -BeTrue
        $b.Iis.limits_held | Should -BeNullOrEmpty
    }
    It 'stays off while the site is locked to its origin, and takes earlier limits away' {
        $a = New-TestAgent $script:Dir (New-Rules)
        Update-IisLimits $a
        $a.Running['iis'] | Should -BeTrue
        $script:Snap = New-Snap @{ IpSecurity = @{ AllowUnlisted = $true; Entries = @($a.Iis.allow_added) } }
        $script:Snap.Dipr = Get-DiprDesired $a.Plan.flood
        $script:Commits.Clear()
        $o = New-TestAgent $script:Dir (New-Rules 'block' @{ origin = @{ only = @('173.245.48.0/20') } })
        Update-IisLimits $o
        $o.Running['iis'] | Should -BeFalse
        $o.Notes['iis'] | Should -Match 'locked to its origin'
        @($script:Commits[0] | Where-Object { $_.Child -eq 'denyByRequestRate' })[0].Attrs.enabled | Should -BeFalse
    }
    It "doesn't report the layer when the write fails, and keeps what was there" {
        $script:CommitOk = $false
        $a = New-TestAgent $script:Dir (New-Rules)
        Update-IisLimits $a
        $a.Running['iis'] | Should -BeFalse
        @($a.Iis.allow_added).Count | Should -Be 0
    }
}

Describe 'which sites get the check page' {
    BeforeAll {
        $script:PagePath = '/pages/check.html'
        $script:Mine = Get-HttpErrorKey 503 71 $script:PagePath
    }
    It 'only those whose every application shows our page' {
        $snap = New-Snap @{ Paths = @(
                (New-Path 'A' '1' '/' @($script:Mine)),
                (New-Path 'B' '2' '/' @($script:Mine)), (New-Path 'B' '2' '/app' @()),
                (New-Path 'C' '3' '/' @($script:Mine) @{ ErrorMode = 'Detailed' }),
                (New-Path 'D' '4' '/' @($script:Mine) @{ ExistingResponse = 'PassThrough' }),
                (New-Path 'E' '5' '/' @($script:Mine) @{ Csp = "default-src 'self'" }),
                (New-Path 'F' '6' '/' @($script:Mine) @{ Csp = "default-src 'self'; script-src 'self' " + (Get-CspHash (Get-CheckScript)) }),
                (New-Path 'G' '7' '/' @($script:Mine) @{ Csp = "script-src 'self' 'unsafe-inline'" }),
                @{ Site = 'loc'; SiteId = ''; Path = ' (location)'; AllowUnlisted = $true; IpEntries = @() }) }
        $r = Get-CheckSites $snap $script:PagePath 71 @(80, 443)
        $r.Ids | Should -Be @('1', '6', '7')
        $r.Skipped.Count | Should -Be 4
        ($r.Skipped -join "`n") | Should -Match 'B/app: its error pages leave the check page out'
        ($r.Skipped -join "`n") | Should -Match 'C/: it shows detailed errors'
        ($r.Skipped -join "`n") | Should -Match 'PassThrough'
        ($r.Skipped -join "`n") | Should -Match 'Content-Security-Policy'
    }
    It 'leaves out sites not bound on the web ports, and folders with their own error pages' {
        $snap = New-Snap @{ Paths = @(
                (New-Path 'Web' '1' '/' @($script:Mine)),
                (New-Path 'Exchange' '2' '/' @($script:Mine)),
                (New-Path 'Shop' '3' '/' @($script:Mine)), (New-Path 'Shop' '3' '/files/legacy' @($script:Mine) @{ ErrorMode = 'Detailed' }),
                (New-Path 'Blog' '4' '/' @($script:Mine)), (New-Path 'Blog' '4' '/old' @()) ) }
        $snap.Sites = @(
            @{ Id = '1'; Name = 'Web'; Bindings = @(@{ Protocol = 'https'; Ip = '*'; Port = 443; Host = 'example.com' }) },
            @{ Id = '2'; Name = 'Exchange'; Bindings = @(@{ Protocol = 'https'; Ip = '*'; Port = 444; Host = '' }, @{ Protocol = 'net.tcp'; Ip = ''; Port = 80; Host = '' }) },
            @{ Id = '3'; Name = 'Shop'; Bindings = @(@{ Protocol = 'http'; Ip = '*'; Port = 80; Host = '' }) },
            @{ Id = '4'; Name = 'Blog'; Bindings = @(@{ Protocol = 'http'; Ip = '*'; Port = 80; Host = '' }) })
        $r = Get-CheckSites $snap $script:PagePath 71 @(80, 443)
        $r.Ids | Should -Be @('1')
        ($r.Skipped -join "`n") | Should -Not -Match 'Exchange'
        ($r.Skipped -join "`n") | Should -Match 'Shop/files/legacy: it shows detailed errors'
        ($r.Skipped -join "`n") | Should -Match 'Blog/old: its error pages leave the check page out'
    }
    It 'reads the binding information IIS keeps' {
        $b = ConvertFrom-BindingInformation 'HTTPS' '*:443:www.example.com'
        $b.Protocol | Should -Be 'https'; $b.Port | Should -Be 443; $b.Host | Should -Be 'www.example.com'; $b.Ip | Should -Be '*'
        (ConvertFrom-BindingInformation 'http' '[::1]:8080:').Ip | Should -Be '[::1]'
        ConvertFrom-BindingInformation 'net.pipe' '*' | Should -BeNullOrEmpty
    }
    It 'matches the page by path in any case, and by substatus' {
        Test-CheckPathEligible (New-Path -HttpErrors @((Get-HttpErrorKey 503 71 '/PAGES/Check.html'))) $script:PagePath 71 'x' | Should -Be ''
        Test-CheckPathEligible (New-Path -HttpErrors @((Get-HttpErrorKey 503 72 $script:PagePath))) $script:PagePath 71 'x' | Should -Not -Be ''
    }
}

Describe 'putting the browser check in IIS' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:Commits = New-Object System.Collections.ArrayList
        $script:CommitOk = $true
        $script:Now = 1793750400
        Mock Invoke-IisCommit { param($Changes, $Agent) if ($script:CommitOk) { [void]$script:Commits.Add(@($Changes)) }; return $script:CommitOk }
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'sets up the page, the error page, the variable and the headers, then the rule first of all for the sites that show it' {
        $a = New-TestAgent $script:Dir (New-Rules 'block' @{ challenge = @{ skip = @('/api/'); exempt = @() } })
        $page = Join-Path $a.Config.page_dir 'check.html'
        $mine = Get-HttpErrorKey 503 71 $page
        $script:Calls = 0
        Mock Get-IisSnapshot {
            $script:Calls++
            if ($script:Calls -eq 1) { return New-Snap @{ GlobalRules = @('Owner-Redirect'); Paths = @((New-Path 'A' '1' '/' @())) } }
            return New-Snap @{ GlobalRules = @('Owner-Redirect'); HttpErrors = @($mine); ServerVariables = @('SG_CHECK'); Paths = @((New-Path 'A' '1' '/' @($mine)), (New-Path 'B' '2' '/' @())) }
        }
        Update-IisCheck $a $script:Now
        $a.Running['iis-check'] | Should -BeTrue
        $script:Commits.Count | Should -Be 2
        $first = @($script:Commits[0])
        @($first | ForEach-Object { $_.Op + ' ' + $_.Section + '/' + $_.Child }) | Should -Be @(
            'Add system.webServer/httpErrors/', 'Add system.webServer/rewrite/allowedServerVariables/',
            'Add system.webServer/rewrite/outboundRules/preConditions',
            'Add system.webServer/rewrite/outboundRules/', 'Add system.webServer/rewrite/outboundRules/', 'Add system.webServer/rewrite/outboundRules/')
        $first[0].Item.Attrs.path | Should -Be $page
        $first[0].Item.Attrs.subStatusCode | Should -Be 71
        $rule = @($script:Commits[1])
        $rule.Count | Should -Be 1
        $rule[0].Index | Should -Be 0
        $rule[0].Item.Attrs.name | Should -Be 'AnalyticsAgent-Check'
        (ConvertTo-ConfigXml $rule[0].Item) | Should -Match 'input="\{INSTANCE_ID\}" pattern="\^\(1\)\$"'
        Test-Path $page | Should -BeTrue
        [IO.File]::ReadAllText($page) | Should -Match ('data-pass="' + [regex]::Escape((Get-ChallengeToken $a.Config.secret (Get-UtcDay $script:Now))) + '"')
        $a.Iis.check_added_variable | Should -BeTrue
        $a.Notes['check'] | Should -Match 'no browser check on B/'
    }
    It 'rewrites the rule only when it changes or is not first, and moves to the new day' {
        $a = New-TestAgent $script:Dir (New-Rules 'block' @{ challenge = @{ skip = @(); exempt = @() } })
        $page = Join-Path $a.Config.page_dir 'check.html'
        $mine = Get-HttpErrorKey 503 71 $page
        $full = { param($rules) New-Snap @{ GlobalRules = $rules; HttpErrors = @($mine); ServerVariables = @('SG_CHECK'); PreConditions = @('AnalyticsAgent-Check')
                OutboundRules = @('AnalyticsAgent-Check-Cache', 'AnalyticsAgent-Check-Robots', 'AnalyticsAgent-Check-Csp'); Paths = @((New-Path 'A' '1' '/' @($mine))) } }
        $script:SnapNow = & $full @()
        Mock Get-IisSnapshot { return $script:SnapNow }
        Update-IisCheck $a $script:Now
        $script:Commits.Clear()
        $script:SnapNow = & $full @('AnalyticsAgent-Check', 'Owner')
        Update-IisCheck $a $script:Now
        $script:Commits.Count | Should -Be 0
        $script:SnapNow = & $full @('Owner', 'AnalyticsAgent-Check')
        Update-IisCheck $a $script:Now
        @($script:Commits[0] | ForEach-Object { $_.Op }) | Should -Be @('Remove', 'Add')
        $script:Commits.Clear()
        $script:SnapNow = & $full @('AnalyticsAgent-Check', 'Owner')
        Update-IisCheck $a ($script:Now + 86400)
        $script:Commits.Count | Should -Be 1
        $xml = ConvertTo-ConfigXml @($script:Commits[0])[1].Item
        $xml | Should -Match ([regex]::Escape((Get-ChallengeToken $a.Config.secret 20762).Replace('.', '\.')))
        $xml | Should -Match ([regex]::Escape((Get-ChallengeToken $a.Config.secret 20761).Replace('.', '\.')))
        [IO.File]::ReadAllText($page) | Should -Match 'data-pass="20762\.'
    }
    It "keeps yesterday's page when the new day's rule can't be written" {
        $a = New-TestAgent $script:Dir (New-Rules 'block' @{ challenge = @{ skip = @(); exempt = @() } })
        $page = Join-Path $a.Config.page_dir 'check.html'
        $mine = Get-HttpErrorKey 503 71 $page
        $script:SnapNow = New-Snap @{ GlobalRules = @(); HttpErrors = @($mine); ServerVariables = @('SG_CHECK'); PreConditions = @('AnalyticsAgent-Check')
            OutboundRules = @('AnalyticsAgent-Check-Cache', 'AnalyticsAgent-Check-Robots', 'AnalyticsAgent-Check-Csp'); Paths = @((New-Path 'A' '1' '/' @($mine))) }
        Mock Get-IisSnapshot { return $script:SnapNow }
        Update-IisCheck $a $script:Now
        $script:SnapNow.GlobalRules = @('AnalyticsAgent-Check')
        $script:CommitOk = $false
        Update-IisCheck $a ($script:Now + 86400)
        [IO.File]::ReadAllText($page) | Should -Match 'data-pass="20761\.'
        $a.Running['iis-check'] | Should -BeTrue
    }
    It "stays off without URL Rewrite, and says so" {
        Mock Get-IisSnapshot { return New-Snap @{ Modules = @('IpRestrictionModule') } }
        $a = New-TestAgent $script:Dir (New-Rules 'block' @{ challenge = @{ skip = @(); exempt = @() } })
        Update-IisCheck $a $script:Now
        $a.Running['iis-check'] | Should -BeFalse
        $a.Notes['check'] | Should -Match 'URL Rewrite'
        $script:Commits.Count | Should -Be 0
    }
    It "never takes over the owner's own 503.71 page" {
        Mock Get-IisSnapshot { return New-Snap @{ HttpErrors = @((Get-HttpErrorKey 503 71 'C:\inetpub\custerr\busy.htm')); Paths = @((New-Path 'A' '1' '/' @())) } }
        $a = New-TestAgent $script:Dir (New-Rules 'block' @{ challenge = @{ skip = @(); exempt = @() } })
        Update-IisCheck $a $script:Now
        $a.Running['iis-check'] | Should -BeFalse
        $a.Notes['check'] | Should -Match 'check_substatus'
        $script:Commits.Count | Should -Be 0
    }
    It 'takes everything out once the rules stop carrying challenge, and the page last' {
        $a = New-TestAgent $script:Dir (New-Rules)
        $page = Join-Path $a.Config.page_dir 'check.html'
        Write-TextFile $page 'x'
        $a.Iis.check_added_variable = $true
        $a.Iis.check_page = $page
        Mock Get-IisSnapshot { return New-Snap @{ GlobalRules = @('Owner', 'AnalyticsAgent-Check'); ServerVariables = @('HTTP_X', 'SG_CHECK'); PreConditions = @('AnalyticsAgent-Check')
                OutboundRules = @('AnalyticsAgent-Check-Cache', 'AnalyticsAgent-Check-Robots', 'AnalyticsAgent-Check-Csp', 'Owner-Out')
                HttpErrors = @((Get-HttpErrorKey 503 71 $page), (Get-HttpErrorKey 503 0 'x')) } }
        $script:CommitOk = $false
        Update-IisCheck $a $script:Now
        Test-Path $page | Should -BeTrue
        $script:CommitOk = $true
        Update-IisCheck $a $script:Now
        $ops = @($script:Commits[0])
        $ops.Count | Should -Be 7
        foreach ($o in $ops) { $o.Op | Should -Be 'Remove' }
        @($ops | Where-Object { $_.Key.name } | ForEach-Object { $_.Key.name }) | Should -Not -Contain 'Owner'
        @($ops | Where-Object { $_.Key.name } | ForEach-Object { $_.Key.name }) | Should -Not -Contain 'Owner-Out'
        @($ops | Where-Object { $_.Section -eq 'system.webServer/httpErrors' }).Count | Should -Be 1
        Test-Path $page | Should -BeFalse
        $a.Running['iis-check'] | Should -BeFalse
    }
    It "leaves a server variable the owner had alone" {
        $a = New-TestAgent $script:Dir (New-Rules)
        $snap = New-Snap @{ ServerVariables = @('SG_CHECK') }
        @(Get-IisCheckRemoval $a $snap '/x').Count | Should -Be 0
    }
}
