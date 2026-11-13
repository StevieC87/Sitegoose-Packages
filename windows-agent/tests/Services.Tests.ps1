BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
    function New-Svc([string]$Name, [string]$State = 'Running', [string]$Mode = 'Auto', [int]$ProcId = 100) {
        return @{ Name = $Name; State = $State; StartMode = $Mode; ProcessId = $ProcId }
    }
    function New-ServicesAgent([string]$Dir, $Services = @(), [bool]$Detect = $true) {
        $cfg = New-TestConfig $Dir
        if (-not (Test-Path $cfg.state_dir)) { New-Item -ItemType Directory -Path $cfg.state_dir -Force | Out-Null }
        $cfg.services = @(Get-ServiceList $Services)
        $cfg.services_detect = $Detect
        return New-Agent $cfg
    }
}

Describe 'the services listed in the config' {
    It 'takes names and {service, name}, and skips anything else' {
        $list = @(Get-ServiceList (ConvertFrom-Json '["MSSQLSERVER", {"service": "W3SVC", "name": "IIS"}, {"name": "x"}, "bad|name", 5, "mssqlserver"]'))
        $list.Count | Should -Be 2
        $list[0].Service | Should -Be 'MSSQLSERVER'
        ($list[1].Service, $list[1].Name) | Should -Be @('W3SVC', 'IIS')
    }
}

Describe 'which services get a light' {
    It 'lists the config first, then what it finds: running, or stopped but starting with Windows' {
        $svcs = @((New-Svc 'W3SVC'), (New-Svc 'MSSQL$SHOP' 'Stopped' 'Auto' 0), (New-Svc 'Redis' 'Stopped' 'Manual' 0),
            (New-Svc 'Spooler'), (New-Svc 'MyApp' 'Running' 'Auto' 300))
        $listed = @(Get-ServiceList @('MyApp', 'Gone'))
        $checks = @(Get-ServiceChecks $svcs $listed $true)
        @($checks | ForEach-Object { $_.name }) | Should -Be @('MyApp', 'Gone', 'MSSQL$SHOP', 'W3SVC')
        ($checks[1].ok, $checks[1].detail) | Should -Be @($false, 'No such service')
        ($checks[2].ok, $checks[2].detail, $checks[2].auto) | Should -Be @($false, 'Stopped', $true)
        ($checks[0].type, $checks[0].target, $checks[0].Pid) | Should -Be @('unit', 'MyApp', 300)
        @(Get-ServiceChecks $svcs $listed $false).Count | Should -Be 2
    }
}

Describe 'a found service that stopped' {
    BeforeEach { $script:Dir = New-TestDir }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'stays red for a week after it last ran, across a restart, and goes at once when uninstalled' {
        $a = New-ServicesAgent $script:Dir
        $script:Now = 1000000
        Mock Get-WindowsServices { return , @($script:Svcs) }
        Mock Get-ProcessReadings { return @{} }
        Mock Invoke-Collector { return @{ Status = 202; Headers = @{}; Body = '{}' } }
        $script:Svcs = @((New-Svc 'Redis' 'Running' 'Manual' 50))
        [void](Invoke-ServicesRound $a $script:Now -Force)
        $script:Svcs = @((New-Svc 'Redis' 'Stopped' 'Manual' 0))
        $b = New-ServicesAgent $script:Dir
        $checks = @(Invoke-ServicesRound $b ($script:Now + 3 * 86400) -Force)
        @($checks | ForEach-Object { '{0} {1}' -f $_.name, $_.ok }) | Should -Be @('Redis False') -Because 'it ran three days ago'
        $r = Invoke-ServicesRound $b ($script:Now + 8 * 86400) -Force
        @($r).Count | Should -Be 0 -Because 'a week without running'
        $script:Svcs = @((New-Svc 'Redis' 'Running' 'Manual' 50))
        [void](Invoke-ServicesRound $b ($script:Now + 9 * 86400) -Force)
        $script:Svcs = @((New-Svc 'Spooler'))
        [void](Invoke-ServicesRound $b ($script:Now + 9 * 86400 + 60) -Force)
        $b.ServiceSeen.Count | Should -Be 0 -Because 'uninstalled is meant'
    }
    It 'forgets nothing when WMI answers with no services at all' {
        Mock Invoke-Collector { return @{ Status = 202; Headers = @{}; Body = '{}' } }
        Mock Get-ProcessReadings { return @{} }
        $a = New-ServicesAgent $script:Dir
        $a.ServiceSeen['redis'] = 1000000.0
        Mock Get-WindowsServices { return , @() }
        Invoke-ServicesRound $a 1000060 -Force | Should -BeNullOrEmpty
        $a.ServiceSeen.ContainsKey('redis') | Should -BeTrue
        Should -Invoke Invoke-Collector -Times 0
    }
    It 'counts a time saved in the future (the clock put back since) as now' {
        $seen = @{ redis = 2000000000.0 }
        $checks = @(Get-ServiceChecks @((New-Svc 'Redis' 'Stopped' 'Manual' 0)) @() $true $seen 1000000.5)
        $seen['redis'] | Should -Be 1000000 -Because 'whole seconds, no later than now'
        $checks.Count | Should -Be 1
        @(Get-ServiceChecks @((New-Svc 'Redis' 'Stopped' 'Manual' 0)) @() $true $seen (1000000 + 8 * 86400)).Count | Should -Be 0 -Because 'a week from when the clock came back'
    }
}

Describe 'services.json' {
    BeforeEach { $script:Dir = New-TestDir; $script:File = Join-Path $script:Dir 'services.json' }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'reads back what it wrote, and nothing on a first run' {
        (Read-ServicesSeen $script:File).Count | Should -Be 0
        Write-TextFile $script:File (ConvertTo-ServicesSeenJson @{ redis = 1000000.0; 'mssql$shop' = 999999.0 })
        $seen = Read-ServicesSeen $script:File
        ($seen['redis'], $seen['mssql$shop']) | Should -Be @(1000000, 999999)
        @(Get-ChildItem $script:Dir).Count | Should -Be 1 -Because 'no temporary file is left'
    }
    It 'starts afresh from a file cut short, and drops a bad entry on its own' {
        [IO.File]::WriteAllText($script:File, '{"seen":{"redis":10000')
        (Read-ServicesSeen $script:File).Count | Should -Be 0
        [IO.File]::WriteAllText($script:File, '{"seen":{"Redis":1000000.7,"a":"1000000","b":true,"c":-5,"bad|name":1000000,"d":null,"e":{"x":1}}}')
        $seen = Read-ServicesSeen $script:File
        @($seen.Keys) | Should -Be @('redis')
        $seen['redis'] | Should -Be 1000000
        [IO.File]::WriteAllText($script:File, '{"seen":[1,2,3]}')
        (Read-ServicesSeen $script:File).Count | Should -Be 0
    }
}

Describe 'what each service uses' {
    BeforeEach { $script:Dir = New-TestDir }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'counts a shared svchost once, and CPU only from the same process a minute apart' {
        $a = New-ServicesAgent $script:Dir
        $svcs = @((New-Svc 'WAS' 'Running' 'Auto' 900), (New-Svc 'W3SVC' 'Running' 'Auto' 900), (New-Svc 'MSSQLSERVER' 'Running' 'Auto' 1200))
        $checks = @(Get-ServiceChecks $svcs @() $true)
        $readings = @{ 900 = @{ Mem = 64MB; Cpu = 10.0; Start = 1 }; 1200 = @{ Mem = 2048MB; Cpu = 100.0; Start = 2 } }
        Add-ServiceUsage $a $checks $readings 1000 4
        $by = @{}; foreach ($c in $checks) { $by[$c.name] = $c }
        $by['MSSQLSERVER']['mem_mb'] | Should -Be 2048
        $by['MSSQLSERVER'].Contains('cpu_pct') | Should -BeFalse -Because 'the first round has no pair'
        $by['W3SVC']['mem_mb'] | Should -Be 64 -Because 'W3SVC sorts first of the two in that svchost'
        $by['WAS'].Contains('mem_mb') | Should -BeFalse -Because 'the same process is not counted twice'
        $by['WAS'].Contains('Pid') | Should -BeFalse
        # 24 s of CPU in 60 s on 4 cores is 10% of the machine.
        $checks = @(Get-ServiceChecks $svcs @() $true)
        $readings = @{ 900 = @{ Mem = 64MB; Cpu = 10.0; Start = 1 }; 1200 = @{ Mem = 2048MB; Cpu = 124.0; Start = 2 } }
        Add-ServiceUsage $a $checks $readings 1060 4
        $by = @{}; foreach ($c in $checks) { $by[$c.name] = $c }
        $by['MSSQLSERVER']['cpu_pct'] | Should -Be 10
        $by['W3SVC']['cpu_pct'] | Should -Be 0
        # Restarted (another start time), or too long ago: no CPU.
        $checks = @(Get-ServiceChecks $svcs @() $true)
        Add-ServiceUsage $a $checks @{ 1200 = @{ Mem = 1MB; Cpu = 200.0; Start = 3 } } 1120 4
        @($checks | Where-Object { $_.Contains('cpu_pct') }).Count | Should -Be 0
        $checks = @(Get-ServiceChecks $svcs @() $true)
        Add-ServiceUsage $a $checks @{ 1200 = @{ Mem = 1MB; Cpu = 300.0; Start = 3 } } 1600 4
        @($checks | Where-Object { $_.Contains('cpu_pct') }).Count | Should -Be 0
    }
    It 'leaves out what a protected process will not say, and a stopped service has nothing' {
        $a = New-ServicesAgent $script:Dir
        $checks = @(Get-ServiceChecks @((New-Svc 'Redis' 'Running' 'Auto' 77), (New-Svc 'MongoDB' 'Stopped' 'Auto' 0)) @() $true)
        Add-ServiceUsage $a $checks @{ 77 = @{ Mem = $null; Cpu = $null; Start = $null } } 1000 2
        foreach ($c in $checks) { $c.Contains('mem_mb') | Should -BeFalse; $c.Contains('cpu_pct') | Should -BeFalse }
        foreach ($k in 'mem_limit_mb', 'oom_kills', 'container_id') { @($checks | Where-Object { $_.Contains($k) }).Count | Should -Be 0 }
    }
}

Describe 'the services report' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:Sent = New-Object System.Collections.ArrayList
        $script:Svcs = @((New-Svc 'W3SVC' 'Running' 'Auto' 900))
        Mock Get-WindowsServices { return , @($script:Svcs) }
        Mock Get-ProcessReadings { return @{ 900 = @{ Mem = 50MB; Cpu = 1.0; Start = 1 } } }
        Mock Invoke-Collector {
            param($Config, $Method, $PathAndQuery, $Body, $Headers, $UserAgent)
            [void]$script:Sent.Add(@{ Path = $PathAndQuery; Body = (ConvertTo-Json -InputObject $Body -Depth 6 -Compress) })
            return @{ Status = 202; Headers = @{}; Body = '{"v":1,"every":90,"stored":1}' }
        }
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'posts the protocol shape once a minute, and an empty list once to clear' {
        $a = New-ServicesAgent $script:Dir
        [void](Invoke-ServicesRound $a 1000)
        $script:Sent.Count | Should -Be 1
        $script:Sent[0].Path | Should -Be '/events/services'
        $body = ConvertFrom-Json $script:Sent[0].Body
        ($body.v, $body.client, $body.site_id) | Should -Be @(1, 'windows-agent/0.3.0', 'aaaaaaaaaaaaaaaaaaaaaaaa')
        $c = @($body.checks)[0]
        ($c.name, $c.type, $c.ok, $c.mem_mb, $c.for_s, $c.auto) | Should -Be @('W3SVC', 'unit', $true, 50, 0, $true)
        $script:Sent[0].Body | Should -Not -Match '"Pid"'
        $a.ServicesEvery | Should -Be 90
        [void](Invoke-ServicesRound $a 1030)
        $script:Sent.Count | Should -Be 1 -Because 'not yet time'
        $script:Svcs = @((New-Svc 'Spooler'))
        [void](Invoke-ServicesRound $a 1090)
        $script:Sent.Count | Should -Be 2
        (ConvertFrom-Json $script:Sent[1].Body).checks.Count | Should -Be 0
        [void](Invoke-ServicesRound $a 1180)
        $script:Sent.Count | Should -Be 2 -Because 'an empty list is sent once'
    }
    It 'reports again at once when the clock was put back past the next round' {
        $a = New-ServicesAgent $script:Dir
        [void](Invoke-ServicesRound $a 100000)
        [void](Invoke-ServicesRound $a (100000 - 86400))
        $script:Sent.Count | Should -Be 2
        [void](Invoke-ServicesRound $a (100000 - 86400 + 30))
        $script:Sent.Count | Should -Be 2 -Because 'then once a wait again'
    }
    It 'sends nothing when Windows cannot list its services' {
        Mock Get-WindowsServices { return $null }
        $a = New-ServicesAgent $script:Dir
        Invoke-ServicesRound $a 1000 | Should -BeNullOrEmpty
        $script:Sent.Count | Should -Be 0
    }
    It 'asks Windows nothing with no list and finding off' {
        $a = New-ServicesAgent $script:Dir @() $false
        [void](Invoke-ServicesRound $a 1000)
        Should -Invoke Get-WindowsServices -Times 0
        $script:Sent.Count | Should -Be 0
    }
}
