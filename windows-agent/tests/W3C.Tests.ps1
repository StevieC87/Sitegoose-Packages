BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
    $script:Header = '#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken'
    $script:Fields = Get-W3CFields $script:Header
    $script:Sw = '#Software: Microsoft Internet Information Services 10.0'
    function New-Line([string]$Ip = '198.51.100.9', [string]$Path = '/pricing', [string]$Status = '200', [string]$Sub = '0',
        [string]$Ua = 'Mozilla/5.0+(Windows+NT+10.0)', [string]$Method = 'GET', [string]$Time = '16:20:01') {
        return "2026-11-03 $Time 10.0.0.5 $Method $Path - 443 - $Ip $Ua - $Status $Sub 0 15"
    }
    function Write-Log([string]$Path, [string[]]$Lines) {
        [IO.File]::AppendAllText($Path, (($Lines -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    }
}

Describe 'the #Fields line' {
    It 'gives the position of each field' {
        $script:Fields.Valid | Should -BeTrue
        $script:Fields.Count | Should -Be 15
        $script:Fields.Map['c-ip'] | Should -Be 8
        $script:Fields.Map['cs(user-agent)'] | Should -Be 9
    }
    It 'is not valid without c-ip, and not a header at all when malformed' {
        (Get-W3CFields '#Fields: date time cs-method cs-uri-stem').Valid | Should -BeFalse
        Get-W3CFields '#Fields: date time c-ip <script>' | Should -BeNullOrEmpty
        Get-W3CFields '#Software: Microsoft Internet Information Services 10.0' | Should -BeNullOrEmpty
        Get-W3CFields ' #Fields: c-ip' | Should -BeNullOrEmpty
        Get-W3CFields '#Fields:' | Should -BeNullOrEmpty
    }
}

Describe 'a log line' {
    It 'reads the request' {
        $e = ConvertFrom-W3CLine (New-Line -Method 'get' -Status '503' -Sub '71') $script:Fields
        Format-IpNumber $e.Ip.F $e.Ip.N | Should -Be '198.51.100.9'
        $e.Method | Should -Be 'GET'
        $e.Path | Should -Be '/pricing'
        $e.Status | Should -Be 503
        $e.SubStatus | Should -Be 71
        $e.Ua | Should -Be 'Mozilla/5.0 (Windows NT 10.0)'
        $e.Time | Should -Be 1793722801
    }
    It "reads IPv6 c-ip and '-' as empty" {
        $e = ConvertFrom-W3CLine (New-Line -Ip '2001:db8::7' -Ua '-') $script:Fields
        $e.Ip.F | Should -Be 6
        $e.Ua | Should -Be ''
    }
    It 'drops a line with more fields than the header says (a forged value with a space can not shift c-ip)' {
        ConvertFrom-W3CLine ((New-Line) + ' 203.0.113.66') $script:Fields | Should -BeNullOrEmpty
        ConvertFrom-W3CLine (New-Line -Ua 'evil 203.0.113.66') $script:Fields | Should -BeNullOrEmpty
        ConvertFrom-W3CLine (New-Line -Path '/a 1.1.1.1') $script:Fields | Should -BeNullOrEmpty
    }
    It 'drops a line with fewer fields, or with no address in c-ip' {
        ConvertFrom-W3CLine '2026-11-03 16:20:01 10.0.0.5 GET /' $script:Fields | Should -BeNullOrEmpty
        ConvertFrom-W3CLine (New-Line -Ip '-') $script:Fields | Should -BeNullOrEmpty
        ConvertFrom-W3CLine (New-Line -Ip '1.2.3.4,5.6.7.8') $script:Fields | Should -BeNullOrEmpty
        ConvertFrom-W3CLine (New-Line -Ip 'fe80::1%7') $script:Fields | Should -BeNullOrEmpty
        ConvertFrom-W3CLine (New-Line) $null | Should -BeNullOrEmpty
    }
    It "drops a line whose date, time or method aren't what IIS writes" {
        ConvertFrom-W3CLine ((New-Line).Replace('2026-11-03', '#Fields:')) $script:Fields | Should -BeNullOrEmpty
        ConvertFrom-W3CLine ((New-Line).Replace('2026-11-03', '2026-11-3')) $script:Fields | Should -BeNullOrEmpty
        ConvertFrom-W3CLine (New-Line -Time '16:20') $script:Fields | Should -BeNullOrEmpty
        ConvertFrom-W3CLine (New-Line -Method '<x>') $script:Fields | Should -BeNullOrEmpty
        ConvertFrom-W3CLine (New-Line -Method '-') $script:Fields | Should -BeNullOrEmpty
        ConvertFrom-W3CLine (New-Line -Method 'PROPFIND') $script:Fields | Should -Not -BeNullOrEmpty
    }
    It 'takes the address from c-ip only, never from a logged X-Forwarded-For' {
        $f = Get-W3CFields '#Fields: date time cs-method cs-uri-stem c-ip cs(X-Forwarded-For) sc-status sc-substatus'
        $e = ConvertFrom-W3CLine '2026-11-03 16:20:01 GET / 203.0.113.7 198.51.100.200 200 0' $f
        Format-IpNumber $e.Ip.F $e.Ip.N | Should -Be '203.0.113.7'
        $f2 = Get-W3CFields '#Fields: date time cs(X-Forwarded-For) c-ip sc-status'
        $e2 = ConvertFrom-W3CLine '2026-11-03 16:20:01 198.51.100.200 203.0.113.7 200' $f2
        Format-IpNumber $e2.Ip.F $e2.Ip.N | Should -Be '203.0.113.7'
    }
    It 'follows the field order a header gives, whatever it is' {
        $f = Get-W3CFields '#Fields: c-ip sc-status cs-uri-stem'
        $e = ConvertFrom-W3CLine '192.0.2.1 404 /x' $f
        $e.Status | Should -Be 404
        $e.Path | Should -Be '/x'
        $e.Time | Should -Be 0
    }
}

Describe 'following a log folder' {
    BeforeEach {
        $script:Dir = New-TestDir
        $script:Tail = New-LogTail $script:Dir
    }
    AfterEach { Remove-Item -Recurse -Force $script:Dir }

    It 'reads a log first seen from its end, then what is added' {
        $log = Join-Path $script:Dir 'u_ex261103.log'
        Write-Log $log @('#Software: Microsoft Internet Information Services 10.0', '#Version: 1.0', $script:Header, (New-Line -Ip '192.0.2.1'))
        @(Read-LogTail $script:Tail).Count | Should -Be 0
        Write-Log $log @((New-Line -Ip '192.0.2.2'), (New-Line -Ip '192.0.2.3'))
        $e = @(Read-LogTail $script:Tail)
        @($e | ForEach-Object { Format-IpNumber $_.Ip.F $_.Ip.N }) | Should -Be @('192.0.2.2', '192.0.2.3')
        @(Read-LogTail $script:Tail).Count | Should -Be 0
    }
    It 'keeps a half-written line until its end arrives' {
        $log = Join-Path $script:Dir 'u_ex261103.log'
        Write-Log $log @($script:Sw, $script:Header)
        [void](Read-LogTail $script:Tail)
        $line = New-Line -Ip '192.0.2.9'
        [IO.File]::AppendAllText($log, $line.Substring(0, 20))
        @(Read-LogTail $script:Tail).Count | Should -Be 0
        [IO.File]::AppendAllText($log, $line.Substring(20) + "`r`n")
        $e = @(Read-LogTail $script:Tail)
        $e.Count | Should -Be 1
        Format-IpNumber $e[0].Ip.F $e[0].Ip.N | Should -Be '192.0.2.9'
    }
    It "uses the header in force: IIS writes a new one mid-file when it restarts" {
        $log = Join-Path $script:Dir 'u_ex261103.log'
        Write-Log $log @($script:Sw, $script:Header, (New-Line), $script:Sw, '#Version: 1.0', '#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-substatus')
        [void](Read-LogTail $script:Tail)
        Write-Log $log @('2026-11-03 16:21:00 192.0.2.44 GET /new 403 502')
        $e = @(Read-LogTail $script:Tail)
        $e.Count | Should -Be 1
        $e[0].Path | Should -Be '/new'
        $e[0].SubStatus | Should -Be 502
    }
    It "reads the old day's file to its end, then the new one from its start" {
        $old = Join-Path $script:Dir 'u_ex261103.log'
        Write-Log $old @($script:Sw, $script:Header)
        (Get-Item $old).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-10)
        [void](Read-LogTail $script:Tail)
        Write-Log $old @((New-Line -Ip '192.0.2.10'))
        (Get-Item $old).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-5)
        $new = Join-Path $script:Dir 'u_ex261104.log'
        Write-Log $new @($script:Sw, '#Version: 1.0', $script:Header, (New-Line -Ip '192.0.2.11'))
        $e = @(Read-LogTail $script:Tail)
        @($e | ForEach-Object { Format-IpNumber $_.Ip.F $_.Ip.N }) | Should -Be @('192.0.2.10', '192.0.2.11')
        $script:Tail.Path | Should -Be $new
    }
    It 'starts again from the top of a truncated file' {
        $log = Join-Path $script:Dir 'u_ex261103.log'
        Write-Log $log @($script:Sw, $script:Header, (New-Line), (New-Line), (New-Line))
        [void](Read-LogTail $script:Tail)
        [IO.File]::WriteAllText($log, '')
        Write-Log $log @($script:Sw, $script:Header, (New-Line -Ip '192.0.2.77'))
        $e = @(Read-LogTail $script:Tail)
        $e.Count | Should -Be 1
        Format-IpNumber $e[0].Ip.F $e[0].Ip.N | Should -Be '192.0.2.77'
    }
    It 'skips a backlog of more than four reads rather than chasing it' {
        $log = Join-Path $script:Dir 'u_ex261103.log'
        Write-Log $log @($script:Sw, $script:Header)
        [void](Read-LogTail $script:Tail)
        Write-Log $log @(1..200 | ForEach-Object { New-Line -Ip ('192.0.2.' + ($_ % 250)) })
        $e = @(Read-LogTail $script:Tail 2000)
        $e.Count | Should -BeLessThan 25
        $e.Count | Should -BeGreaterThan 5
        foreach ($x in $e) { $x.Path | Should -Be '/pricing' }
    }
    It "takes a #Fields line only from IIS's own header block" {
        $log = Join-Path $script:Dir 'u_ex261103.log'
        Write-Log $log @($script:Sw, $script:Header, (New-Line -Ip '192.0.2.30'))
        [void](Read-LogTail $script:Tail)
        # No #Software line in its block: not IIS's header, the old fields stay.
        Write-Log $log @('#Fields: c-ip date time cs-method cs-uri-stem', (New-Line -Ip '192.0.2.31'))
        $e = @(Read-LogTail $script:Tail)
        $e.Count | Should -Be 1
        Format-IpNumber $e[0].Ip.F $e[0].Ip.N | Should -Be '192.0.2.31'
        # A #Software line in a block of its own doesn't open the next one.
        Write-Log $log @($script:Sw, (New-Line -Ip '192.0.2.32'), '#Fields: c-ip sc-status', '192.0.2.33 200')
        $e = @(Read-LogTail $script:Tail)
        @($e | ForEach-Object { Format-IpNumber $_.Ip.F $_.Ip.N }) | Should -Be @('192.0.2.32')
        $f = Find-W3CFields $log (Get-Item $log).Length
        $f.Count | Should -Be 15
    }
    It 'ignores files that are not IIS logs' {
        Write-Log (Join-Path $script:Dir 'notes.txt') @('x')
        Write-Log (Join-Path $script:Dir 'u_ex261103.log.bak') @('x')
        @(Get-LogFiles $script:Dir).Count | Should -Be 0
        Write-Log (Join-Path $script:Dir 'u_ex26110312.log') @('x')
        Write-Log (Join-Path $script:Dir 'ex261103.log') @('x')
        Write-Log (Join-Path $script:Dir 'u_ex261103_x.log') @('x')
        @(Get-LogFiles $script:Dir).Count | Should -Be 3
    }
    It 'finds the header in force for a log first seen in the middle' {
        $log = Join-Path $script:Dir 'u_ex261103.log'
        Write-Log $log @($script:Sw, '#Fields: c-ip sc-status', '1.2.3.4 200', $script:Sw, '#Fields: date time c-ip cs-uri-stem', '2026-11-03 16:20:01 1.2.3.4 /x')
        $f = Find-W3CFields $log (Get-Item $log).Length
        $f.Count | Should -Be 4
    }
}

Describe 'the token bucket' {
    It 'lets burst + 1 through at once, then the rate' {
        $b = @{}
        $ok = @(1..61 | ForEach-Object { Test-TokenBucket $b 'k' 100 20 61 })
        @($ok | Where-Object { $_ }).Count | Should -Be 61
        Test-TokenBucket $b 'k' 100 20 61 | Should -BeFalse
        Test-TokenBucket $b 'k' 100.0625 20 61 | Should -BeTrue
        Test-TokenBucket $b 'k' 100.0625 20 61 | Should -BeFalse
        @(1..20 | ForEach-Object { Test-TokenBucket $b 'k' 101.0625 20 61 } | Where-Object { $_ }).Count | Should -Be 20
    }
    It 'gives nothing back for a time that runs backwards' {
        $b = @{}
        [void](Test-TokenBucket $b 'k' 100 1 1)
        Test-TokenBucket $b 'k' 50 1 1 | Should -BeFalse
        Test-TokenBucket $b 'k' 100.5 1 1 | Should -BeFalse
        Test-TokenBucket $b 'k' 101 1 1 | Should -BeTrue
    }
    It 'keeps memory bounded: full buckets go, then the longest idle' {
        $b = New-Object System.Collections.Hashtable
        for ($i = 0; $i -lt 300; $i++) { [void](Test-TokenBucket $b ('a' + $i) (1000 + $i) 1 5) }
        Limit-Buckets $b 1000000 1 5 100
        $b.Count | Should -Be 0
        for ($i = 0; $i -lt 300; $i++) { for ($k = 0; $k -lt 5; $k++) { [void](Test-TokenBucket $b ('a' + $i) (2000 + $i * 0.001) 0.0001 5) } }
        Limit-Buckets $b 2000.3 0.0001 5 100
        $b.Count | Should -BeLessOrEqual 100
        $b.ContainsKey('a299') | Should -BeTrue
        $b.ContainsKey('a0') | Should -BeFalse
    }
}
