BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
    $script:Rand = New-Object System.Random 777
    $script:Ecma = [System.Text.RegularExpressions.RegexOptions]::ECMAScript
    function Test-Anchored([string]$Pattern, [string]$Text) { return [regex]::IsMatch($Text, '^(' + $Pattern + ')$', $script:Ecma) }
}

Describe 'number ranges as regular expressions' {
    It 'matches exactly the numbers of every aligned block of an octet (all 511), and nothing else' {
        $blocks = 0
        for ($size = 1; $size -le 256; $size *= 2) {
            for ($lo = 0; $lo -lt 256; $lo += $size) {
                $hi = $lo + $size - 1
                $re = New-Object System.Text.RegularExpressions.Regex ('^(' + (Get-NumberRangeRegex $lo $hi) + ')$'), $script:Ecma
                for ($n = 0; $n -le 255; $n++) {
                    $re.IsMatch([string]$n) | Should -Be ($n -ge $lo -and $n -le $hi) -Because "$n in $lo..$hi"
                }
                # Leading zeros and junk never match.
                $re.IsMatch('0' + [string]$lo) | Should -BeFalse
                $re.IsMatch('') | Should -BeFalse
                $blocks++
            }
        }
        $blocks | Should -Be 511
    }
    It 'matches exactly any range lo..hi (400 random ones)' {
        for ($i = 0; $i -lt 400; $i++) {
            $a = $script:Rand.Next(0, 256); $b = $script:Rand.Next(0, 256)
            $lo = [math]::Min($a, $b); $hi = [math]::Max($a, $b)
            $re = New-Object System.Text.RegularExpressions.Regex ('^(' + (Get-NumberRangeRegex $lo $hi) + ')$'), $script:Ecma
            for ($n = 0; $n -le 999; $n++) {
                if ($re.IsMatch([string]$n) -ne ($n -ge $lo -and $n -le $hi)) { throw "range $lo..$hi wrong at $n" }
            }
        }
    }
    It 'writes plain patterns: digits, classes, alternation, groups' {
        Get-NumberRangeRegex 0 255 | Should -Be '([0-9]|[1-9][0-9]|(1[0-9][0-9]|2([0-4][0-9]|5[0-5])))'
        Get-NumberRangeRegex 7 7 | Should -Be '7'
        Get-NumberRangeRegex 64 95 | Should -Be '(6[4-9]|[7-8][0-9]|9[0-5])'
    }
}

Describe 'IPv4 CIDR blocks as regular expressions' {
    It 'matches every address of a block and none outside it, for every prefix length' {
        for ($p = 0; $p -le 32; $p++) {
            for ($round = 0; $round -lt 12; $round++) {
                $size = [long][math]::Pow(2, 32 - $p)
                $start = [long]([math]::Floor($script:Rand.NextDouble() * [math]::Pow(2, $p))) * $size
                $end = $start + $size - 1
                $re = New-Object System.Text.RegularExpressions.Regex ('^(' + (ConvertTo-CidrRegex $start $p) + ')$'), $script:Ecma
                $inside = @($start, $end, ($start + [long][math]::Floor($script:Rand.NextDouble() * $size)))
                foreach ($x in $inside) { $re.IsMatch((Format-IPv4 $x)) | Should -BeTrue -Because "$(Format-IPv4 $x) in $(Format-IPv4 $start)/$p" }
                $outside = @(($start - 1), ($end + 1), ($start - 256), ($end + 256), ($start - $size), ($end + $size))
                foreach ($x in $outside) {
                    if ($x -lt 0 -or $x -gt 4294967295) { continue }
                    $re.IsMatch((Format-IPv4 $x)) | Should -BeFalse -Because "$(Format-IPv4 $x) not in $(Format-IPv4 $start)/$p"
                }
            }
        }
    }
    It 'agrees with the numbers on 20,000 random address and block pairs' {
        for ($i = 0; $i -lt 2000; $i++) {
            $p = $script:Rand.Next(0, 33)
            $size = [long][math]::Pow(2, 32 - $p)
            $start = [long]([math]::Floor($script:Rand.NextDouble() * [math]::Pow(2, $p))) * $size
            $re = New-Object System.Text.RegularExpressions.Regex ('^(' + (ConvertTo-CidrRegex $start $p) + ')$'), $script:Ecma
            for ($k = 0; $k -lt 10; $k++) {
                # Half near the block, half anywhere.
                if ($k % 2) { $x = [long]($script:Rand.NextDouble() * 4294967296) } else { $x = $start + [long](($script:Rand.NextDouble() * 3 - 1) * $size) }
                if ($x -lt 0 -or $x -gt 4294967295) { continue }
                if ($re.IsMatch((Format-IPv4 $x)) -ne ($x -ge $start -and $x -lt $start + $size)) { throw "$(Format-IPv4 $x) vs $(Format-IPv4 $start)/$p" }
            }
        }
    }
    It 'gives the known patterns for the shared exempt ranges' {
        ConvertTo-CidrRegex ([long](ConvertTo-IpNumber '66.249.64.0').N) 27 | Should -Be '66\.249\.64\.([0-9]|([1-2][0-9]|3[0-1]))'
        ConvertTo-CidrRegex ([long](ConvertTo-IpNumber '10.0.0.0').N) 8 | Should -Be '10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
        ConvertTo-CidrRegex ([long](ConvertTo-IpNumber '203.0.113.7').N) 32 | Should -Be '203\.0\.113\.7'
    }
}

Describe 'exempt ranges as URL Rewrite conditions' {
    It 'covers non-aligned ranges and IPv4-mapped entries, and leaves IPv6 out' {
        $ranges = @(Get-Networks @('1.2.3.5', '1.2.3.6', '1.2.3.7', '1.2.3.8', '::ffff:9.9.9.0/120', '2001:db8::/32'))
        $patterns = @(Get-ExemptPatterns $ranges)
        $patterns.Count | Should -Be 1
        foreach ($ip in '1.2.3.5', '1.2.3.8', '9.9.9.0', '9.9.9.255') { [regex]::IsMatch($ip, $patterns[0], $script:Ecma) | Should -BeTrue }
        foreach ($ip in '1.2.3.4', '1.2.3.9', '9.9.10.0', '11.2.3.5', '1.2.3.50', '2001:db8::1') { [regex]::IsMatch($ip, $patterns[0], $script:Ecma) | Should -BeFalse }
        @(Get-ExemptPatterns @(Get-Networks @('2001:db8::/32'))).Count | Should -Be 0
    }
    It 'splits many blocks into several anchored conditions that together match the same set' {
        $entries = @(0..149 | ForEach-Object { '10.{0}.{1}.0/24' -f [math]::Floor($_ * 2 / 256), (($_ * 2) % 256) })
        $ranges = @(Get-Networks $entries)
        $patterns = @(Get-ExemptPatterns $ranges 60)
        $patterns.Count | Should -Be 3
        foreach ($pat in $patterns) { $pat | Should -Match '^\^\(.*\)\$$' }
        for ($i = 0; $i -lt 2000; $i++) {
            $x = [long]167772160 + [long]($script:Rand.NextDouble() * 200000)
            $ip = Format-IPv4 $x
            $hit = @($patterns | Where-Object { [regex]::IsMatch($ip, $_, $script:Ecma) }).Count -gt 0
            $hit | Should -Be (Test-InRanges $ranges 4 ([System.Numerics.BigInteger]$x))
        }
    }
    It 'matches the Cloudflare IPv4 ranges exactly at their edges' {
        $cf = @(Get-CloudflareRanges | ForEach-Object { ConvertTo-IpRange $_ } | Where-Object { $_.F -eq 4 })
        $patterns = @(Get-ExemptPatterns $cf)
        foreach ($r in $cf) {
            foreach ($x in $r.S, $r.E) { @($patterns | Where-Object { [regex]::IsMatch((Format-IPv4 $x), $_, $script:Ecma) }).Count | Should -Be 1 }
            foreach ($x in ($r.S - 1), ($r.E + 1)) {
                $hit = @($patterns | Where-Object { [regex]::IsMatch((Format-IPv4 $x), $_, $script:Ecma) }).Count -gt 0
                $hit | Should -Be (Test-InRanges $cf 4 $x)
            }
        }
    }
}
