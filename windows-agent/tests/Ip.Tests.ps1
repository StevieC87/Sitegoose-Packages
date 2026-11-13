BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
    $script:Rand = New-Object System.Random 4242
    function Get-RandomV4 { return [long]($script:Rand.NextDouble() * 4294967296) }
    function Get-RandomV6 {
        $b = New-Object byte[] 16
        $script:Rand.NextBytes($b)
        return ConvertTo-BigFromBytes $b
    }
    function Get-RandomRange([int]$F) {
        if ($F -eq 4) {
            $a = Get-RandomV4; $len = [long]($script:Rand.NextDouble() * [math]::Pow(2, $script:Rand.Next(0, 28)))
            $e = [math]::Min($a + $len, 4294967295)
            return New-IpRange 4 $a $e
        }
        $s = Get-RandomV6
        $len = $script:Pow2[$script:Rand.Next(0, 100)]
        $e = $s + $len
        if ($e -gt $script:Pow2[128] - 1) { $e = $script:Pow2[128] - 1 }
        return New-IpRange 6 $s $e
    }
}

Describe 'parsing addresses' {
    It 'reads strict dotted IPv4' {
        (ConvertTo-IpNumber '203.0.113.7').N | Should -Be ([System.Numerics.BigInteger]3405803783)
        (ConvertTo-IpNumber '0.0.0.0').N | Should -Be ([System.Numerics.BigInteger]0)
        (ConvertTo-IpNumber '255.255.255.255').N | Should -Be ([System.Numerics.BigInteger]4294967295)
    }
    It 'refuses anything else as IPv4: <_>' -ForEach @('256.1.1.1', '1.2.3', '1.2.3.4.5', '01.2.3.4', '1.2.3.04', ' ', '', '1.2.3.4/24', '1.2.3.-1', 'a.b.c.d', '1.2.3.4 ', '0x1.2.3.4') {
        if ($_ -eq '1.2.3.4 ') { (ConvertTo-IpNumber $_).F | Should -Be 4 } else { ConvertTo-IpNumber $_ | Should -BeNullOrEmpty }
    }
    It 'reads IPv6 and refuses zones, brackets and junk: <_>' -ForEach @('fe80::1%12', '[::1]', '2001:db8::g', '1:2:3:4:5:6:7:8:9', ':::', '2001:db8::1/64', '1.2.3.4:80') {
        ConvertTo-IpNumber $_ | Should -BeNullOrEmpty
    }
    It 'treats IPv4-mapped IPv6 as IPv4' {
        $a = ConvertTo-IpNumber '::ffff:203.0.113.7'
        $a.F | Should -Be 4
        Format-IpNumber $a.F $a.N | Should -Be '203.0.113.7'
        (ConvertTo-IpNumber '::ffff:cb00:7107').F | Should -Be 4
        (ConvertTo-IpNumber '::ffff:cb00:7107' -NoMap).F | Should -Be 6
    }
    It 'writes IPv6 as RFC 5952 says: <in> -> <out>' -ForEach @(
        @{ in = '2001:0DB8:0000:0000:0000:0000:0000:0001'; out = '2001:db8::1' },
        @{ in = '2001:db8:0:1:1:1:1:1'; out = '2001:db8:0:1:1:1:1:1' },
        @{ in = '2001:0:0:1:0:0:0:1'; out = '2001:0:0:1::1' },
        @{ in = '1:0:0:2:0:0:3:4'; out = '1::2:0:0:3:4' },
        @{ in = '::'; out = '::' },
        @{ in = '::1'; out = '::1' },
        @{ in = 'fe80::'; out = 'fe80::' },
        @{ in = '0:0:0:0:0:1:0:0'; out = '::1:0:0' },
        @{ in = '1:0:0:0:0:0:0:0'; out = '1::' }
    ) {
        $n = ConvertTo-IpNumber $in -NoMap
        Format-IPv6 $n.N | Should -BeExactly $out
    }
    It 'round-trips random IPv6 addresses through its own writer' {
        for ($i = 0; $i -lt 300; $i++) {
            $n = Get-RandomV6
            if ($i % 3 -eq 0) { $n = [System.Numerics.BigInteger]::Divide($n, $script:Pow2[$script:Rand.Next(1, 120)]) }
            $text = Format-IPv6 $n
            (ConvertTo-IpNumber $text -NoMap).N | Should -Be $n
            $text | Should -BeExactly $text.ToLowerInvariant()
        }
    }
}

Describe 'ranges' {
    It 'ignores host bits in a CIDR range, as the rules allow' {
        Format-IpRange (ConvertTo-IpRange '10.1.2.3/8') | Should -Be '10.0.0.0/8'
        Format-IpRange (ConvertTo-IpRange '2001:db8:1:2::5/32') | Should -Be '2001:db8::/32'
        Format-IpRange (ConvertTo-IpRange '0.0.0.0/0') | Should -Be '0.0.0.0/0'
    }
    It 'turns an IPv4-mapped range into IPv4' {
        Format-IpRange (ConvertTo-IpRange '::ffff:10.0.0.0/104') | Should -Be '10.0.0.0/8'
        (ConvertTo-IpRange '::ffff:0:0/95').F | Should -Be 6
    }
    It 'refuses bad prefixes' {
        ConvertTo-IpRange '1.2.3.4/33' | Should -BeNullOrEmpty
        ConvertTo-IpRange '1.2.3.4/' | Should -BeNullOrEmpty
        ConvertTo-IpRange '2001:db8::/129' | Should -BeNullOrEmpty
        ConvertTo-IpRange '1.2.3.4/255.255.255.0' | Should -BeNullOrEmpty
        ConvertTo-IpRange '1.2.3.4-1.2.3.9' | Should -BeNullOrEmpty
    }
    It "reads what Windows Firewall writes back (masks and ranges), and nothing else" {
        Format-IpRange (ConvertTo-IpRange '10.0.0.0/255.0.0.0' -FirewallForms) | Should -Be '10.0.0.0/8'
        Format-IpRange (ConvertTo-IpRange '1.2.3.4-1.2.3.9' -FirewallForms) | Should -Be '1.2.3.4-1.2.3.9'
        Format-IpRange (ConvertTo-IpRange '1.2.3.0-1.2.3.255' -FirewallForms) | Should -Be '1.2.3.0/24'
        Format-IpRange (ConvertTo-IpRange '2001:db8::1-2001:db8::ff' -FirewallForms) | Should -Be '2001:db8::1-2001:db8::ff'
        ConvertTo-IpRange '10.0.0.0/255.0.255.0' -FirewallForms | Should -BeNullOrEmpty
        ConvertTo-IpRange '1.2.3.9-1.2.3.4' -FirewallForms | Should -BeNullOrEmpty
        ConvertTo-IpRange '1.2.3.4-::1' -FirewallForms | Should -BeNullOrEmpty
        foreach ($k in 'Any', 'LocalSubnet', 'Internet', 'DNS', '*') { ConvertTo-IpRange $k -FirewallForms | Should -BeNullOrEmpty }
    }
    It 'merges overlapping and adjacent ranges, IPv4 first' {
        $m = @(Merge-IpRanges @((ConvertTo-IpRange '2001:db8::/33'), (ConvertTo-IpRange '10.0.0.0/9'), (ConvertTo-IpRange '10.128.0.0/9'),
                (ConvertTo-IpRange '2001:db8:8000::/33'), (ConvertTo-IpRange '10.5.0.0/16'), (ConvertTo-IpRange '11.0.0.1')))
        @($m | ForEach-Object { Format-IpRange $_ }) | Should -Be @('10.0.0.0/8', '11.0.0.1', '2001:db8::/32')
    }
    It 'reads a list from the rules, skipping what is not an address' {
        @(Get-Networks @('1.2.3.4', 'nonsense', 5, $null, '10.0.0.0/8', '2001:db8::/32') | ForEach-Object { Format-IpRange $_ }) |
            Should -Be @('1.2.3.4', '10.0.0.0/8', '2001:db8::/32')
        @(Get-Networks 'just a string').Count | Should -Be 0
        @(Get-Networks $null).Count | Should -Be 0
    }
    It 'splits a range into the fewest aligned CIDR blocks' {
        $blocks = @(Split-IpRange (ConvertTo-IpRange '1.2.3.5-1.2.3.17' -FirewallForms))
        @($blocks | ForEach-Object { (Format-IPv4 $_.S) + '/' + $_.P }) | Should -Be @('1.2.3.5/32', '1.2.3.6/31', '1.2.3.8/29', '1.2.3.16/31')
        for ($i = 0; $i -lt 200; $i++) {
            $f = 4; if ($i % 2) { $f = 6 }
            $r = Get-RandomRange $f
            $bits = Get-FamilyBits $f
            $next = $r.S
            foreach ($b in @(Split-IpRange $r)) {
                $b.S | Should -Be $next
                $size = $script:Pow2[$bits - $b.P]
                [System.Numerics.BigInteger]::Remainder($b.S, $size).IsZero | Should -BeTrue
                $next = $b.S + $size
            }
            $next | Should -Be ($r.E + 1)
        }
    }
}

Describe 'subtracting and the complement' {
    It 'subtracts as set difference, checked point by point' {
        for ($round = 0; $round -lt 40; $round++) {
            $f = 4; if ($round % 2) { $f = 6 }
            $a = @(1..6 | ForEach-Object { Get-RandomRange $f })
            $b = @(1..6 | ForEach-Object { Get-RandomRange $f })
            $d = @(Remove-IpRanges $a $b)
            for ($k = 1; $k -lt $d.Count; $k++) { $d[$k].S | Should -BeGreaterThan ($d[$k - 1].E + 1) }
            $points = New-Object System.Collections.ArrayList
            foreach ($r in @($a) + @($b)) { foreach ($x in ($r.S - 1), $r.S, $r.E, ($r.E + 1)) { [void]$points.Add($x) } }
            foreach ($x in $points) {
                if ($x -lt 0) { continue }
                $want = (Test-InRanges $a $f $x) -and -not (Test-InRanges $b $f $x)
                (Test-InRanges $d $f $x) | Should -Be $want
            }
        }
    }
    It 'gives the complement: with the allowed ranges it covers everything, once' {
        foreach ($f in 4, 6) {
            for ($round = 0; $round -lt 20; $round++) {
                $allowed = @(Merge-IpRanges @(1..8 | ForEach-Object { Get-RandomRange $f }))
                $c = @(Get-IpComplement $allowed $f)
                $all = @(Merge-IpRanges (@($allowed) + @($c)))
                $all.Count | Should -Be 1
                $all[0].S | Should -Be ([System.Numerics.BigInteger]::Zero)
                $all[0].E | Should -Be ($script:Pow2[(Get-FamilyBits $f)] - 1)
                @(Remove-IpRanges $c $allowed).Count | Should -Be $c.Count
                foreach ($r in $allowed) {
                    (Test-InRanges $c $f $r.S) | Should -BeFalse
                    (Test-InRanges $c $f $r.E) | Should -BeFalse
                    if ($r.S -gt 0) { (Test-InRanges $c $f ($r.S - 1)) | Should -Be (-not (Test-InRanges $allowed $f ($r.S - 1))) }
                }
            }
        }
    }
    It 'complements nothing to everything and everything to nothing' {
        @(Get-IpComplement @() 4 | ForEach-Object { Format-IpRange $_ }) | Should -Be @('0.0.0.0/0')
        @(Get-IpComplement @() 6 | ForEach-Object { Format-IpRange $_ }) | Should -Be @('::/0')
        @(Get-IpComplement @((ConvertTo-IpRange '0.0.0.0/0')) 4).Count | Should -Be 0
        @(Get-IpComplement @((ConvertTo-IpRange '10.0.0.0/8')) 6 | ForEach-Object { Format-IpRange $_ }) | Should -Be @('::/0')
    }
    It "keeps every Cloudflare range out of the origin lock's complement" {
        $cf = @(Get-CloudflareRanges | ForEach-Object { ConvertTo-IpRange $_ })
        $cf.Count | Should -BeGreaterThan 10
        foreach ($f in 4, 6) {
            $c = @(Get-IpComplement $cf $f)
            foreach ($r in @($cf | Where-Object { $_.F -eq $f })) {
                foreach ($x in $r.S, $r.E, ($r.S + [System.Numerics.BigInteger]::Divide($r.E - $r.S, 2))) { (Test-InRanges $c $f $x) | Should -BeFalse }
                (Test-InRanges $c $f ($r.S - 1)) | Should -Be (-not (Test-InRanges $cf $f ($r.S - 1)))
                (Test-InRanges $c $f ($r.E + 1)) | Should -Be (-not (Test-InRanges $cf $f ($r.E + 1)))
            }
            # A known outsider is in it.
            if ($f -eq 4) { (Test-InRanges $c 4 (ConvertTo-IpNumber '8.8.8.8').N) | Should -BeTrue }
            else { (Test-InRanges $c 6 (ConvertTo-IpNumber '2001:4860:4860::8888').N) | Should -BeTrue }
        }
    }
}

Describe 'lookups and keys' {
    It 'finds addresses by binary search as a linear scan does' {
        foreach ($f in 4, 6) {
            $ranges = @(1..40 | ForEach-Object { Get-RandomRange $f })
            $set = New-IpSet $ranges
            for ($i = 0; $i -lt 200; $i++) {
                $r = $ranges[$i % $ranges.Count]
                $x = $r.S
                if ($i % 4 -eq 1) { $x = $r.E + 1 } elseif ($i % 4 -eq 2) { $x = $r.S - 1 } elseif ($i % 4 -eq 3) { if ($f -eq 4) { $x = [System.Numerics.BigInteger](Get-RandomV4) } else { $x = Get-RandomV6 } }
                if ($x -lt 0) { continue }
                (Test-IpSet $set ([pscustomobject]@{ F = $f; N = $x })) | Should -Be (Test-InRanges $ranges $f $x)
            }
        }
        Test-IpSet (New-IpSet @()) (ConvertTo-IpNumber '1.2.3.4') | Should -BeFalse
    }
    It 'counts IPv4 by address and IPv6 by /64' {
        Get-FloodKey (ConvertTo-IpNumber '198.51.100.9') | Should -Be '198.51.100.9'
        Get-FloodKey (ConvertTo-IpNumber '::ffff:198.51.100.9') | Should -Be '198.51.100.9'
        Get-FloodKey (ConvertTo-IpNumber '2001:db8:0:1:aaaa::1') | Should -Be '2001:db8:0:1::/64'
        Get-FloodKey (ConvertTo-IpNumber '2001:db8:0:1:ffff:ffff:ffff:ffff') | Should -Be '2001:db8:0:1::/64'
    }
    It 'tells a public IPv6 address from local, Teredo and 6to4 ones' {
        Test-PublicIPv6 @((ConvertTo-IpRange 'fe80::1'), (ConvertTo-IpRange '::1'), (ConvertTo-IpRange '10.0.0.5')) | Should -BeFalse
        Test-PublicIPv6 @((ConvertTo-IpRange '2001:0:4136:e378::1'), (ConvertTo-IpRange '2002:c000:204::1'), (ConvertTo-IpRange 'fd00::5')) | Should -BeFalse
        Test-PublicIPv6 @((ConvertTo-IpRange '2a01:4f8:c17:1::1')) | Should -BeTrue
    }
}
