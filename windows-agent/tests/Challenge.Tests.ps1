BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
    $script:Cases = Get-Cases
    $script:Secret = [string]$script:Cases.secret
    $script:Plan = Get-AgentPlan (ConvertFrom-Json (ConvertTo-Json -Depth 5 -InputObject @{
                v = 1; enabled = $true; mode = 'block'; challenge = $script:Cases.challenge }))
    function Get-RuleVars($Request, [string]$Cookie, [string]$Site = '1') {
        return @{
            REQUEST_METHOD = [string]$Request.method; HTTP_ACCEPT = [string]$Request.accept; URL = [string]$Request.path
            REMOTE_ADDR = [string]$Request.ip; HTTP_COOKIE = $Cookie; INSTANCE_ID = $Site
        }
    }
    function Get-DayTokens([double]$Now) {
        $day = Get-UtcDay $Now
        return @((Get-ChallengeToken $script:Secret $day), (Get-ChallengeToken $script:Secret ($day - 1)))
    }
}

Describe 'the pass, from the shared cases' {
    It 'gives every address the pass of the cases' {
        foreach ($t in $script:Cases.tokens) {
            $day = Get-UtcDay $t.now
            if ($t.who -ceq '*') { $who = '*' } else { $who = Get-ChallengeWho $t.ip; $who | Should -BeExactly $t.who }
            Get-ChallengeToken $script:Secret $day $who | Should -BeExactly $t.token -Because $t.ip
        }
    }
    It "gives the server-level pass (who = *) the cases' nginx token" {
        Get-ChallengeToken $script:Secret (Get-UtcDay 1793750400) | Should -BeExactly '20761.41f343eed3c7494bababe53abee29292'
    }
    It 'checks every cookie of the cases' {
        foreach ($c in $script:Cases.checks) {
            Test-ChallengePass $script:Secret ([string]$c.cookie) (Get-ChallengeWho $c.ip) $c.now | Should -Be ([bool]$c.valid) -Because $c.why
        }
    }
    It 'makes every decision of the cases (the address-bound reference)' {
        foreach ($d in $script:Cases.decisions) {
            Test-ChallengeNeeded $d.request $script:Plan.challenge $d.now $script:Secret | Should -Be ([bool]$d.challenged) -Because $d.why
        }
    }
}

Describe 'the IIS rule against the shared decisions' {
    It 'decides as the reference does, with the server-level pass, and never checks IPv6' {
        foreach ($d in $script:Cases.decisions) {
            $rule = Get-CheckRule $script:Plan.challenge (Get-DayTokens $d.now) @('1') 71
            $cookie = [string]$d.request.cookie
            # The rule's pass is the server-level one: a valid address pass maps
            # to it, anything else stays as it is.
            if (Test-ChallengePass $script:Secret $cookie (Get-ChallengeWho $d.request.ip) $d.now) {
                $cookie = Get-ChallengeToken $script:Secret (Get-UtcDay $d.now)
            }
            $expected = [bool]$d.challenged -and ((ConvertTo-IpNumber $d.request.ip).F -eq 4)
            Invoke-RewriteRule $rule (Get-RuleVars $d.request ('__sg_passn=' + $cookie)) | Should -Be $expected -Because $d.why
        }
    }
}

Describe 'the IIS rule on its own' {
    BeforeAll {
        $script:Now = 1793750400
        $script:Tokens = Get-DayTokens $script:Now
        $script:Rule = Get-CheckRule $script:Plan.challenge $script:Tokens @('3', '1', '12') 71
        $script:Page = @{ method = 'GET'; accept = 'text/html'; path = '/pricing'; ip = '198.51.100.9' }
        function Test-Checked([string]$Cookie, [hashtable]$Change = @{}) {
            $v = Get-RuleVars $script:Page $Cookie '3'
            foreach ($k in $Change.Keys) { $v[$k] = $Change[$k] }
            return Invoke-RewriteRule $script:Rule $v
        }
    }
    It "lets today's and yesterday's pass through, wherever it sits among the cookies" {
        $t = $script:Tokens[0]; $y = $script:Tokens[1]
        Test-Checked '' | Should -BeTrue
        Test-Checked "__sg_passn=$t" | Should -BeFalse
        Test-Checked "__sg_passn=$y" | Should -BeFalse
        Test-Checked "a=1; __sg_passn=$t" | Should -BeFalse
        Test-Checked "a=1;__sg_passn=$t;b=2" | Should -BeFalse
        Test-Checked "__sg_passn=$t; b=2" | Should -BeFalse
    }
    It 'checks look-alikes: an old pass, a longer or shorter one, upper case, another name' {
        $t = $script:Tokens[0]
        $old = Get-ChallengeToken $script:Secret ((Get-UtcDay $script:Now) - 2)
        Test-Checked "__sg_passn=$old" | Should -BeTrue
        Test-Checked ("__sg_passn=" + $t + '0') | Should -BeTrue
        Test-Checked ("__sg_passn=" + $t.Substring(0, $t.Length - 1)) | Should -BeTrue
        Test-Checked ("__sg_passn=" + $t.ToUpperInvariant()) | Should -BeTrue
        Test-Checked ("x__sg_passn=" + $t) | Should -BeTrue
        Test-Checked ("__sg_pass=" + $t) | Should -BeTrue
        Test-Checked ("__SG_PASSN=" + $t) | Should -BeTrue
        # The dot is literal, not "any character".
        Test-Checked ("__sg_passn=" + $t.Replace('.', 'x')) | Should -BeTrue
    }
    It 'never checks an IPv6 visitor, in any of the forms IIS writes' {
        foreach ($ip in '2001:db8::1', '::ffff:198.51.100.9', '[2001:db8::1]', 'fe80::1%12', '::1') {
            Test-Checked '' @{ REMOTE_ADDR = $ip } | Should -BeFalse -Because $ip
        }
    }
    It 'only checks the sites whose error page is ours' {
        Test-Checked '' @{ INSTANCE_ID = '1' } | Should -BeTrue
        Test-Checked '' @{ INSTANCE_ID = '12' } | Should -BeTrue
        Test-Checked '' @{ INSTANCE_ID = '2' } | Should -BeFalse
        Test-Checked '' @{ INSTANCE_ID = '31' } | Should -BeFalse
        Test-Checked '' @{ INSTANCE_ID = '' } | Should -BeFalse
    }
    It 'checks exactly outside the exempt ranges, at their edges' {
        Test-Checked '' @{ REMOTE_ADDR = '66.249.64.0' } | Should -BeFalse
        Test-Checked '' @{ REMOTE_ADDR = '66.249.64.31' } | Should -BeFalse
        Test-Checked '' @{ REMOTE_ADDR = '66.249.64.32' } | Should -BeTrue
        Test-Checked '' @{ REMOTE_ADDR = '66.249.63.255' } | Should -BeTrue
        Test-Checked '' @{ REMOTE_ADDR = '166.249.64.5' } | Should -BeTrue
        Test-Checked '' @{ REMOTE_ADDR = '66.249.64.5' } | Should -BeFalse
    }
    It 'skips the prefixes in any case, and only as prefixes' {
        Test-Checked '' @{ URL = '/api/x' } | Should -BeFalse
        Test-Checked '' @{ URL = '/Wp-Json/x' } | Should -BeFalse
        Test-Checked '' @{ URL = '/.well-known/acme-challenge/x' } | Should -BeFalse
        Test-Checked '' @{ URL = '/x/api/' } | Should -BeTrue
        Test-Checked '' @{ URL = '/apiary' } | Should -BeTrue
        Test-Checked '' @{ URL = '/xwell-known/' } | Should -BeTrue
    }
    It 'leaves alone what is not a page asked for by a browser' {
        Test-Checked '' @{ REQUEST_METHOD = 'POST' } | Should -BeFalse
        Test-Checked '' @{ REQUEST_METHOD = 'OPTIONS' } | Should -BeFalse
        Test-Checked '' @{ REQUEST_METHOD = 'GETX' } | Should -BeFalse
        Test-Checked '' @{ REQUEST_METHOD = 'head' } | Should -BeTrue
        Test-Checked '' @{ HTTP_ACCEPT = '*/*' } | Should -BeFalse
        Test-Checked '' @{ HTTP_ACCEPT = '' } | Should -BeFalse
        Test-Checked '' @{ HTTP_ACCEPT = 'Text/HTML;q=0.9' } | Should -BeTrue
    }
    It 'is a 503 with our substatus, sets the server variable, and stops' {
        $xml = ConvertTo-ConfigXml $script:Rule
        $xml | Should -Match '<action type="CustomResponse" statusCode="503" subStatusCode="71"'
        $xml | Should -Match '<set name="SG_CHECK" value="1" replace="true" />'
        $xml | Should -Match 'stopProcessing="true"'
        $xml | Should -Match '<match url="\.\*" />'
        $xml | Should -Match 'input="\{INSTANCE_ID\}" pattern="\^\(1\|3\|12\)\$"'
    }
    It 'stays out of the way with no skip prefixes or exempt ranges' {
        $r = Get-CheckRule @{ skip = @(); exempt = @() } $script:Tokens @('1') 71
        Invoke-RewriteRule $r (Get-RuleVars $script:Page '' '1') | Should -BeTrue
        @(@($r.Children | Where-Object { $_.Name -eq 'conditions' })[0].Items).Count | Should -Be 5
    }
    It 'splits a long exempt list over several conditions' {
        $ex = @(Get-Networks @(0..199 | ForEach-Object { '10.{0}.{1}.0/24' -f [math]::Floor($_ * 2 / 256), (($_ * 2) % 256) }))
        $r = Get-CheckRule @{ skip = @('/api/'); exempt = $ex } $script:Tokens @('1') 71
        $n = @(@($r.Children | Where-Object { $_.Name -eq 'conditions' })[0].Items).Count
        $n | Should -BeGreaterThan 7
        Invoke-RewriteRule $r (Get-RuleVars @{ method = 'GET'; accept = 'text/html'; path = '/'; ip = '10.1.140.9' } '' '1') | Should -BeFalse
        Invoke-RewriteRule $r (Get-RuleVars @{ method = 'GET'; accept = 'text/html'; path = '/'; ip = '10.1.141.9' } '' '1') | Should -BeTrue
    }
}

Describe 'the check page' {
    BeforeAll {
        $script:Token = Get-ChallengeToken $script:Secret 20761
        $script:Html = Get-CheckPage $script:Token
    }
    It 'carries the pass in data-pass and its one script and style allowed by hash' {
        $script:Html | Should -Match ('data-pass="' + [regex]::Escape($script:Token) + '"')
        $m = [regex]::Match($script:Html, '<script>(.*)</script>')
        $m.Success | Should -BeTrue
        $csp = Get-CheckCsp
        $csp | Should -Match ([regex]::Escape((Get-CspHash $m.Groups[1].Value)))
        $style = [regex]::Match($script:Html, '<style>(.*)</style>').Groups[1].Value
        $csp | Should -Match ([regex]::Escape((Get-CspHash $style)))
        ([regex]::Matches($script:Html, '<script')).Count | Should -Be 1
        $script:Html | Should -Not -Match ' on[a-z]+='
    }
    It 'gives the known hash for a known text (the CSP form)' {
        Get-CspHash 'abc' | Should -BeExactly "'sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0='"
    }
    It 'forbids framing and everything else in its policy' {
        $csp = Get-CheckCsp
        $csp | Should -Match "default-src 'none'"
        $csp | Should -Match "frame-ancestors 'none'"
        $csp | Should -Match "form-action 'none'"
        $csp | Should -Not -Match 'unsafe'
    }
    It 'reloads only when the cookie reads back, and at most 3 times a minute' {
        $s = Get-CheckScript
        $s | Should -Match '__sg_passn='
        $s | Should -Match 'indexOf\(" __sg_passn="\+v\)<0'
        $s | Should -Match '__sg_tries'
        $s | Should -Match 'n>=3'
        $s | Should -Match '60000'
        $s | Should -Match 'Max-Age=86400; Path=/; SameSite=Lax'
        $s.IndexOf('location.reload()') | Should -BeGreaterThan $s.IndexOf('n>=3')
    }
    It 'is the same script whatever the day (the hash holds)' {
        (Get-CheckPage (Get-ChallengeToken $script:Secret 20762)) -replace 'data-pass="[^"]*"', '' |
            Should -BeExactly ($script:Html -replace 'data-pass="[^"]*"', '')
    }
    It 'refuses to write anything but a pass into the page' {
        { Get-CheckPage '"><script>alert(1)</script>' } | Should -Throw
        { Get-CheckPage '' } | Should -Throw
    }
    It 'is plain ASCII, with no IIS-specific entity trouble' {
        foreach ($ch in $script:Html.ToCharArray()) { [int]$ch | Should -BeLessThan 128 }
    }
}

Describe 'what the rule needs around it' {
    BeforeAll { $script:Support = Get-CheckSupport 'C:\ProgramData\AnalyticsAgent\www\check.html' 71 }
    It 'shows the page for 503.71 only, as a file' {
        $xml = ConvertTo-ConfigXml $script:Support.HttpError
        $xml | Should -Match 'statusCode="503" subStatusCode="71"'
        $xml | Should -Match 'responseMode="File"'
        $xml | Should -Match 'prefixLanguageFilePath=""'
    }
    It 'puts no-store, noindex and the policy on our responses only' {
        @($script:Support.Outbound).Count | Should -Be 3
        foreach ($o in $script:Support.Outbound) { $o.Attrs.preCondition | Should -Be $script:Support.PreCondition.Attrs.name }
        $pc = ConvertTo-ConfigXml $script:Support.PreCondition
        $pc | Should -Match 'input="\{SG_CHECK\}" pattern="\^1\$"'
        $csp = @($script:Support.Outbound | Where-Object { $_.Attrs.name -eq 'AnalyticsAgent-Check-Csp' })[0]
        $csp.Children[1].Attrs.value | Should -BeExactly (Get-CheckCsp)
        # The variable is not an HTTP_ one: a request header can't set it.
        $script:Support.Variable.Attrs.name | Should -Not -Match '^HTTP_'
    }
    It 'escapes attribute values in the XML it shows' {
        ConvertTo-ConfigXml @{ Tag = 'x'; Attrs = [ordered]@{ a = 'a<b>"c"&''d' } } | Should -BeExactly '<x a="a&lt;b&gt;&quot;c&quot;&amp;&apos;d" />'
    }
}
