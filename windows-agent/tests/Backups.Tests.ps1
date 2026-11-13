BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers.ps1')
    function New-BackupTestConfig([string]$Dir, $Backups) {
        $cfg = New-TestConfig $Dir
        if (-not (Test-Path $cfg.state_dir)) { New-Item -ItemType Directory -Path $cfg.state_dir -Force | Out-Null }
        $cfg.services = @()
        $cfg.backups = $Backups
        return $cfg
    }
    $global:Cases = ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $PSScriptRoot '../../protocols/download-cases.json')))
    function ConvertFrom-TestHex([string]$Hex) {
        $b = New-Object byte[] ($Hex.Length / 2)
        for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
        return , $b
    }
    function Get-TestPublicKey { return [pscustomobject]@{ kty = 'RSA'; n = $global:Cases.test_key.n; e = $global:Cases.test_key.e } }
    # RSA-OAEP-SHA256 undone with the fixture's private key, as the browser does it.
    function Unprotect-TestOaep([byte[]]$Wrapped) {
        $n = ConvertTo-UnsignedBig (ConvertFrom-Base64Url $global:Cases.test_key.n)
        $d = ConvertTo-UnsignedBig (ConvertFrom-Base64Url $global:Cases.test_key.d)
        $k = $Wrapped.Length
        $le = [System.Numerics.BigInteger]::ModPow((ConvertTo-UnsignedBig $Wrapped), $d, $n).ToByteArray()
        $em = New-Object byte[] $k
        for ($i = 0; $i -lt [math]::Min($le.Length, $k); $i++) { $em[$k - 1 - $i] = $le[$i] }
        $maskedSeed = [byte[]]$em[1..32]
        $masked = [byte[]]$em[33..($k - 1)]
        $seed = Get-XorBytes $maskedSeed (Get-Mgf1 $masked 32)
        $block = Get-XorBytes $masked (Get-Mgf1 $seed ($k - 33))
        $one = [Array]::IndexOf($block, [byte]1, 32)
        return , [byte[]]$block[($one + 1)..($block.Length - 1)]
    }
    # The download file read back as the dashboard reads it: tags checked, chunk by chunk.
    function Read-TestDownload([byte[]]$Data, [byte[]]$Secret) {
        $header = [byte[]]$Data[0..11]
        [Text.Encoding]::ASCII.GetString($header, 0, 8) | Should -Be 'SGDL0001'
        $chunk = ([int]$header[8] -shl 24) -bor ([int]$header[9] -shl 16) -bor ([int]$header[10] -shl 8) -bor [int]$header[11]
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = 'ECB'; $aes.Padding = 'None'; $aes.Key = Get-HmacSha256 $Secret 'sitegoose-download-v1 enc'
        $ecb = $aes.CreateEncryptor()
        $mac = New-Object System.Security.Cryptography.HMACSHA256 (, (Get-HmacSha256 $Secret 'sitegoose-download-v1 mac'))
        $out = New-Object IO.MemoryStream
        $counter = New-Object byte[] 16
        $pos = 12; $index = 0
        while ($pos -lt $Data.Length) {
            $size = [math]::Min($chunk, $Data.Length - $pos - 32)
            $sealed = New-Object byte[] $size
            [Array]::Copy($Data, $pos, $sealed, 0, $size)
            $tag = [byte[]]$Data[($pos + $size)..($pos + $size + 31)]
            $pos += $size + 32
            $meta = New-Object byte[] 9
            for ($i = 0; $i -lt 8; $i++) { $meta[$i] = [byte](($index -shr (56 - 8 * $i)) -band 255) }
            $meta[8] = [byte]([int]($pos -ge $Data.Length))
            [Convert]::ToBase64String($mac.ComputeHash([byte[]]($header + $meta + $sealed))) | Should -Be ([Convert]::ToBase64String($tag))
            for ($b = 0; $b -lt $size; $b += 16) {
                $ks = $ecb.TransformFinalBlock($counter, 0, 16)
                for ($i = 15; $i -ge 0; $i--) { $counter[$i] = [byte](($counter[$i] + 1) -band 255); if ($counter[$i] -ne 0) { break } }
                for ($i = 0; $i -lt 16 -and $b + $i -lt $size; $i++) { $out.WriteByte($sealed[$b + $i] -bxor $ks[$i]) }
            }
            $index++
        }
        return , $out.ToArray()
    }
}

Describe 'a download kept for a day' {
    It 'is the same file as the other agents make' {
        $secret = ConvertFrom-TestHex $global:Cases.secret
        foreach ($case in $global:Cases.cases) {
            $out = New-Object IO.MemoryStream
            $w = New-DownloadWriter $out $secret ([int]$global:Cases.chunk)
            $plain = ConvertFrom-TestHex $case.plaintext
            # Written in two goes, as a pipe hands it over.
            $half = [int]($plain.Length / 2)
            $w.Write($plain, 0, $half)
            $w.Write($plain, $half, $plain.Length - $half)
            $w.Finish()
            (($out.ToArray() | ForEach-Object { $_.ToString('x2') }) -join '') | Should -Be $case.file
        }
    }
    It 'stops past its size' {
        $w = New-DownloadWriter (New-Object IO.MemoryStream) (New-Object byte[] 32) 32 80
        { $w.Write((New-Object byte[] 100), 0, 100) } | Should -Throw
        $w.TooBig | Should -BeTrue
    }
    It 'wraps the key for the browser only' {
        $secret = [byte[]](0..31)
        $wrapped = Protect-OaepSha256 (Get-TestPublicKey) $secret
        $wrapped.Length | Should -Be 256
        (Unprotect-TestOaep $wrapped) -join ',' | Should -Be ($secret -join ',')
        ([Convert]::ToBase64String((Protect-OaepSha256 (Get-TestPublicKey) $secret))) | Should -Not -Be ([Convert]::ToBase64String($wrapped))
        { Protect-OaepSha256 ([pscustomobject]@{ kty = 'EC' }) $secret } | Should -Throw '*RSA public key*'
        { Protect-OaepSha256 ([pscustomobject]@{ kty = 'RSA'; n = $global:Cases.test_key.n; e = 'Aw' }) $secret } | Should -Throw '*2048 to 4096*'
        { Protect-OaepSha256 ([pscustomobject]@{ kty = 'RSA'; n = 'AQAB'; e = 'AQAB' }) $secret } | Should -Throw '*2048 to 4096*'
    }
}

Describe 'the backups section' {
    It 'is off without a repository' {
        $cfg = New-BackupTestConfig (Join-Path $TestDrive 'a') (ConvertFrom-Json '{"folders": ["C:\\inetpub\\wwwroot"]}')
        Get-BackupConfig $cfg | Should -BeNullOrEmpty
    }
    It 'fills in the rest, keeping only drive folders and its own storage keys' {
        $raw = ConvertFrom-Json '{"repository": "s3:https://nbg1.your-objectstorage.com/b/web", "folders": ["C:\\sites\\shop\\", "/etc", "C:\\sites\\shop"],
            "env": {"AWS_ACCESS_KEY_ID": "k", "PATH": "x"}, "at": "25:00", "keep": {"daily": 3}}'
        $bc = Get-BackupConfig (New-BackupTestConfig (Join-Path $TestDrive 'b') $raw)
        $bc.folders | Should -Be @('C:\sites\shop')
        @($bc.env.Keys) | Should -Be @('AWS_ACCESS_KEY_ID')
        $bc.at | Should -Be '03:00'
        $bc.keep.daily | Should -Be 3
        $bc.keep.weekly | Should -Be 8
        $bc.allow_restore | Should -BeFalse
        $bc.password_file | Should -BeLike '*backup-password.txt'
    }
    It 'never puts a password in a label, and skips SQL Server on another machine' {
        $dbs = @(Get-BackupDatabases (ConvertFrom-Json '[{"mysql": "mysql://shop:s3cret@db.local:3307/shop"}, {"sqlserver": "local"},
            {"sqlserver": "sqlserver://sa:pw@10.0.0.9"}, {"postgresql": "local"}, {"mariadb": "mariadb://u:p@h"}]'))
        @($dbs | ForEach-Object { $_.label }) | Should -Be @('mysql db.local:3307', 'sqlserver local', 'mysql h')
        ($dbs | ForEach-Object { $_.label }) -join ' ' | Should -Not -Match 's3cret'
    }
}

Describe 'database passwords' {
    BeforeAll { $bc = Get-BackupConfig (New-BackupTestConfig (Join-Path $TestDrive 'p') @{ repository = 'C:\repo' }) }
    It 'MySQL reads its password from a file, not the command line' {
        $db = @(Get-BackupDatabases @(@{ mysql = 'mysql://shop:p%40ss:w"d@db:3306/shop' }))[0]
        $s = Get-DbSession $bc $db
        try {
            ($s.Args -join ' ') | Should -Not -Match 'p@ss'
            $s.Args[0] | Should -BeLike '--defaults-extra-file=*'
            Get-Content -Raw $s.Files[0] | Should -Match 'password="p@ss:w\\"d"'
        } finally { Close-DbSession $s }
        Test-Path $s.Files[0] | Should -BeFalse
    }
    It 'PostgreSQL and SQL Server take it from the environment' {
        $pg = Get-DbSession $bc @(Get-BackupDatabases @(@{ postgresql = 'postgres://app:pw@db/shop' }))[0]
        $pg.Env.PGPASSWORD | Should -Be 'pw'
        $pg.Args.Count | Should -Be 0
        $ms = Get-DbSession $bc @(Get-BackupDatabases @(@{ sqlserver = 'sqlserver://sa:pw@localhost' }))[0]
        $ms.Env.SQLCMDPASSWORD | Should -Be 'pw'
        ($ms.Args -join ' ') | Should -Not -Match 'pw'
        (Get-DbSession $bc @(Get-BackupDatabases @(@{ sqlserver = 'local' }))[0]).Args | Should -Be @('-S', '.', '-E')
    }
    It 'MongoDB reads its connection string from a config file' {
        $s = Get-DbSession $bc @(Get-BackupDatabases @(@{ mongodb = 'mongodb://u:pw@db/admin' }))[0]
        try {
            $s.Args[0] | Should -BeLike '--config=*'
            Get-Content -Raw $s.Files[0] | Should -Match '^uri: "mongodb://u:pw@db/admin"'
        } finally { Close-DbSession $s }
    }
}

Describe 'command lines' {
    It 'come apart into exactly the arguments given' {
        $printf = (Get-Command printf -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
        if (-not $printf) { Set-ItResult -Skipped -Because 'no printf here'; return }
        $given = @('plain', 'two words', 'quo"te', 'trailing\', 'C:\a b\', '')
        $r = Invoke-BackupProcess $printf.Source (@('%s|') + $given)
        $r.Out | Should -Be (($given -join '|') + '|')
    }
}

Describe 'S3' {
    BeforeAll {
        # AWS's own worked examples ("Authenticating Requests (AWS Signature Version 4)" in the S3 docs).
        $loc = @{ scheme = 'https'; host = 'examplebucket.s3.amazonaws.com'; bucket = ''; region = 'us-east-1' }
        $keys = @('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
        $now = [DateTime]::new(2013, 5, 24, 0, 0, 0, [DateTimeKind]::Utc)
    }
    It 'signs a request as AWS does' {
        $empty = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        $s = Get-S3Signed $loc 'GET' 'test.txt' @{} @{ range = 'bytes=0-9' } $empty $keys[0] $keys[1] '' $now
        $s.Url | Should -Be 'https://examplebucket.s3.amazonaws.com/test.txt'
        $s.Headers.Authorization | Should -BeLike '*SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41'
    }
    It 'signs a link as AWS does' {
        $s = Get-S3Signed $loc 'GET' 'test.txt' @{} @{} '' $keys[0] $keys[1] '' $now 86400
        $s.Url | Should -BeLike '*X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404'
    }
    It 'reads the bucket and region from the repository, and puts downloads beside it' {
        $l = Get-S3Location @{ repository = 's3:https://nbg1.your-objectstorage.com/bucket/srv/one'; region = '' }
        ($l.host, $l.bucket, $l.prefix, $l.region) | Should -Be @('nbg1.your-objectstorage.com', 'bucket', 'srv/one', 'nbg1')
        (Get-S3Location @{ repository = 's3:s3.eu-central-1.amazonaws.com/b'; region = '' }).region | Should -Be 'eu-central-1'
        (Get-S3Location @{ repository = 's3:s3.amazonaws.com/b'; region = '' }).region | Should -Be 'us-east-1'
        Get-S3Location @{ repository = 'C:\backups'; region = '' } | Should -BeNullOrEmpty
        Get-S3DownloadKey $l 'x.gz' | Should -Be 'sitegoose-downloads/srv_one/x.gz'
    }
}

Describe 'when a run is due' {
    It 'once a day, from the time set' {
        $bc = @{ at = '03:00'; schedule = 'nightly'; weekday = 'sun' }
        Test-BackupDue $bc @{} ([DateTime]'2026-11-07 02:59') | Should -BeFalse
        Test-BackupDue $bc @{} ([DateTime]'2026-11-07 03:00') | Should -BeTrue
        Test-BackupDue $bc @{ last_day = '2026-11-07' } ([DateTime]'2026-11-07 23:00') | Should -BeFalse
    }
    It 'weekly on its day, or never when off' {
        $wed = [DateTime]'2026-11-04 03:30'
        Test-BackupDue @{ at = '03:00'; schedule = 'weekly'; weekday = 'sun' } @{} $wed | Should -BeFalse
        Test-BackupDue @{ at = '03:00'; schedule = 'weekly'; weekday = 'wed' } @{} $wed | Should -BeTrue
        Test-BackupDue @{ at = '03:00'; schedule = 'off'; weekday = 'sun' } @{} $wed | Should -BeFalse
    }
    It "the dashboard's schedule wins over the config's" {
        $bc = @{ at = '03:00'; schedule = 'nightly'; weekday = 'sun' }
        $wed = [DateTime]'2026-11-04 03:30'
        Test-BackupDue $bc @{ schedule = [pscustomobject]@{ schedule = 'off' } } $wed | Should -BeFalse
        Test-BackupDue $bc @{ schedule = [pscustomobject]@{ schedule = 'nightly'; at = '23:00' } } $wed | Should -BeFalse
        (Get-BackupSchedule $bc @{ schedule = [pscustomobject]@{ schedule = 'weekly'; weekday = 'wed' } }).from | Should -Be 'dashboard'
        (Get-BackupSchedule $bc @{ schedule = $null }).from | Should -Be 'config'
        $raw = ConvertFrom-Json '{"repository": "C:\\repo", "schedule": "Weekly", "weekday": "Friday", "temp_dir": "D:\\big"}'
        $c = Get-BackupConfig (New-BackupTestConfig (Join-Path $TestDrive 's') $raw)
        $c.schedule | Should -Be 'weekly'
        $c.weekday | Should -Be 'fri'
        $c.download_temp | Should -BeLike 'D:\big*sitegoose-backup-temp'
        # Only the download goes to temp_dir, a drive every account may read:
        # option files with passwords and dumps stay in the state folder.
        $c.temp | Should -Be (Join-Path $c.config.state_dir 'backup-temp')
        $secret = New-SecretFile $c 'password="hunter2"' '.cnf'
        try { Split-Path -Parent $secret | Should -Be $c.temp } finally { Remove-Item -LiteralPath $secret -Force }
    }
    It 'makes its own folder when temp_dir is not set, and both go in one cleanup' {
        $raw = ConvertFrom-Json '{"repository": "C:\\repo"}'
        $c = Get-BackupConfig (New-BackupTestConfig (Join-Path $TestDrive 't') $raw)
        $c.download_temp | Should -Be $c.temp
        New-PrivateFolder $c.download_temp
        Test-Path -LiteralPath $c.temp -PathType Container | Should -BeTrue
    }
    It 'never swaps a drive or a Windows folder whole' {
        'C:\' -match $script:SystemFolderPattern | Should -BeTrue
        'C:\Windows' -match $script:SystemFolderPattern | Should -BeTrue
        'C:\sites' -match $script:SystemFolderPattern | Should -BeFalse
    }
}

Describe 'a real run' {
    # restic on PATH, a repository in a folder, a folder of a site.
    BeforeAll {
        $script:HaveRestic = [bool](Get-Command restic -ErrorAction SilentlyContinue)
        $dir = Join-Path $TestDrive 'real'
        $cfg = New-BackupTestConfig $dir @{ repository = (Join-Path $dir 'repo'); allow_restore = $true }
        Set-Content -Path (Join-Path $dir 'backup-password.txt') -Value 'correct horse'
        $bc = Get-BackupConfig $cfg
        $site = Join-Path $dir 'sites/shop'
        New-Item -ItemType Directory -Path $site -Force | Out-Null
        Set-Content -Path (Join-Path $site 'index.html') -Value 'the shop'
        $bc.folders = @($site)
        # The collector: what was sent, and what it hands back to a GET.
        $global:Sent = New-Object System.Collections.ArrayList
        $global:Asked = '{"requests": []}'
        function Invoke-Collector {
            param($Config, [string]$Method, [string]$PathAndQuery, $Body = $null, [hashtable]$Headers = @{}, [string]$UserAgent = '')
            [void]$global:Sent.Add(@{ Path = $PathAndQuery; Body = $Body })
            if ($Method -eq 'GET') { return @{ Status = 200; Headers = @{}; Body = $global:Asked } }
            return @{ Status = 200; Headers = @{}; Body = '{}' }
        }
        Mock Start-Sleep { }
    }
    BeforeEach { if (-not $script:HaveRestic) { Set-ItResult -Skipped -Because "restic isn't installed" } }

    It 'backs up, reports names and sizes only, and puts a defaced folder back' {
        $r = Invoke-BackupRun $bc 'manual'
        $r.state | Should -Be 'ok'
        $run = @(Get-BackupRuns $bc)[0]
        $run.items[0].name | Should -Be $site
        Send-BackupReport $bc | Should -BeTrue
        $report = @($global:Sent | Where-Object { $_.Path -eq '/events/backups' })[0].Body
        $report.runs[0].items[0].bytes | Should -BeGreaterThan 0
        (ConvertTo-Json $report -Depth 8) | Should -Not -Match 'correct horse'

        Set-Content -Path (Join-Path $site 'index.html') -Value 'hacked'
        Set-Content -Path (Join-Path $site 'shell.php') -Value 'backdoor'
        $global:Sent.Clear()
        $done = Invoke-BackupRestore $bc $run.run @() 'req1'
        Get-Content (Join-Path $site 'index.html') | Should -Be 'the shop'
        Test-Path (Join-Path $site 'shell.php') | Should -BeFalse
        Get-Content (Join-Path $done.aside[0] 'shell.php') | Should -Be 'backdoor'
        @($global:Sent | Where-Object { $_.Path -eq '/events/maintenance' } | ForEach-Object { [bool]$_.Body.end }) | Should -Be @($false, $true)
        @(Get-BackupRuns $bc | Where-Object { $_.trigger -eq 'before-restore' }).Count | Should -Be 1
    }
    It 'puts everything back when a service stops after the restore' {
        $run = @(Get-BackupRuns $bc | Where-Object { $_.trigger -ne 'before-restore' })[0]
        Set-Content -Path (Join-Path $site 'index.html') -Value 'today'
        $script:Calls = 0
        Mock Get-RunningServices { $script:Calls++; if ($script:Calls -eq 1) { return @('W3SVC') } return @() }
        { Invoke-BackupRestore $bc $run.run @() 'req2' } | Should -Throw '*W3SVC stopped*Everything was put back*'
        Get-Content (Join-Path $site 'index.html') | Should -Be 'today'
    }
    It 'writes one part to a file' {
        $run = @(Get-BackupRuns $bc | Where-Object { $_.trigger -ne 'before-restore' })[0]
        $out = Join-Path $TestDrive 'shop.zip'
        Export-BackupItem $bc $run.items[0] $out
        (Get-Item $out).Length | Should -BeGreaterThan 0
    }
    It "won't restore from the dashboard unless the server allows it" {
        $bc.allow_restore = $false
        $global:Asked = '{"requests": [{"id": "r9", "kind": "restore", "run": "20261107T030000Z", "items": []}]}'
        $global:Sent.Clear()
        Invoke-BackupRequests $bc | Should -BeTrue
        $answer = @($global:Sent | Where-Object { $_.Body.state -eq 'failed' })[0].Body
        $answer.error | Should -Match 'allow_restore'
    }
    It 'backs up now and puts the whole run, encrypted, in our storage' {
        $site2 = Join-Path $TestDrive 'real/sites/blog'
        New-Item -ItemType Directory -Path $site2 -Force | Out-Null
        Set-Content -Path (Join-Path $site2 'post.html') -Value 'a post'
        $bc.folders = @($site, $site2)
        $global:Uploaded = New-Object IO.MemoryStream
        $global:Asked = '{"schedule": {"schedule": "weekly", "weekday": "mon", "at": "04:00"}, "requests": [{"id": "r7", "kind": "backup", "download": true,
            "hosted": {"public_key": ' + (ConvertTo-Json (Get-TestPublicKey) -Compress) + ', "max_bytes": 1000000000}}]}'
        function Invoke-Collector {
            param($Config, [string]$Method, [string]$PathAndQuery, $Body = $null, [hashtable]$Headers = @{}, [string]$UserAgent = '')
            [void]$global:Sent.Add(@{ Path = $PathAndQuery; Body = $Body })
            if ($Method -eq 'GET') { return @{ Status = 200; Headers = @{}; Body = $global:Asked } }
            if ($PathAndQuery -eq '/events/backups/upload') {
                $parts = @(1..([math]::Ceiling($Body.bytes / 1024)) | ForEach-Object { @{ n = $_; url = "https://up/$_" } })
                return @{ Status = 200; Headers = @{}; Body = (ConvertTo-Json @{ part_size = 1024; parts = $parts } -Depth 4) }
            }
            return @{ Status = 200; Headers = @{}; Body = '{}' }
        }
        Mock Send-UploadPart { $global:Uploaded.Write($Data, 0, $Data.Length); return '"e' + $global:Uploaded.Length + '"' }
        $global:Sent.Clear()
        Invoke-BackupRequests $bc | Should -BeTrue
        $done = @($global:Sent | Where-Object { $_.Path -eq '/events/backups/requests' -and $_.Body.state -eq 'done' })
        $done.Count | Should -Be 1
        $answer = $done[0].Body
        $answer.hosted | Should -BeTrue
        $answer.bytes | Should -Be $global:Uploaded.Length
        (Get-BackupSchedule $bc (Read-BackupState $bc)).schedule | Should -Be 'weekly'
        $plain = Read-TestDownload $global:Uploaded.ToArray() (Unprotect-TestOaep ([Convert]::FromBase64String($answer.wrapped_key)))
        Add-Type -AssemblyName System.IO.Compression
        $zip = New-Object IO.Compression.ZipArchive((New-Object IO.MemoryStream (, $plain)), [IO.Compression.ZipArchiveMode]::Read)
        @($zip.Entries | ForEach-Object { $_.FullName } | Sort-Object) | Should -Be @(@($site, $site2 | ForEach-Object { (($_ -replace '[:\\/]+', '_').Trim('_')) + '.zip' }) | Sort-Object)
        $finished = @($global:Sent | Where-Object { $_.Path -eq '/events/backups/upload/done' })[0].Body
        @($finished.parts | ForEach-Object { $_.n }) | Should -Be @(1..@($finished.parts).Count)
        @(Get-ChildItem -LiteralPath $bc.temp -Filter 'backup-download-*').Count | Should -Be 0
    }
    It 'refuses a download over the plan' {
        $run = @(Get-BackupRuns $bc | Where-Object { $_.trigger -ne 'before-restore' })[0]
        $hosted = [pscustomobject]@{ public_key = (Get-TestPublicKey); max_bytes = 100 }
        { Invoke-BackupDownload $bc $run.run @() $hosted 'r8' } | Should -Throw '*more than the 100 bytes a file your plan allows*'
    }
}
