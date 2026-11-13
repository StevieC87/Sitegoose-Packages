#Requires -Version 5.1
# analytics-agent-windows
<#
The server agent for Windows Server with IIS: the analytics firewall and flood
protection. It fetches the site's rules (GET /events/firewall/rules, protocol
in sdk/protocols/firewall.md) and puts them where Windows and IIS enforce them,
each as far as this server has the piece:

- windows-firewall: deny, lists (Spamhaus DROP), shared and banned, plus the
  addresses this agent bans itself, as Windows Defender Firewall block rules of
  its own (named AnalyticsAgent-*, in the group "AnalyticsAgent"), on the web
  ports only (80 and 443, TCP and UDP). Changed in place, never all deleted and
  made again. Block mode only. A block rule beats an allow rule in Windows
  Firewall, so `allow` is taken out of the lists rather than allowed.
- origin: with `origin.only` in the rules (the site is behind Cloudflare), the
  web ports are blocked for everything except those ranges, `allow`, the
  private and loopback ranges and this server's own addresses: the block rules
  hold the complement of what may come in.
- iis: IIS's own Dynamic IP Restrictions (server level), with the exempt
  ranges (Cloudflare, search engines, allow, good bots, private) as IP
  restriction allow entries, which the module never limits. Block mode only.
- logs: the page limit (`flood.req_rate` / `req_burst`) read from IIS's W3C
  logs: an address (an IPv6 /64) asking for pages faster than that is banned
  in Windows Firewall for `flood.ban` seconds and reported as `rate`.
- iis-check: the browser check (`challenge`) through IIS URL Rewrite: a global
  rule answers a page request without a pass with a 503 and the check page.

And every minute, whether its Windows services run and what each uses
(POST /events/services, protocol in sdk/protocols/services.md).

Backups, with a "backups" section in the config (sdk/protocols/backups.md):
every night its databases (SQL Server, MySQL/MariaDB, PostgreSQL, MongoDB),
each dumped by its own tool, and its folders, through a shadow copy, into
restic, encrypted here into the owner's own storage with a password only they
have. A process of its own (backup-worker), started by the loop.

The server's own management ports (RDP 3389, WinRM 5985/5986, SSH, SMB) are
never touched: every firewall rule the agent writes names its ports, and
those can't be among them.

Windows PowerShell 5.1 or later, no modules to install. Runs as SYSTEM from a
scheduled task (install.ps1 sets it up).

    analytics-agent.ps1 run      keep the rules in place (what the task runs)
    analytics-agent.ps1 once     fetch and apply once
    analytics-agent.ps1 status   what's in place now
    analytics-agent.ps1 clear    remove everything the agent put in place
    analytics-agent.ps1 services check the services now, print and report them
    analytics-agent.ps1 backup-setup   install restic, make the password and the repository
    analytics-agent.ps1 backup         back up now
    analytics-agent.ps1 backups        list the backups
    analytics-agent.ps1 restore RUN [PART...] [-Into FOLDER] [-Yes]
                                       put a backup back (or copy it out with -Into)
    analytics-agent.ps1 export RUN PART FILE   write one part to a file
#>
param(
    [Parameter(Position = 0)]
    [string]$Command = 'run',
    [string]$ConfigPath = '',
    [string]$Into = '',
    [switch]$Yes,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest = @()
)

try { Add-Type -AssemblyName System.Numerics -ErrorAction SilentlyContinue } catch { }

# ---- Constants -------------------------------------------------------------------

$script:AgentVersion = '0.3.0'
$script:RulePrefix = 'AnalyticsAgent'
$script:FwGroup = 'AnalyticsAgent'
$script:FwDescription = 'Written by the analytics agent; changed in place. Remove with: analytics-agent.ps1 clear'
$script:ProtocolVersion = 1
$script:MinSync = 30
$script:RetrySeconds = 60
$script:HttpTimeoutMs = 10000
$script:Batch = 200
$script:MaxReportRows = 2000
$script:TickSeconds = 5
$script:FloodBanDefault = 600
$script:BanReportAfter = 10
$script:BanSlack = 3
$script:BansMax = 10000
$script:BucketsMax = 50000
$script:ClassCacheMax = 20000
$script:ChallengeReportEvery = 15
$script:ChallengeMaxRows = 500
$script:LogReadMax = 8MB
$script:FirewallMaxPerRule = 1000
$script:CheckRetryEvery = 60
# IIS's request limits count every request, images and scripts too: this many
# requests per page, and never fewer than DiprFloor in 10 s (an office behind
# one NAT address loading asset-heavy pages stays well under it).
$script:DiprRequestsPerPage = 20
$script:DiprFloor = 500
$script:DiprConcurrentFloor = 100
# Bans also refused by IIS (ipSecurity deny entries, IPv4): an open keep-alive
# or HTTP/2 connection outlives a new Windows Firewall rule.
$script:IisDenyMax = 500
$script:IisBansEvery = 30
# The page limit's report of an address IIS's limits refused: kept apart from
# the bans (nothing is banned for it), at most this many.
$script:IisDeniedMax = 10000
$script:SnapshotTimeout = 120
# Cloud platform addresses the origin lock never shuts out: Azure's wire
# server and load balancer health probe (168.63.129.16). The metadata services
# (169.254.169.254) are in 169.254/16 already.
$script:PlatformRanges = @('168.63.129.16/32')
# Widest range a block list may hold: as the collector's scanner list, /8 and
# IPv6 /32. Anything wider is a mistake, not a block.
$script:WidestBlockV4 = 8
$script:WidestBlockV6 = 32
$script:IisSoftwareLine = '#Software: Microsoft Internet Information Services'
$script:CommandTimeout = 30
$script:FirewallTimeout = 120
# Never counted, banned or locked out: private, loopback and shared ranges.
$script:LocalRanges = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '100.64.0.0/10',
    '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10')
# Ports no rule of the agent may ever name: SSH, RPC, NetBIOS, SMB, RDP, WinRM.
$script:ProtectedPorts = @(22, 135, 139, 445, 3389, 5985, 5986)
# Static files by extension: one page load asks for dozens of them.
$script:StaticRegex = New-Object System.Text.RegularExpressions.Regex ('\.(css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|pdf|wasm)$',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$script:SkipPrefixPattern = '^/[a-z0-9/._~%:@,=+-]{0,199}$'
$script:Layers = @('windows-firewall', 'origin', 'iis', 'logs', 'iis-check')
# The browser check in IIS: the global rule, its outbound header rules, the
# server variable that ties them together (not HTTP_*, so no request header can
# set it) and the private 503 sub-status whose error page is the check page.
$script:CheckRuleName = 'AnalyticsAgent-Check'
$script:CheckPreCondition = 'AnalyticsAgent-Check'
$script:CheckVariable = 'SG_CHECK'
$script:CheckOutbound = @(
    @{ Name = 'AnalyticsAgent-Check-Cache'; Variable = 'RESPONSE_Cache_Control'; Value = 'no-store' },
    @{ Name = 'AnalyticsAgent-Check-Robots'; Variable = 'RESPONSE_X_Robots_Tag'; Value = 'noindex' },
    @{ Name = 'AnalyticsAgent-Check-Csp'; Variable = 'RESPONSE_Content_Security_Policy'; Value = '' }
)
$script:CheckExemptPerCondition = 60
$script:V4Pattern = '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
$script:DenyActions = @{ 0 = 'AbortRequest'; 401 = 'Unauthorized'; 403 = 'Forbidden'; 404 = 'NotFound' }
$script:ErrorModes = @{ 0 = 'DetailedLocalOnly'; 1 = 'Custom'; 2 = 'Detailed' }
$script:ExistingResponses = @{ 0 = 'Auto'; 1 = 'Replace'; 2 = 'PassThrough' }
# Whether its services run, and what each uses (sdk/protocols/services.md).
$script:ServicesEvery = 60
$script:ServicesMax = 50
$script:ServicesTimeout = 30
# A CPU pair further apart than this isn't this minute's average.
$script:UsageMaxPairSeconds = 300
# A found service that stopped stays (red) this long after it last ran; when
# it ran is saved at most hourly, so the file isn't written every minute.
$script:ServicesKeepGone = 7 * 86400
$script:ServicesSeenEvery = 3600
# The services worth a light when found: IIS, databases, caches, queues, web
# servers and Docker. Matched against the service's own name, not its display name.
$script:DetectServices = New-Object System.Text.RegularExpressions.Regex (('^(W3SVC|WAS|MSSQLSERVER|MSSQL\$[A-Za-z0-9_]+|SQLSERVERAGENT|SQLAgent\$[A-Za-z0-9_]+|' +
    'MySQL[0-9]*|MariaDB[0-9.]*|postgresql(-x64)?-[0-9.]+|Redis|Memurai|MongoDB|RabbitMQ|memcached|elasticsearch-service-x64|' +
    'nginx|Apache[0-9.]*|Tomcat[0-9]*|ClickHouse|docker|com\.docker\.service)$'), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$script:ServiceNamePattern = '^[A-Za-z0-9_.$@ -]{1,80}$'

$script:DefaultConfig = [ordered]@{
    site_id = ''
    secret = ''
    endpoint = ''
    ports = @(80, 443)
    state_dir = ''
    page_dir = ''
    # IIS log folders (each holding u_ex*.log files); empty: the sites' own,
    # from IIS's configuration, else %SystemDrive%\inetpub\logs\LogFiles\W3SVC*.
    iis_log_dirs = @()
    windows_firewall = $true
    iis_limits = $true
    iis_check = $true
    logs = $true
    # Addresses per Windows Firewall rule. More go in further rules.
    firewall_chunk = 500
    # The 503 sub-status of the browser check's page (503.<this>).
    check_substatus = 71
    # `netsh http flush logbuffer` every few seconds, so IIS's log lines (which
    # HTTP.sys buffers for up to a minute) reach the page limit sooner.
    flush_log_buffer = $true
    # Windows services to check besides the ones found (their names, as
    # `Get-Service` prints them), and whether to find the common ones.
    services = @()
    services_detect = $true
}

$script:Pow2 = New-Object 'System.Numerics.BigInteger[]' 129
$script:Pow2[0] = [System.Numerics.BigInteger]::One
for ($i = 1; $i -le 128; $i++) { $script:Pow2[$i] = [System.Numerics.BigInteger]::Multiply($script:Pow2[$i - 1], 2) }
$script:MappedBase = [System.Numerics.BigInteger]::Multiply([System.Numerics.BigInteger]65535, $script:Pow2[32])
$script:LogFile = $null
$script:Quiet = $false
$script:Abandoned = New-Object System.Collections.ArrayList
$script:AgentPath = $PSCommandPath
$script:WebConfigCache = New-Object System.Collections.Hashtable

# ---- Small helpers -----------------------------------------------------------------

function Write-AgentLog {
    param([string]$Text)
    $line = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + ' ' + $Text
    if (-not $script:Quiet) { Write-Host $line }
    if ($script:LogFile) {
        try {
            if ((Test-Path -LiteralPath $script:LogFile) -and (Get-Item -LiteralPath $script:LogFile).Length -gt 5MB) {
                Move-Item -LiteralPath $script:LogFile -Destination ($script:LogFile + '.1') -Force
            }
            [IO.File]::AppendAllText($script:LogFile, $line + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
        } catch { }
    }
}

function Write-AgentNote {
    # Logs a state once, not every round.
    param($Agent, [string]$Topic, [string]$Text)
    $old = ''
    if ($Agent.Notes.ContainsKey($Topic)) { $old = [string]$Agent.Notes[$Topic] }
    if ($Text -and $Text -cne $old) { Write-AgentLog $Text }
    $Agent.Notes[$Topic] = $Text
}

function Get-Prop {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    # The value as it is: a one-element list must not come back as its element.
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return , $Object[$Name] }
        return $Default
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $Default }
    return , $p.Value
}

function Test-IsMap {
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [System.Collections.IDictionary]) { return $true }
    return $Value.GetType().FullName -eq 'System.Management.Automation.PSCustomObject'
}

function Get-EntryList {
    # A JSON list as an array; anything else as an empty one.
    param($Value)
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [System.Collections.IDictionary]) { return @() }
    if ($Value -is [System.Collections.IEnumerable]) { return @($Value) }
    return @()
}

function Get-WholeNumber {
    # A whole number in [Low, High] from the network, else $null (a bool is not one).
    param($Value, [double]$Low, [double]$High)
    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    if (-not ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or
            $Value -is [single] -or $Value -is [int16] -or $Value -is [byte])) { return $null }
    $d = [double]$Value
    if ($d -ne [math]::Floor($d) -or $d -lt $Low -or $d -gt $High) { return $null }
    return [long]$d
}

function Get-EpochNow {
    return ([DateTime]::UtcNow.Ticks - 621355968000000000) / 10000000.0
}

function Get-UtcDay {
    param([double]$Now)
    return [long][math]::Floor($Now / 86400)
}

function ConvertTo-IsoTime {
    param([double]$Epoch)
    $t = New-Object DateTime ([long](621355968000000000 + [math]::Floor($Epoch * 1000) * 10000)), ([DateTimeKind]::Utc)
    return $t.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function Get-Sha256Hex {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash((New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)) } finally { $sha.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Write-TextFile {
    # Atomically, UTF-8 without a byte order mark.
    param([string]$Path, [string]$Text)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $tmp = $Path + '.tmp' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    # A write that failed (a full disk) leaves no half-written file behind.
    try { [IO.File]::WriteAllText($tmp, $Text, (New-Object System.Text.UTF8Encoding($false))) } catch {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw
    }
    if (-not (Test-Path -LiteralPath $Path)) { [IO.File]::Move($tmp, $Path); return }
    # [NullString]: a plain $null reaches .NET as '' (no backup file wanted).
    try { [IO.File]::Replace($tmp, $Path, [NullString]::Value) } catch {
        # Replace fails while another process (IIS) has the file open: copy over it.
        try { Copy-Item -LiteralPath $tmp -Destination $Path -Force } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-External {
    # A command that can't hang the loop: killed after $Seconds, a failure
    # (Code 1) when it can't start. Returns @{ Code; Out; Err }.
    param([string]$File, [string[]]$Arguments = @(), [int]$Seconds = $script:CommandTimeout)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = (($Arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
    } catch {
        return @{ Code = 1; Out = ''; Err = $_.Exception.Message }
    }
    $out = $proc.StandardOutput.ReadToEndAsync()
    $err = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit($Seconds * 1000)) {
        try { $proc.Kill() } catch { }
        return @{ Code = 1; Out = ''; Err = "$File timed out after $Seconds s" }
    }
    $proc.WaitForExit()
    return @{ Code = $proc.ExitCode; Out = $out.Result; Err = $err.Result }
}

function Invoke-WithTimeout {
    # Runs a script block in a runspace of its own, so a hung Windows call
    # (the firewall service, CIM) can't stall the loop. Returns
    # @{ Output; Errors }; throws when it ran past $Seconds.
    param([scriptblock]$ScriptBlock, [object[]]$ArgumentList = @(), [int]$Seconds = 60)
    # Runs that timed out are disposed of once they do end (a hung call can't
    # be killed, only left; a stuck one is kept until then, never piled up).
    foreach ($old in @($script:Abandoned)) {
        if ($old.Handle.IsCompleted) {
            try { $old.Ps.Dispose() } catch { }
            [void]$script:Abandoned.Remove($old)
        }
    }
    $ps = [powershell]::Create()
    [void]$ps.AddScript($ScriptBlock.ToString())
    foreach ($arg in $ArgumentList) { [void]$ps.AddArgument($arg) }
    $handle = $ps.BeginInvoke()
    if (-not $handle.AsyncWaitHandle.WaitOne($Seconds * 1000)) {
        try { [void]$ps.BeginStop($null, $null) } catch { }
        [void]$script:Abandoned.Add(@{ Ps = $ps; Handle = $handle })
        throw "timed out after $Seconds s"
    }
    try {
        $out = $ps.EndInvoke($handle)
        $errors = @($ps.Streams.Error | ForEach-Object { $_.ToString() })
        return @{ Output = @($out); Errors = $errors }
    } finally {
        $ps.Dispose()
    }
}

# ---- Addresses -------------------------------------------------------------------
# An address is @{F = 4|6; N = BigInteger}; a range is @{F; S; E} (inclusive).

function New-IpRange {
    param([int]$F, [System.Numerics.BigInteger]$S, [System.Numerics.BigInteger]$E)
    return [pscustomobject]@{ F = $F; S = $S; E = $E }
}

function ConvertTo-BigFromBytes {
    param([byte[]]$Bytes)
    $le = New-Object byte[] ($Bytes.Length + 1)
    for ($i = 0; $i -lt $Bytes.Length; $i++) { $le[$i] = $Bytes[$Bytes.Length - 1 - $i] }
    return New-Object System.Numerics.BigInteger (, $le)
}

function ConvertTo-IpNumber {
    # Strict: dotted IPv4 without leading zeros, or IPv6 (no zone). An
    # IPv4-mapped IPv6 address (::ffff:1.2.3.4) is IPv4, unless -NoMap.
    param([string]$Text, [switch]$NoMap)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $t = $Text.Trim()
    if ($t -cmatch '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$') {
        $n = [long]0
        for ($i = 1; $i -le 4; $i++) {
            $o = [int]$Matches[$i]
            if ($o -gt 255) { return $null }
            $n = $n * 256 + $o
        }
        return [pscustomobject]@{ F = 4; N = [System.Numerics.BigInteger]$n }
    }
    if ($t.Length -gt 45 -or $t.IndexOf(':') -lt 0 -or $t -notmatch '^[0-9A-Fa-f:.]+$') { return $null }
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($t, [ref]$addr)) { return $null }
    if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $null }
    $n6 = ConvertTo-BigFromBytes $addr.GetAddressBytes()
    if (-not $NoMap -and $n6 -ge $script:MappedBase -and $n6 -lt ($script:MappedBase + $script:Pow2[32])) {
        return [pscustomobject]@{ F = 4; N = ($n6 - $script:MappedBase) }
    }
    return [pscustomobject]@{ F = 6; N = $n6 }
}

function Format-IPv4 {
    param([System.Numerics.BigInteger]$N)
    $v = [long]$N
    return '{0}.{1}.{2}.{3}' -f (($v -shr 24) -band 255), (($v -shr 16) -band 255), (($v -shr 8) -band 255), ($v -band 255)
}

function Format-IPv6 {
    # RFC 5952: lower case, the longest run of two or more zero groups as ::
    # (the first one on a tie), no embedded IPv4.
    param([System.Numerics.BigInteger]$N)
    $groups = New-Object int[] 8
    $x = $N
    for ($i = 7; $i -ge 0; $i--) {
        $groups[$i] = [int][System.Numerics.BigInteger]::Remainder($x, 65536)
        $x = [System.Numerics.BigInteger]::Divide($x, 65536)
    }
    $bestStart = -1; $bestLen = 0; $i = 0
    while ($i -lt 8) {
        if ($groups[$i] -eq 0) {
            $j = $i
            while ($j -lt 8 -and $groups[$j] -eq 0) { $j++ }
            if (($j - $i) -gt $bestLen) { $bestStart = $i; $bestLen = $j - $i }
            $i = $j
        } else { $i++ }
    }
    $hex = @($groups | ForEach-Object { $_.ToString('x') })
    if ($bestLen -lt 2) { return ($hex -join ':') }
    $left = ''
    if ($bestStart -gt 0) { $left = ($hex[0..($bestStart - 1)] -join ':') }
    $right = ''
    if ($bestStart + $bestLen -lt 8) { $right = ($hex[($bestStart + $bestLen)..7] -join ':') }
    return $left + '::' + $right
}

function Format-IpNumber {
    param([int]$F, [System.Numerics.BigInteger]$N)
    if ($F -eq 4) { return Format-IPv4 $N }
    return Format-IPv6 $N
}

function Get-FamilyBits { param([int]$F) if ($F -eq 4) { return 32 } return 128 }

function ConvertTo-IpRange {
    # An address or CIDR range (host bits ignored) from the rules. With
    # -FirewallForms also what Windows Firewall gives back: "a-b" ranges and
    # IPv4 masks ("10.0.0.0/255.0.0.0").
    param([string]$Text, [switch]$FirewallForms)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $t = $Text.Trim()
    if ($FirewallForms -and $t.IndexOf('-') -gt 0) {
        $two = $t.Split('-')
        if ($two.Count -ne 2) { return $null }
        $a = ConvertTo-IpNumber $two[0]
        $b = ConvertTo-IpNumber $two[1]
        if ($null -eq $a -or $null -eq $b -or $a.F -ne $b.F -or $a.N -gt $b.N) { return $null }
        return New-IpRange $a.F $a.N $b.N
    }
    $slash = $t.IndexOf('/')
    if ($slash -lt 0) {
        $a = ConvertTo-IpNumber $t
        if ($null -eq $a) { return $null }
        return New-IpRange $a.F $a.N $a.N
    }
    $addrText = $t.Substring(0, $slash)
    $bitsText = $t.Substring($slash + 1)
    $raw = ConvertTo-IpNumber $addrText -NoMap
    if ($null -eq $raw) { return $null }
    $f = $raw.F
    $n = $raw.N
    if ($bitsText -cmatch '^[0-9]{1,3}$') {
        $p = [int]$bitsText
    } elseif ($FirewallForms -and $f -eq 4 -and $bitsText.IndexOf('.') -gt 0) {
        $m = ConvertTo-IpNumber $bitsText
        if ($null -eq $m -or $m.F -ne 4) { return $null }
        $p = -1
        for ($k = 0; $k -le 32; $k++) {
            if ($m.N -eq ($script:Pow2[32] - $script:Pow2[32 - $k])) { $p = $k; break }
        }
        if ($p -lt 0) { return $null }
    } else { return $null }
    if ($p -gt (Get-FamilyBits $f)) { return $null }
    # IPv4-mapped IPv6 (::ffff:1.2.3.0/120): those visitors are seen as IPv4.
    if ($f -eq 6 -and $p -ge 96 -and $n -ge $script:MappedBase -and $n -lt ($script:MappedBase + $script:Pow2[32])) {
        $f = 4; $n = $n - $script:MappedBase; $p = $p - 96
    }
    $size = $script:Pow2[(Get-FamilyBits $f) - $p]
    $s = $n - [System.Numerics.BigInteger]::Remainder($n, $size)
    return New-IpRange $f $s ($s + $size - 1)
}

function Merge-IpRanges {
    # Sorted (IPv4 first) and collapsed: overlapping and adjacent ranges joined.
    param([object[]]$Ranges)
    $list = @(@($Ranges) | Where-Object { $null -ne $_ } | Sort-Object -Property @{ Expression = 'F' }, @{ Expression = 'S' })
    $out = New-Object System.Collections.ArrayList
    $cur = $null
    foreach ($r in $list) {
        if ($null -ne $cur -and $cur.F -eq $r.F -and $r.S -le ($cur.E + 1)) {
            if ($r.E -gt $cur.E) { $cur.E = $r.E }
        } else {
            if ($null -ne $cur) { [void]$out.Add($cur) }
            $cur = New-IpRange $r.F $r.S $r.E
        }
    }
    if ($null -ne $cur) { [void]$out.Add($cur) }
    return $out.ToArray()
}

function Test-RangeBefore {
    # Whether range $B lies wholly before the start of $A (family first).
    param($B, $A)
    if ($B.F -ne $A.F) { return $B.F -lt $A.F }
    return $B.E -lt $A.S
}

function Remove-IpRanges {
    # $From minus $Take, both any list of ranges; the result is merged.
    param([object[]]$From, [object[]]$Take)
    $a = @(Merge-IpRanges $From)
    $b = @(Merge-IpRanges $Take)
    $out = New-Object System.Collections.ArrayList
    $j = 0
    foreach ($r in $a) {
        while ($j -lt $b.Count -and (Test-RangeBefore $b[$j] $r)) { $j++ }
        $s = $r.S
        $done = $false
        for ($k = $j; $k -lt $b.Count; $k++) {
            $x = $b[$k]
            if ($x.F -ne $r.F -or $x.S -gt $r.E) { break }
            if ($x.S -gt $s) { [void]$out.Add((New-IpRange $r.F $s ($x.S - 1))) }
            if ($x.E + 1 -gt $s) { $s = $x.E + 1 }
            if ($s -gt $r.E) { $done = $true; break }
        }
        if (-not $done -and $s -le $r.E) { [void]$out.Add((New-IpRange $r.F $s $r.E)) }
    }
    return $out.ToArray()
}

function Get-IpComplement {
    # Every address of family $F that isn't in $Allowed.
    param([object[]]$Allowed, [int]$F)
    $all = New-IpRange $F ([System.Numerics.BigInteger]::Zero) ($script:Pow2[(Get-FamilyBits $F)] - 1)
    return @(Remove-IpRanges @($all) @(@($Allowed) | Where-Object { $null -ne $_ -and $_.F -eq $F }))
}

function Split-IpRange {
    # A range as the fewest CIDR blocks: @{F; S; P}.
    param($Range)
    $bits = Get-FamilyBits $Range.F
    $out = New-Object System.Collections.ArrayList
    $s = $Range.S
    while ($s -le $Range.E) {
        $k = $bits
        while ($k -gt 0 -and ((-not [System.Numerics.BigInteger]::Remainder($s, $script:Pow2[$k]).IsZero) -or ($s + $script:Pow2[$k] - 1 -gt $Range.E))) { $k-- }
        [void]$out.Add([pscustomobject]@{ F = $Range.F; S = $s; P = $bits - $k })
        $s = $s + $script:Pow2[$k]
    }
    return $out.ToArray()
}

function Format-IpRange {
    # One address, one CIDR block, or "first-last": what Windows Firewall takes.
    param($Range)
    $bits = Get-FamilyBits $Range.F
    if ($Range.S -eq $Range.E) { return Format-IpNumber $Range.F $Range.S }
    $size = $Range.E - $Range.S + 1
    for ($p = 0; $p -le $bits; $p++) {
        if ($size -eq $script:Pow2[$bits - $p]) {
            if ([System.Numerics.BigInteger]::Remainder($Range.S, $size).IsZero) {
                return (Format-IpNumber $Range.F $Range.S) + '/' + $p
            }
            break
        }
    }
    return (Format-IpNumber $Range.F $Range.S) + '-' + (Format-IpNumber $Range.F $Range.E)
}

function Get-Networks {
    # Valid addresses and ranges only, merged. An IPv6 range that covers the
    # whole of ::ffff:0:0/96 is dropped, whichever list it is in: that is every
    # IPv4 address (as the packages do). With -Block (the list's name), a
    # range wider than /8 (IPv6 /32) is dropped too, before merging, so two
    # neighbouring ranges never add up to one too wide.
    param($Entries, [string]$Block = '')
    $ranges = New-Object System.Collections.ArrayList
    $mappedEnd = $script:MappedBase + $script:Pow2[32] - 1
    foreach ($e in @(Get-EntryList $Entries)) {
        if ($e -isnot [string]) { continue }
        $r = ConvertTo-IpRange $e
        if ($null -eq $r) { continue }
        if ($e.Contains(':')) {
            if ($r.F -eq 6 -and $r.S -le $script:MappedBase -and $r.E -ge $mappedEnd) { continue }
            if ($r.F -eq 4 -and $r.S -eq 0 -and $r.E -eq ($script:Pow2[32] - 1)) { continue }
        }
        if ($Block -and (Test-WideRange $r)) {
            Write-AgentLog ("{0}: {1} left out, wider than /{2} (IPv6 /{3})" -f $Block, $e, $script:WidestBlockV4, $script:WidestBlockV6)
            continue
        }
        [void]$ranges.Add($r)
    }
    return @(Merge-IpRanges $ranges.ToArray())
}

function Test-WideRange {
    # Wider than a block list may be: /8, IPv6 /32.
    param($Range)
    $size = $Range.E - $Range.S + 1
    if ($Range.F -eq 4) { return $size -gt $script:Pow2[32 - $script:WidestBlockV4] }
    return $size -gt $script:Pow2[128 - $script:WidestBlockV6]
}

function New-IpSet {
    # Sorted starts and ends per family, for a binary search.
    param([object[]]$Ranges)
    $m = @(Merge-IpRanges $Ranges)
    $v4 = @($m | Where-Object { $_.F -eq 4 })
    $v6 = @($m | Where-Object { $_.F -eq 6 })
    $s4 = New-Object long[] $v4.Count
    $e4 = New-Object long[] $v4.Count
    for ($i = 0; $i -lt $v4.Count; $i++) { $s4[$i] = [long]$v4[$i].S; $e4[$i] = [long]$v4[$i].E }
    $s6 = New-Object 'System.Numerics.BigInteger[]' $v6.Count
    $e6 = New-Object 'System.Numerics.BigInteger[]' $v6.Count
    for ($i = 0; $i -lt $v6.Count; $i++) { $s6[$i] = $v6[$i].S; $e6[$i] = $v6[$i].E }
    return @{ S4 = $s4; E4 = $e4; S6 = $s6; E6 = $e6 }
}

function Test-IpSet {
    param($Set, $Ip)
    if ($null -eq $Set -or $null -eq $Ip) { return $false }
    if ($Ip.F -eq 4) { $s = $Set.S4; $e = $Set.E4; $n = [long]$Ip.N } else { $s = $Set.S6; $e = $Set.E6; $n = $Ip.N }
    $lo = 0; $hi = $s.Length - 1; $found = -1
    while ($lo -le $hi) {
        $mid = [int][math]::Floor(($lo + $hi) / 2)
        if ($s[$mid] -le $n) { $found = $mid; $lo = $mid + 1 } else { $hi = $mid - 1 }
    }
    return ($found -ge 0 -and $e[$found] -ge $n)
}

function Get-FloodKey {
    # An address as the limits count it: IPv4, or an IPv6 address's /64.
    param($Ip)
    if ($null -eq $Ip) { return $null }
    if ($Ip.F -eq 4) { return Format-IPv4 $Ip.N }
    $net = $Ip.N - [System.Numerics.BigInteger]::Remainder($Ip.N, $script:Pow2[64])
    return (Format-IPv6 $net) + '/64'
}

function Get-OwnRanges {
    # This server's own unicast addresses (its requests to itself come from them).
    $out = New-Object System.Collections.ArrayList
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            foreach ($u in $nic.GetIPProperties().UnicastAddresses) {
                $text = $u.Address.ToString()
                $pct = $text.IndexOf('%')
                if ($pct -ge 0) { $text = $text.Substring(0, $pct) }
                $r = ConvertTo-IpRange $text
                if ($null -ne $r) { [void]$out.Add($r) }
            }
        }
    } catch { }
    return @(Merge-IpRanges $out.ToArray())
}

function Test-PublicIPv6 {
    # Whether one of these addresses is a public IPv6 one (not local, Teredo or 6to4).
    param([object[]]$Own)
    $notPublic = New-IpSet @(@($script:LocalRanges + @('2001::/32', '2002::/16')) | ForEach-Object { ConvertTo-IpRange $_ })
    foreach ($r in @($Own)) {
        if ($r.F -eq 6 -and -not (Test-IpSet $notPublic ([pscustomobject]@{ F = 6; N = $r.S }))) { return $true }
    }
    return $false
}

# ---- IPv4 ranges as URL Rewrite regular expressions -----------------------------
# URL Rewrite matches {REMOTE_ADDR} with a regular expression only, so exempt
# ranges become patterns. REMOTE_ADDR is checked to be a dotted IPv4 address
# first, so an octet that can be anything is [0-9]{1,3}.

function Get-DigitRangeRegex {
    # Strings of the same length; the leading digits may be zeros.
    param([string]$Lo, [string]$Hi)
    if ($Lo.Length -eq 1) {
        if ($Lo -ceq $Hi) { return $Lo }
        return '[' + $Lo + '-' + $Hi + ']'
    }
    if ($Lo[0] -eq $Hi[0]) { return [string]$Lo[0] + (Get-DigitRangeRegex $Lo.Substring(1) $Hi.Substring(1)) }
    $n = $Lo.Length - 1
    $zeros = '0' * $n
    $nines = '9' * $n
    $parts = New-Object System.Collections.ArrayList
    $a = [int]::Parse([string]$Lo[0])
    $b = [int]::Parse([string]$Hi[0])
    if ($Lo.Substring(1) -cne $zeros) {
        [void]$parts.Add([string]$a + (Get-DigitRangeRegex $Lo.Substring(1) $nines))
        $a++
    }
    $hiTail = $Hi.Substring(1) -cne $nines
    $bEnd = $b
    if ($hiTail) { $bEnd = $b - 1 }
    if ($a -le $bEnd) {
        $cls = '[' + $a + '-' + $bEnd + ']'
        if ($a -eq $bEnd) { $cls = [string]$a }
        [void]$parts.Add($cls + ('[0-9]' * $n))
    }
    if ($hiTail) { [void]$parts.Add([string]$b + (Get-DigitRangeRegex $zeros $Hi.Substring(1))) }
    if ($parts.Count -eq 1) { return $parts[0] }
    return '(' + ($parts -join '|') + ')'
}

function Get-NumberRangeRegex {
    # Whole numbers Lo..Hi (0..255) as written without leading zeros.
    param([int]$Lo, [int]$Hi)
    $parts = New-Object System.Collections.ArrayList
    foreach ($len in 1, 2, 3) {
        $lenLo = 0
        if ($len -gt 1) { $lenLo = [int][math]::Pow(10, $len - 1) }
        $lenHi = [int][math]::Pow(10, $len) - 1
        $a = [math]::Max($Lo, $lenLo)
        $b = [math]::Min($Hi, $lenHi)
        if ($a -le $b) { [void]$parts.Add((Get-DigitRangeRegex ([string]$a) ([string]$b))) }
    }
    if ($parts.Count -eq 1) { return $parts[0] }
    return '(' + ($parts -join '|') + ')'
}

function ConvertTo-CidrRegex {
    # One IPv4 CIDR block (@{S; P}) as an unanchored pattern.
    param([long]$S, [int]$P)
    $oct = @((($S -shr 24) -band 255), (($S -shr 16) -band 255), (($S -shr 8) -band 255), ($S -band 255))
    $full = [int][math]::Floor($P / 8)
    $rem = $P % 8
    $parts = @()
    for ($i = 0; $i -lt 4; $i++) {
        if ($i -lt $full) {
            $parts += [string]$oct[$i]
        } elseif ($i -eq $full -and $rem -gt 0) {
            $parts += Get-NumberRangeRegex $oct[$i] ($oct[$i] + [int][math]::Pow(2, 8 - $rem) - 1)
        } else {
            $parts += '[0-9]{1,3}'
        }
    }
    return ($parts -join '\.')
}

function Get-ExemptPatterns {
    # The IPv4 part of $Ranges as anchored patterns of at most $PerPattern
    # blocks each (one URL Rewrite condition apiece).
    param([object[]]$Ranges, [int]$PerPattern = $script:CheckExemptPerCondition)
    $blocks = New-Object System.Collections.ArrayList
    foreach ($r in @(Merge-IpRanges $Ranges)) {
        if ($r.F -ne 4) { continue }
        foreach ($c in @(Split-IpRange $r)) { [void]$blocks.Add((ConvertTo-CidrRegex ([long]$c.S) $c.P)) }
    }
    $out = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $blocks.Count; $i += $PerPattern) {
        $last = [math]::Min($i + $PerPattern, $blocks.Count) - 1
        [void]$out.Add('^(' + ($blocks[$i..$last] -join '|') + ')$')
    }
    return $out.ToArray()
}

# ---- Config ----------------------------------------------------------------------

function Get-DefaultConfigPath {
    if ($env:ANALYTICS_AGENT_CONFIG) { return $env:ANALYTICS_AGENT_CONFIG }
    $base = $env:ProgramData
    if (-not $base) { $base = '/tmp' }
    return (Join-Path (Join-Path $base 'AnalyticsAgent') 'config.json')
}

function Test-InsideFolder {
    # Whether $Path is $Folder or below it, after resolving "..".
    param([string]$Path, [string]$Folder)
    if (-not $Path) { return $false }
    try {
        $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
        $base = [IO.Path]::GetFullPath($Folder).TrimEnd('\', '/')
    } catch { return $false }
    $cmp = [StringComparison]::Ordinal
    if ($env:windir) { $cmp = [StringComparison]::OrdinalIgnoreCase }
    if ([string]::Equals($full, $base, $cmp)) { return $true }
    $sep = [IO.Path]::DirectorySeparatorChar
    return $full.StartsWith($base + $sep, $cmp)
}

function Test-ConfigOwner {
    # Whether an owner (a SID) may own the config: SYSTEM, Administrators or TrustedInstaller.
    param([string]$Sid)
    return @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') -contains $Sid
}

function Test-PrivateConfig {
    # On Windows: the config and its folder owned by SYSTEM or Administrators
    # (install.ps1 makes them so). Anyone else who owns them can rewrite their
    # ACL, read the secret and change where the agent writes. '' or why not.
    param([string]$Path)
    if (-not $env:windir) { return '' }
    foreach ($p in @((Split-Path -Parent $Path), $Path)) {
        try { $owner = (Get-Acl -LiteralPath $p).GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { return "the owner of $p can't be read: refused" }
        if (-not (Test-ConfigOwner $owner)) {
            return "$p is owned by $owner, not SYSTEM or Administrators: refused (run install.ps1 again, or: icacls `"$p`" /setowner *S-1-5-32-544)"
        }
    }
    return ''
}

function Read-AgentConfig {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "No config at $Path (install.ps1 writes it)." }
    try { $obj = ConvertFrom-Json ([IO.File]::ReadAllText($Path)) } catch { throw "$Path isn't valid JSON: $($_.Exception.Message)" }
    $c = @{}
    foreach ($k in $script:DefaultConfig.Keys) { $c[$k] = $script:DefaultConfig[$k] }
    foreach ($p in $obj.PSObject.Properties) { $c[$p.Name] = $p.Value }
    if (-not ([string]$c.site_id -cmatch '^[a-fA-F0-9]{24}$')) { throw "site_id in $Path must be the site's 24-character ID." }
    if (-not ([string]$c.secret -cmatch '^[A-Za-z0-9]{8,200}$')) { throw "secret in $Path must be the site secret (letters and digits)." }
    if (-not ([string]$c.endpoint -match '^https?://[^\s/]+')) { throw "endpoint in $Path must be the collector's URL." }
    $c.site_id = ([string]$c.site_id).ToLowerInvariant()
    $dir = Split-Path -Parent $Path
    if (-not $c.state_dir) { $c.state_dir = Join-Path $dir 'state' }
    if (-not $c.page_dir) { $c.page_dir = Join-Path $dir 'www' }
    # What the agent writes stays in the config's own folder: a config that
    # pointed elsewhere (or a junction inside it) would turn writes made as
    # SYSTEM into writes anywhere.
    foreach ($k in 'state_dir', 'page_dir') {
        if (-not (Test-InsideFolder ([string]$c[$k]) $dir)) { throw "$k in $Path must be a folder inside $dir." }
    }
    foreach ($p in @($dir, $c.state_dir, $c.page_dir)) { if (Test-ReparsePoint $p) { throw "$p is a junction or link: refused (the agent writes there as SYSTEM)." } }
    $why = Test-PrivateConfig $Path
    if ($why) { throw $why }
    foreach ($k in 'windows_firewall', 'iis_limits', 'iis_check', 'logs', 'flush_log_buffer', 'services_detect') {
        if ($c[$k] -isnot [bool]) { $c[$k] = $script:DefaultConfig[$k] }
    }
    $c.ports = @(Get-SafePorts $c.ports)
    $chunk = Get-WholeNumber $c.firewall_chunk 1 $script:FirewallMaxPerRule
    if ($null -eq $chunk) { $chunk = 500 }
    $c.firewall_chunk = [int]$chunk
    $sub = Get-WholeNumber $c.check_substatus 1 999
    if ($null -eq $sub) { $sub = 71 }
    $c.check_substatus = [int]$sub
    $c.iis_log_dirs = @(@(Get-EntryList $c.iis_log_dirs) | Where-Object { $_ -is [string] -and $_ })
    $c.services = @(Get-ServiceList $c.services)
    $c.config_path = $Path
    if (-not (Test-Path -LiteralPath $c.state_dir)) { New-Item -ItemType Directory -Path $c.state_dir -Force | Out-Null }
    return $c
}

function Get-SafePorts {
    # The web ports: whole numbers 1-65535, never a management port.
    param($Ports)
    $out = New-Object System.Collections.ArrayList
    foreach ($p in @(Get-EntryList $Ports)) {
        $n = Get-WholeNumber $p 1 65535
        if ($null -eq $n) { continue }
        if ($script:ProtectedPorts -contains [int]$n) {
            Write-AgentLog "port $n left out of `"ports`": the agent never touches a management port"
            continue
        }
        if (-not $out.Contains([int]$n)) { [void]$out.Add([int]$n) }
    }
    return @($out.ToArray() | Sort-Object)
}

# ---- Rules -----------------------------------------------------------------------

function Get-AgentPlan {
    # What to put in place, from the rules. flood, origin and challenge are
    # $null when the rules don't carry them, or when the firewall is off.
    param($Rules)
    $enabledValue = Get-Prop $Rules 'enabled'
    $enabled = ($enabledValue -is [bool]) -and $enabledValue
    $mode = Get-Prop $Rules 'mode'
    $block = $enabled -and ($mode -is [string]) -and ($mode -ceq 'block')
    $p = @{
        enabled = $enabled
        block = $block
        allow = @(Get-Networks (Get-Prop $Rules 'allow'))
        deny = @(Get-Networks (Get-Prop $Rules 'deny') -Block 'deny')
        ban = @(Get-Networks (Get-Prop $Rules 'banned') -Block 'banned')
        list = @(Get-Networks (Get-Prop $Rules 'lists') -Block 'lists')
        shared = @(Get-Networks (Get-Prop $Rules 'shared') -Block 'shared')
        goodbots = @(Get-Networks (Get-Prop $Rules 'goodbots'))
        flood = $null
        origin = $null
        challenge = $null
    }
    if (-not $enabled) { return $p }
    $allowE = @(Get-EntryList (Get-Prop $Rules 'allow'))
    $goodE = @(Get-EntryList (Get-Prop $Rules 'goodbots'))
    $flood = Get-Prop $Rules 'flood'
    if (Test-IsMap $flood) {
        $limits = @{
            conn_rate = Get-WholeNumber (Get-Prop $flood 'conn_rate') 1 1000000
            conn_max = Get-WholeNumber (Get-Prop $flood 'conn_max') 1 1000000
            req_rate = Get-WholeNumber (Get-Prop $flood 'req_rate') 1 1000000
            req_burst = Get-WholeNumber (Get-Prop $flood 'req_burst') 0 10000000
            ban = Get-WholeNumber (Get-Prop $flood 'ban') 1 (7 * 24 * 3600)
        }
        if ($null -eq $limits.ban) { $limits.ban = $script:FloodBanDefault }
        if ($null -ne $limits.req_rate -and $null -eq $limits.req_burst) { $limits.req_burst = $limits.req_rate * 3 }
        # Never counted or banned: allow, goodbots, exempt and the local ranges.
        $limits.exempt = @(Get-Networks (@($allowE) + @($goodE) + @(Get-EntryList (Get-Prop $flood 'exempt')) + $script:LocalRanges))
        $p.flood = $limits
    }
    $origin = Get-Prop $Rules 'origin'
    if (Test-IsMap $origin) {
        $only = @(Get-Networks (Get-Prop $origin 'only'))
        # An empty list would shut every visitor out but `allow`: a broken
        # answer, not a lock, so it fails open.
        if ($only.Count -gt 0) {
            $p.origin = @{ only = @(Get-Networks (@(Get-EntryList (Get-Prop $origin 'only')) + @($allowE))) }
        }
    }
    $challenge = Get-Prop $Rules 'challenge'
    if (Test-IsMap $challenge) {
        $skip = New-Object System.Collections.ArrayList
        foreach ($prefix in @(@(Get-EntryList (Get-Prop $challenge 'skip')) | Select-Object -First 100)) {
            if ($prefix -isnot [string]) { continue }
            $lower = $prefix.ToLowerInvariant()
            # This text becomes a URL Rewrite pattern: plain path characters only.
            if ($lower -cmatch $script:SkipPrefixPattern -and -not $skip.Contains($lower)) { [void]$skip.Add($lower) }
        }
        $p.challenge = @{
            skip = @($skip.ToArray())
            exempt = @(Get-Networks (@($allowE) + @($goodE) + @(Get-EntryList (Get-Prop $challenge 'exempt'))))
        }
    }
    return $p
}

# ---- The browser check: the pass and the page ----------------------------------

function Get-ChallengeToken {
    # The pass of sdk/protocols/firewall.md: <day>.<32 hex>. who = * for a
    # server-level check (the __sg_passn cookie).
    param([string]$Secret, [long]$Day, [string]$Who = '*')
    $enc = New-Object System.Text.UTF8Encoding($false)
    $h1 = New-Object System.Security.Cryptography.HMACSHA256 (, $enc.GetBytes($Secret))
    $key = $h1.ComputeHash($enc.GetBytes('sg-challenge-v1'))
    $h1.Dispose()
    $h2 = New-Object System.Security.Cryptography.HMACSHA256 (, $key)
    $mac = $h2.ComputeHash($enc.GetBytes(('{0}|{1}' -f $Day, $Who)))
    $h2.Dispose()
    $hex = (($mac[0..15] | ForEach-Object { $_.ToString('x2') }) -join '')
    return ('{0}.{1}' -f $Day, $hex)
}

function Get-ChallengeWho {
    # IPv4 (an IPv4-mapped IPv6 address as IPv4), or an IPv6 address's first
    # four groups, each as four lower-case hex digits.
    param([string]$Ip)
    $n = ConvertTo-IpNumber $Ip
    if ($null -eq $n) { return $null }
    if ($n.F -eq 4) { return Format-IPv4 $n.N }
    $high = [System.Numerics.BigInteger]::Divide($n.N, $script:Pow2[64])
    $groups = New-Object string[] 4
    for ($i = 3; $i -ge 0; $i--) {
        $groups[$i] = ([int][System.Numerics.BigInteger]::Remainder($high, 65536)).ToString('x4')
        $high = [System.Numerics.BigInteger]::Divide($high, 65536)
    }
    return ($groups -join ':')
}

function Test-ConstantEqual {
    param([string]$A, [string]$B)
    if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) { $diff = $diff -bor ([int][char]$A[$i] -bxor [int][char]$B[$i]) }
    return $diff -eq 0
}

function Test-ChallengePass {
    # Whether a cookie value is a valid pass for `who` (today's or yesterday's).
    param([string]$Secret, [string]$Cookie, [string]$Who, [double]$Now)
    if ($null -eq $Who -or -not ($Cookie -cmatch '^([0-9]{1,9})\.[0-9a-f]{32}$')) { return $false }
    $day = [long]$Matches[1]
    $today = Get-UtcDay $Now
    if ($day -ne $today -and $day -ne ($today - 1)) { return $false }
    return Test-ConstantEqual $Cookie (Get-ChallengeToken $Secret $day $Who)
}

function Test-ChallengeNeeded {
    # The protocol's decision for one request, with the packages' address-bound
    # pass: the reference the IIS rule (who = *) is tested against.
    param($Request, $Challenge, [double]$Now, [string]$Secret)
    if ($null -eq $Challenge) { return $false }
    $method = ([string](Get-Prop $Request 'method')).ToUpperInvariant()
    if ($method -cne 'GET' -and $method -cne 'HEAD') { return $false }
    if (([string](Get-Prop $Request 'accept')).ToLowerInvariant().IndexOf('text/html') -lt 0) { return $false }
    $path = ([string](Get-Prop $Request 'path')).ToLowerInvariant()
    foreach ($s in @($Challenge.skip)) { if ($path.StartsWith($s, [StringComparison]::Ordinal)) { return $false } }
    $ipText = [string](Get-Prop $Request 'ip')
    $ip = ConvertTo-IpNumber $ipText
    if ($null -ne $ip -and (Test-IpSet (New-IpSet $Challenge.exempt) $ip)) { return $false }
    return -not (Test-ChallengePass $Secret ([string](Get-Prop $Request 'cookie')) (Get-ChallengeWho $ipText) $Now)
}

function Get-CheckScript {
    # Constant, so its hash in the page's policy is too: the day's pass is read
    # from the page. Reloads only when the cookie reads back, and at most 3
    # times a minute (counted in sessionStorage, or in a __sg_tries cookie
    # when sessionStorage is blocked or full).
    return '(function(){var m=document.getElementById("m"),v=m.getAttribute("data-pass")||"",c="__sg_passn="+v+"; Max-Age=86400; Path=/; SameSite=Lax"+(location.protocol==="https:"?"; Secure":"");document.cookie=c;if((" "+document.cookie).indexOf(" __sg_passn="+v)<0){m.textContent="Your browser turned down the cookie this check needs. Allow cookies for this site, then reload the page.";return;}var k="__sg_tries",t=[],a=" "+document.cookie,i=a.indexOf(" __sg_tries="),n=i<0?0:(parseInt(a.slice(i+12),10)||0);try{t=JSON.parse(sessionStorage.getItem(k)||"[]").filter(function(x){return Date.now()-x<60000;});}catch(e){}n=Math.max(n,t.length);if(n>=3){m.textContent="This page could not be opened because the address of your connection keeps changing. Please try again in a minute.";return;}t.push(Date.now());try{sessionStorage.setItem(k,JSON.stringify(t));}catch(e){document.cookie=k+"="+(n+1)+"; Max-Age=60; Path=/; SameSite=Lax";}location.reload();})();'
}

function Get-CheckStyle {
    return 'body{font:16px/1.5 system-ui,sans-serif;max-width:32em;margin:15vh auto;padding:0 1em;color:#222}'
}

function Get-CspHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash((New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)) } finally { $sha.Dispose() }
    return "'sha256-" + [Convert]::ToBase64String($bytes) + "'"
}

function Get-CheckCsp {
    # A static page can't carry a fresh nonce, so its one script and one style
    # are allowed by their hashes instead: nothing else runs.
    return "default-src 'none'; script-src " + (Get-CspHash (Get-CheckScript)) + "; style-src " + (Get-CspHash (Get-CheckStyle)) +
        "; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}

function Get-CheckPage {
    param([string]$Token)
    if (-not ($Token -cmatch '^[0-9]{1,9}\.[0-9a-f]{32}$')) { throw "not a pass: $Token" }
    return '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width,initial-scale=1">' +
        '<meta name="robots" content="noindex"><title>One moment</title>' +
        '<style>' + (Get-CheckStyle) + '</style></head><body>' +
        '<p id="m" data-pass="' + $Token + '">Checking your browser. The page reloads by itself in a moment.</p>' +
        '<noscript><p>This site needs JavaScript to let you in. Turn it on, then reload the page.</p></noscript>' +
        '<script>' + (Get-CheckScript) + '</script></body></html>'
}

# ---- IIS configuration as data ---------------------------------------------------
# An element is @{ Tag; Attrs = [ordered]@{}; Children = @(@{ Name; Attrs; Items = @(element...) }) }.
# The same description is written through Microsoft.Web.Administration and
# shown as XML text (status, the backup log, the tests).

function ConvertTo-ConfigValue {
    param($Value)
    if ($Value -is [bool]) { if ($Value) { return 'true' } return 'false' }
    return [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}', $Value)
}

function ConvertTo-ConfigXml {
    param($Element, [string]$Indent = '')
    $attrs = ''
    if ($Element.Attrs) {
        foreach ($k in $Element.Attrs.Keys) {
            $attrs += ' ' + $k + '="' + [System.Security.SecurityElement]::Escape((ConvertTo-ConfigValue $Element.Attrs[$k])) + '"'
        }
    }
    $children = @($Element.Children | Where-Object { $null -ne $_ })
    $own = @($Element.Items | Where-Object { $null -ne $_ })
    if ($children.Count -eq 0 -and $own.Count -eq 0) { return $Indent + '<' + $Element.Tag + $attrs + ' />' }
    $lines = @($Indent + '<' + $Element.Tag + $attrs + '>')
    foreach ($it in $own) { $lines += ConvertTo-ConfigXml $it ($Indent + '  ') }
    foreach ($c in $children) {
        $items = @($c.Items | Where-Object { $null -ne $_ })
        $childEl = @{ Tag = $c.Name; Attrs = $c.Attrs; Children = @() }
        if ($items.Count -eq 0) {
            $lines += ConvertTo-ConfigXml $childEl ($Indent + '  ')
        } else {
            $open = ConvertTo-ConfigXml $childEl ($Indent + '  ')
            $lines += $open.Substring(0, $open.Length - 3) + '>'
            foreach ($it in $items) { $lines += ConvertTo-ConfigXml $it ($Indent + '    ') }
            $lines += $Indent + '  </' + $c.Name + '>'
        }
    }
    $lines += $Indent + '</' + $Element.Tag + '>'
    return ($lines -join "`r`n")
}

function New-Condition {
    param([string]$InputText, [string]$Pattern, [bool]$Negate = $false, [bool]$IgnoreCase = $true)
    return @{ Tag = 'add'; Attrs = [ordered]@{ input = $InputText; pattern = $Pattern; negate = $Negate; ignoreCase = $IgnoreCase } }
}

function Get-CheckRule {
    # The global rule: a GET or HEAD asking for text/html, on a site whose error
    # page is ours, from IPv4 (IIS writes IPv6 in more than one form, so no
    # IPv6 visitor is ever checked rather than risk checking an exempt one),
    # outside the skip prefixes and the exempt ranges, without today's or
    # yesterday's pass, gets 503.<sub>: the check page.
    param($Challenge, [string[]]$Tokens, [string[]]$SiteIds, [int]$SubStatus)
    $conds = New-Object System.Collections.ArrayList
    [void]$conds.Add((New-Condition '{REQUEST_METHOD}' '^(GET|HEAD)$'))
    [void]$conds.Add((New-Condition '{HTTP_ACCEPT}' 'text/html'))
    [void]$conds.Add((New-Condition '{INSTANCE_ID}' ('^(' + (@($SiteIds | Sort-Object { [long]$_ }) -join '|') + ')$') $false $false))
    [void]$conds.Add((New-Condition '{REMOTE_ADDR}' $script:V4Pattern $false $false))
    $skip = @($Challenge.skip)
    if ($skip.Count -gt 0) {
        # {URL} is the decoded path, so the prefixes are matched decoded too.
        $escaped = @($skip | ForEach-Object { [regex]::Escape([Uri]::UnescapeDataString($_)) })
        [void]$conds.Add((New-Condition '{URL}' ('^(' + ($escaped -join '|') + ')') $true $true))
    }
    $pass = @($Tokens | ForEach-Object { $_.Replace('.', '\.') }) -join '|'
    [void]$conds.Add((New-Condition '{HTTP_COOKIE}' ('(^|;\s*)__sg_passn=(' + $pass + ')(;|$)') $true $false))
    foreach ($pattern in @(Get-ExemptPatterns $Challenge.exempt)) {
        [void]$conds.Add((New-Condition '{REMOTE_ADDR}' $pattern $true $false))
    }
    return @{
        Tag = 'rule'
        Attrs = [ordered]@{ name = $script:CheckRuleName; enabled = $true; stopProcessing = $true; patternSyntax = 'ECMAScript' }
        Children = @(
            @{ Name = 'match'; Attrs = [ordered]@{ url = '.*' } },
            @{ Name = 'conditions'; Attrs = [ordered]@{ logicalGrouping = 'MatchAll'; trackAllCaptures = $false }; Items = @($conds.ToArray()) },
            @{ Name = 'serverVariables'; Items = @(@{ Tag = 'set'; Attrs = [ordered]@{ name = $script:CheckVariable; value = '1'; replace = $true } }) },
            @{ Name = 'action'; Attrs = [ordered]@{ type = 'CustomResponse'; statusCode = 503; subStatusCode = $SubStatus;
                    statusReason = 'Service Unavailable'; statusDescription = 'Checking your browser' } }
        )
    }
}

function Get-CheckSupport {
    # What the rule needs around it: its error page (only 503.<sub>, so a real
    # 503 keeps its own), its server variable, and the outbound rules that put
    # the page's own headers on only the responses the rule made.
    param([string]$PagePath, [int]$SubStatus)
    $outbound = @()
    foreach ($o in $script:CheckOutbound) {
        $value = $o.Value
        if ($o.Name -ceq 'AnalyticsAgent-Check-Csp') { $value = Get-CheckCsp }
        $outbound += @{
            Tag = 'rule'
            Attrs = [ordered]@{ name = $o.Name; preCondition = $script:CheckPreCondition; enabled = $true }
            Children = @(
                @{ Name = 'match'; Attrs = [ordered]@{ serverVariable = $o.Variable; pattern = '.*' } },
                @{ Name = 'action'; Attrs = [ordered]@{ type = 'Rewrite'; value = $value; replace = $true } }
            )
        }
    }
    return @{
        HttpError = @{ Tag = 'error'; Attrs = [ordered]@{ statusCode = 503; subStatusCode = $SubStatus; prefixLanguageFilePath = ''; path = $PagePath; responseMode = 'File' } }
        Variable = @{ Tag = 'add'; Attrs = [ordered]@{ name = $script:CheckVariable } }
        PreCondition = @{
            Tag = 'preCondition'
            Attrs = [ordered]@{ name = $script:CheckPreCondition; logicalGrouping = 'MatchAll' }
            Children = @()
            Items = @(New-Condition ('{' + $script:CheckVariable + '}') '^1$' $false $false)
        }
        Outbound = $outbound
    }
}

function ConvertTo-EnumName {
    param($Value, [hashtable]$Map)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    $n = [int]$Value
    if ($Map.ContainsKey($n)) { return $Map[$n] }
    return [string]$Value
}

function Get-IpSecurityKey {
    param([string]$Address, [string]$Mask)
    if (-not $Mask) { $Mask = '255.255.255.255' }
    return ($Address + '|' + $Mask).ToLowerInvariant()
}

function Get-ExemptAllowEntries {
    # IIS IP restriction allow entries (ipAddress + subnetMask) for the IPv4
    # part of the exempt ranges.
    param([object[]]$Exempt)
    $out = New-Object System.Collections.ArrayList
    foreach ($r in @(Merge-IpRanges $Exempt)) {
        if ($r.F -ne 4) { continue }
        foreach ($c in @(Split-IpRange $r)) {
            $mask = Format-IPv4 ($script:Pow2[32] - $script:Pow2[32 - $c.P])
            [void]$out.Add(@{ ipAddress = (Format-IPv4 $c.S); subnetMask = $mask; Key = (Get-IpSecurityKey (Format-IPv4 $c.S) $mask) })
        }
    }
    return $out.ToArray()
}

function Get-DiprDesired {
    # IIS counts every request, images and scripts too, so its limit is the
    # pages of ten seconds (rate x 10 + burst) times DiprRequestsPerPage,
    # never under DiprFloor: a backstop against floods, not the page limit
    # (that is the logs layer). Requests open at once: conn_max, never under
    # DiprConcurrentFloor (HTTP/2 opens many streams on one connection).
    param($Flood)
    $max = $script:DiprFloor
    if ($Flood.req_rate) { $max = [math]::Max($script:DiprFloor, ([long]$Flood.req_rate * 10 + [long]$Flood.req_burst) * $script:DiprRequestsPerPage) }
    $conc = 300
    if ($Flood.conn_max) { $conc = [math]::Max($script:DiprConcurrentFloor, [long]$Flood.conn_max) }
    return @{
        denyAction = 'Forbidden'
        enableLoggingOnlyMode = $false
        rateEnabled = [bool]$Flood.req_rate
        maxRequests = [long]$max
        intervalMs = [long]10000
        concEnabled = [bool]$Flood.conn_max
        maxConcurrent = [long]$conc
    }
}

function Get-DiprChanges {
    # The dynamicIpSecurity attributes, as changes, from @{ denyAction; ... }.
    param($Values)
    $section = 'system.webServer/security/dynamicIpSecurity'
    return @(
        @{ Op = 'Set'; Section = $section; Child = ''; Attrs = [ordered]@{ denyAction = $Values.denyAction; enableLoggingOnlyMode = [bool]$Values.enableLoggingOnlyMode } },
        @{ Op = 'Set'; Section = $section; Child = 'denyByRequestRate'; Attrs = [ordered]@{ enabled = [bool]$Values.rateEnabled; maxRequests = [long]$Values.maxRequests; requestIntervalInMilliseconds = [long]$Values.intervalMs } },
        @{ Op = 'Set'; Section = $section; Child = 'denyByConcurrentRequests'; Attrs = [ordered]@{ enabled = [bool]$Values.concEnabled; maxConcurrentRequests = [long]$Values.maxConcurrent } }
    )
}

function Test-DiprSame {
    param($A, $B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    foreach ($k in 'denyAction', 'enableLoggingOnlyMode', 'rateEnabled', 'maxRequests', 'intervalMs', 'concEnabled', 'maxConcurrent') {
        if ([string](Get-Prop $A $k) -ne [string](Get-Prop $B $k)) { return $false }
    }
    return $true
}

function Get-IisLimitsBlocker {
    # Why IIS's request limits can't be put in place safely here, or ''.
    # Decided before anything is written, so a site that would drop the exempt
    # ranges keeps the limits off rather than switching them on and off.
    param($Snap, [bool]$Ours, [bool]$PublicV6, [bool]$Held = $false)
    if (-not $Snap.Installed) { return "IIS isn't installed here: no IIS request limits" }
    if ($Snap.Error) { return "IIS's configuration can't be read ($($Snap.Error)): no IIS request limits" }
    if (@($Snap.Modules) -notcontains 'IpRestrictionModule') {
        return "IIS's IP and Domain Restrictions isn't installed (Install-WindowsFeature Web-IP-Security): no IIS request limits"
    }
    if (-not $Ours -and $Snap.Dipr -and ($Snap.Dipr.rateEnabled -or $Snap.Dipr.concEnabled)) {
        return "Dynamic IP Restrictions is already set up at server level by someone else: left as it is, no IIS request limits from the agent"
    }
    if (-not $Snap.IpSecurity -or -not $Snap.IpSecurity.AllowUnlisted) {
        return "IIS's server-level IP restrictions deny unlisted addresses: the exempt ranges can't be added as allow entries, so no IIS request limits"
    }
    $server = @($Snap.IpSecurity.Entries)
    foreach ($path in @($Snap.Paths)) {
        if ($path.ContainsKey('AllowUnlisted') -and $path.AllowUnlisted -eq $false) {
            return ("{0}{1} denies unlisted addresses: allow entries for the exempt ranges would let them in there, so no IIS request limits" -f $path.Site, $path.Path)
        }
        $missing = @()
        if ($path.ContainsKey('IpEntries')) { $have = @($path.IpEntries); $missing = @($server | Where-Object { $have -notcontains $_ }) }
        if ($path.IpCleared -or $missing.Count -gt 0) {
            return ("{0}{1} clears or removes the server's IP restriction entries, so the exempt ranges wouldn't be exempt there: no IIS request limits" -f $path.Site, $path.Path)
        }
    }
    if ($Held) {
        return "a site or folder dropped the exempt ranges once they were added (see the log): no IIS request limits until the sites' configuration changes"
    }
    if ($PublicV6) {
        return "this server has a public IPv6 address, and IIS's allow entries can't be relied on to exempt IPv6 proxies (Cloudflare connects over IPv6 too): no IIS request limits; the page limit from the logs still applies"
    }
    return ''
}

function Get-IpPathsDigest {
    # The sites, folders and locations that carry IP restrictions, without
    # their entries: what has to change before a held layer is tried again.
    param($Snap)
    $items = @(@($Snap.Paths) | Where-Object { $_.ContainsKey('IpEntries') } | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Site, $_.Path, [bool]$_.IpCleared, [bool]$_.AllowUnlisted } | Sort-Object)
    return Get-Sha256Hex ($items -join "`n")
}

function Test-CheckPathEligible {
    # Whether a visitor checked at this site path really gets the check page:
    # our error page in its effective httpErrors, custom errors on, IIS's own
    # body not passed through, and no policy of the site's that would block
    # the page's script. Returns '' or why not.
    param($Path, [string]$PagePath, [int]$SubStatus, [string]$ScriptHash)
    $mine = Get-HttpErrorKey 503 $SubStatus $PagePath
    if (@($Path.HttpErrors) -notcontains $mine) { return 'its error pages leave the check page out' }
    if ($Path.ErrorMode -eq 'Detailed') { return 'it shows detailed errors (httpErrors errorMode="Detailed")' }
    if ($Path.ExistingResponse -eq 'PassThrough') { return 'its error pages pass responses through (existingResponse="PassThrough")' }
    $csp = [string]$Path.Csp
    if ($csp -and $csp.IndexOf("'unsafe-inline'") -lt 0 -and $csp.IndexOf($ScriptHash) -lt 0) {
        return "its Content-Security-Policy header would block the check page's script (add $ScriptHash to its script-src)"
    }
    return ''
}

function Get-HttpErrorKey {
    param([int]$Status, [int]$SubStatus, [string]$PathText)
    return ('{0}.{1}|{2}' -f $Status, $SubStatus, $PathText).ToLowerInvariant()
}

function Get-CheckSites {
    # The IIS sites bound on the web ports whose every application, virtual
    # directory and folder with a web.config of its own gets the check page:
    # @{ Ids; Skipped }. Sites on other ports (Exchange, WSUS, internal ones)
    # are left alone.
    param($Snap, [string]$PagePath, [int]$SubStatus, [int[]]$Ports = @(80, 443))
    $hash = Get-CspHash (Get-CheckScript)
    $web = @{}
    foreach ($site in @($Snap.Sites)) {
        $bound = @(@($site.Bindings) | Where-Object { @('http', 'https') -contains $_.Protocol -and @($Ports) -contains [int]$_.Port })
        if ($bound.Count -gt 0) { $web[[string]$site.Id] = $true }
    }
    $bySite = [ordered]@{}
    $skipped = New-Object System.Collections.ArrayList
    foreach ($path in @($Snap.Paths)) {
        if (-not $path.SiteId) { continue }
        $id = [string]$path.SiteId
        if (-not $web.ContainsKey($id)) { continue }
        if (-not $bySite.Contains($id)) { $bySite[$id] = '' }
        if ($bySite[$id]) { continue }
        $why = Test-CheckPathEligible $path $PagePath $SubStatus $hash
        if ($why) { $bySite[$id] = ('{0}{1}: {2}' -f $path.Site, $path.Path, $why) }
    }
    $ids = New-Object System.Collections.ArrayList
    foreach ($id in $bySite.Keys) {
        if ($bySite[$id]) { [void]$skipped.Add($bySite[$id]) } else { [void]$ids.Add($id) }
    }
    return @{ Ids = @($ids.ToArray()); Skipped = @($skipped.ToArray()) }
}

# ---- IIS: reading and writing (Microsoft.Web.Administration) ---------------------

function Get-IisServerManager {
    if (-not $env:windir) { return $null }
    $dll = Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll'
    if (-not (Test-Path -LiteralPath $dll)) { return $null }
    if (-not ('Microsoft.Web.Administration.ServerManager' -as [type])) { Add-Type -Path $dll }
    return New-Object Microsoft.Web.Administration.ServerManager
}

function Get-IisCollectionNames {
    param($Collection, [string]$Attr = 'name')
    $out = New-Object System.Collections.ArrayList
    foreach ($el in $Collection) { [void]$out.Add([string]$el[$Attr]) }
    return $out.ToArray()
}

function Get-IisSnapshot {
    # What the agent needs to know of IIS, as plain data (so the decisions on
    # it are tested without IIS). Read in a runspace of its own with a time
    # limit: a hung configuration read can't stall the loop.
    param($Config)
    if (-not $env:windir -or -not $script:AgentPath) { return Get-IisSnapshotCore $Config }
    try {
        $res = Invoke-WithTimeout -Seconds $script:SnapshotTimeout -ArgumentList @($script:AgentPath, $Config, $script:WebConfigCache) -ScriptBlock {
            param($path, $config, $cache)
            . $path -Command lib
            $script:Quiet = $true
            $script:WebConfigCache = $cache
            Get-IisSnapshotCore $config
        }
        $out = @($res.Output | Where-Object { $_ -is [hashtable] })
        if ($out.Count -gt 0) { return $out[0] }
        $why = 'no answer'
        if (@($res.Errors).Count -gt 0) { $why = $res.Errors[0] }
        $snap = New-IisSnapshot
        $snap.Installed = $true
        $snap.Error = $why
        return $snap
    } catch {
        $snap = New-IisSnapshot
        $snap.Installed = $true
        $snap.Error = "reading it took too long ($($_.Exception.Message))"
        return $snap
    }
}

function New-IisSnapshot {
    return @{ Installed = $false; Error = ''; Modules = @(); Dipr = $null; IpSecurity = $null; GlobalRules = @()
        OutboundRules = @(); PreConditions = @(); ServerVariables = @(); HttpErrors = @(); Paths = @(); LogDirs = @(); Sites = @() }
}

function ConvertFrom-BindingInformation {
    # "ip:port:host" (ip may be "*" or "[v6]") into @{ Ip; Port; Host }, or $null.
    param([string]$Protocol, [string]$Info)
    if (-not ($Info -match '^(.*):([0-9]{1,5}):([^:]*)$')) { return $null }
    return @{ Protocol = $Protocol.ToLowerInvariant(); Ip = $Matches[1]; Port = [int]$Matches[2]; Host = $Matches[3] }
}

function Test-ClearsIpSecurity {
    # Whether a web.config clears or removes IP restriction entries anywhere in it.
    param([string]$File)
    if (-not $File -or -not (Test-Path -LiteralPath $File)) { return $false }
    try {
        $x = New-Object System.Xml.XmlDocument
        $x.XmlResolver = $null
        $x.Load($File)
        return $x.SelectNodes("//*[local-name()='ipSecurity']/*[local-name()='clear' or local-name()='remove']").Count -gt 0
    } catch { return $false }
}

function Find-WebConfigFolders {
    # The folders under $Root (not $Root itself) that hold a web.config of
    # their own, as relative paths with "/": at most 200, 6 levels down, 2,000
    # folders looked at, cached for 10 minutes.
    param([string]$Root)
    $now = Get-EpochNow
    $hit = $script:WebConfigCache[$Root]
    if ($null -ne $hit -and $now - $hit.At -lt 600) { return @($hit.Found) }
    $found = New-Object System.Collections.ArrayList
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue(@{ Dir = $Root; Rel = ''; Depth = 0 })
    $seen = 0
    $skip = @('node_modules', '.git', '.svn', 'bower_components', 'aspnet_client')
    while ($queue.Count -gt 0 -and $seen -lt 2000 -and $found.Count -lt 200) {
        $d = $queue.Dequeue()
        $seen++
        try { $subs = [IO.Directory]::GetDirectories($d.Dir) } catch { continue }
        foreach ($s in $subs) {
            $name = [IO.Path]::GetFileName($s)
            if ($skip -contains $name.ToLowerInvariant()) { continue }
            try { if (([IO.File]::GetAttributes($s) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue } } catch { continue }
            $rel = $d.Rel + '/' + $name
            if ([IO.File]::Exists((Join-Path $s 'web.config'))) { [void]$found.Add($rel) }
            if ($d.Depth + 1 -lt 6) { $queue.Enqueue(@{ Dir = $s; Rel = $rel; Depth = $d.Depth + 1 }) }
        }
    }
    if ($script:WebConfigCache.Count -gt 500) { $script:WebConfigCache.Clear() }
    $script:WebConfigCache[$Root] = @{ At = $now; Found = @($found.ToArray()) }
    return @($found.ToArray())
}

function Get-IisSnapshotCore {
    param($Config)
    $snap = New-IisSnapshot
    $sm = $null
    try { $sm = Get-IisServerManager } catch { $snap.Error = $_.Exception.Message; return $snap }
    if ($null -eq $sm) { return $snap }
    try {
        $snap.Installed = $true
        $ah = $sm.GetApplicationHostConfiguration()
        $snap.Modules = @(Get-IisCollectionNames $ah.GetSection('system.webServer/globalModules').GetCollection())
        $hasIp = $snap.Modules -contains 'IpRestrictionModule'
        $hasRewrite = $snap.Modules -contains 'RewriteModule'
        if ($hasIp) {
            $d = $ah.GetSection('system.webServer/security/dynamicIpSecurity')
            $rate = $d.GetChildElement('denyByRequestRate')
            $conc = $d.GetChildElement('denyByConcurrentRequests')
            $snap.Dipr = @{
                denyAction = ConvertTo-EnumName $d['denyAction'] $script:DenyActions
                enableLoggingOnlyMode = [bool]$d['enableLoggingOnlyMode']
                rateEnabled = [bool]$rate['enabled']; maxRequests = [long]$rate['maxRequests']; intervalMs = [long]$rate['requestIntervalInMilliseconds']
                concEnabled = [bool]$conc['enabled']; maxConcurrent = [long]$conc['maxConcurrentRequests']
            }
            $ips = $ah.GetSection('system.webServer/security/ipSecurity')
            $keys = @(foreach ($e in $ips.GetCollection()) { Get-IpSecurityKey ([string]$e['ipAddress']) ([string]$e['subnetMask']) })
            $snap.IpSecurity = @{ AllowUnlisted = [bool]$ips['allowUnlisted']; Entries = $keys }
        }
        if ($hasRewrite) {
            $snap.GlobalRules = @(Get-IisCollectionNames $ah.GetSection('system.webServer/rewrite/globalRules').GetCollection())
            $ob = $ah.GetSection('system.webServer/rewrite/outboundRules')
            $snap.OutboundRules = @(Get-IisCollectionNames $ob.GetCollection())
            $snap.PreConditions = @(Get-IisCollectionNames $ob.GetChildElement('preConditions').GetCollection())
            $snap.ServerVariables = @(Get-IisCollectionNames $ah.GetSection('system.webServer/rewrite/allowedServerVariables').GetCollection())
        }
        $snap.HttpErrors = @(foreach ($e in $ah.GetSection('system.webServer/httpErrors').GetCollection()) {
                Get-HttpErrorKey ([int]$e['statusCode']) ([int]$e['subStatusCode']) ([string]$e['path']) })
        $paths = New-Object System.Collections.ArrayList
        $logDirs = New-Object System.Collections.ArrayList
        $sites = New-Object System.Collections.ArrayList
        foreach ($site in $sm.Sites) {
            $siteName = [string]$site.Name
            $bindings = New-Object System.Collections.ArrayList
            foreach ($b in $site.Bindings) {
                $parsed = ConvertFrom-BindingInformation ([string]$b.Protocol) ([string]$b.BindingInformation)
                if ($parsed) { [void]$bindings.Add($parsed) }
            }
            $state = ''
            try { $state = [string]$site.State } catch { }
            [void]$sites.Add(@{ Id = [string]$site.Id; Name = $siteName; State = $state; Bindings = @($bindings.ToArray()) })
            try {
                $dir = [Environment]::ExpandEnvironmentVariables([string]$site.LogFile.Directory)
                if ($dir) { [void]$logDirs.Add((Join-Path $dir ('W3SVC' + $site.Id))) }
            } catch { }
            # Every application, its virtual directories and the folders under
            # them with a web.config of their own: each can change the error
            # pages or the IP restrictions for what is below it.
            $targets = New-Object System.Collections.ArrayList
            $known = @{}
            foreach ($app in $site.Applications) {
                $appPath = [string]$app.Path
                foreach ($vd in $app.VirtualDirectories) {
                    $vpath = $appPath
                    if ([string]$vd.Path -ne '/') { $vpath = $appPath.TrimEnd('/') + [string]$vd.Path }
                    if (-not $vpath) { $vpath = '/' }
                    $physical = [Environment]::ExpandEnvironmentVariables([string]$vd.PhysicalPath)
                    if (-not $known.ContainsKey($vpath.ToLowerInvariant())) {
                        $known[$vpath.ToLowerInvariant()] = $true
                        [void]$targets.Add(@{ Path = $vpath; Physical = $physical })
                    }
                }
            }
            foreach ($t in @($targets.ToArray())) {
                if (-not $t.Physical -or -not (Test-Path -LiteralPath $t.Physical)) { continue }
                foreach ($rel in @(Find-WebConfigFolders $t.Physical)) {
                    $vpath = $t.Path.TrimEnd('/') + $rel
                    if ($known.ContainsKey($vpath.ToLowerInvariant())) { continue }
                    $known[$vpath.ToLowerInvariant()] = $true
                    [void]$targets.Add(@{ Path = $vpath; Physical = (Join-Path $t.Physical ($rel.TrimStart('/').Replace('/', '\'))) })
                }
            }
            foreach ($t in $targets) {
                $info = @{ Site = $siteName; SiteId = [string]$site.Id; Path = $t.Path }
                try {
                    $wc = $sm.GetWebConfiguration($siteName, $t.Path)
                    $he = $wc.GetSection('system.webServer/httpErrors')
                    $info.ErrorMode = ConvertTo-EnumName $he['errorMode'] $script:ErrorModes
                    $info.ExistingResponse = ConvertTo-EnumName $he['existingResponse'] $script:ExistingResponses
                    $info.HttpErrors = @(foreach ($e in $he.GetCollection()) {
                            Get-HttpErrorKey ([int]$e['statusCode']) ([int]$e['subStatusCode']) ([string]$e['path']) })
                    $info.Csp = ''
                    foreach ($h in $wc.GetSection('system.webServer/httpProtocol').GetCollection('customHeaders')) {
                        if ([string]$h['name'] -eq 'Content-Security-Policy') { $info.Csp = [string]$h['value'] }
                    }
                    if ($hasIp) {
                        $ip = $wc.GetSection('system.webServer/security/ipSecurity')
                        $info.AllowUnlisted = [bool]$ip['allowUnlisted']
                        $info.IpEntries = @(foreach ($e in $ip.GetCollection()) { Get-IpSecurityKey ([string]$e['ipAddress']) ([string]$e['subnetMask']) })
                        $info.IpCleared = Test-ClearsIpSecurity (Join-Path $t.Physical 'web.config')
                    }
                } catch {
                    $info.Error = $_.Exception.Message
                    $info.HttpErrors = @()
                    $info.AllowUnlisted = $false
                }
                [void]$paths.Add($info)
            }
        }
        # <location> paths in applicationHost.config, where IP restrictions
        # usually live: one of them denying unlisted addresses, or clearing
        # the server's entries, matters too.
        if ($hasIp) {
            $clearing = @{}
            try {
                $x = New-Object System.Xml.XmlDocument
                $x.XmlResolver = $null
                $x.Load((Get-IisConfigFile))
                foreach ($loc in $x.SelectNodes('/configuration/location')) {
                    if ($loc.SelectNodes(".//*[local-name()='ipSecurity']/*[local-name()='clear' or local-name()='remove']").Count -gt 0) {
                        $clearing[([string]$loc.GetAttribute('path')).ToLowerInvariant()] = $true
                    }
                }
            } catch { }
            foreach ($lp in @($ah.GetLocationPaths())) {
                if (-not $lp) { continue }
                try {
                    $ip = $ah.GetSection('system.webServer/security/ipSecurity', $lp)
                    [void]$paths.Add(@{ Site = $lp; SiteId = ''; Path = ' (location)'; AllowUnlisted = [bool]$ip['allowUnlisted']
                            IpEntries = @(foreach ($e in $ip.GetCollection()) { Get-IpSecurityKey ([string]$e['ipAddress']) ([string]$e['subnetMask']) })
                            IpCleared = $clearing.ContainsKey(([string]$lp).ToLowerInvariant()) })
                } catch { }
            }
        }
        $snap.Paths = @($paths.ToArray())
        $snap.Sites = @($sites.ToArray())
        $snap.LogDirs = @($logDirs.ToArray() | Select-Object -Unique)
    } catch {
        $snap.Error = $_.Exception.Message
    } finally {
        $sm.Dispose()
    }
    return $snap
}

function Set-MwaBody {
    param($Element, $Desc)
    if ($Desc.Attrs) { foreach ($k in $Desc.Attrs.Keys) { $Element.SetAttributeValue($k, $Desc.Attrs[$k]) } }
    if ($Desc.Items) {
        $coll = $Element.GetCollection()
        foreach ($item in @($Desc.Items)) {
            $ie = $coll.CreateElement($item.Tag)
            Set-MwaBody $ie $item
            [void]$coll.Add($ie)
        }
    }
    foreach ($child in @($Desc.Children | Where-Object { $null -ne $_ })) {
        $ce = $Element.GetChildElement($child.Name)
        if ($child.Attrs) { foreach ($k in $child.Attrs.Keys) { $ce.SetAttributeValue($k, $child.Attrs[$k]) } }
        $items = @($child.Items | Where-Object { $null -ne $_ })
        if ($items.Count -gt 0) {
            $coll = $ce.GetCollection()
            foreach ($item in $items) {
                $ie = $coll.CreateElement($item.Tag)
                Set-MwaBody $ie $item
                [void]$coll.Add($ie)
            }
        }
    }
}

function Find-MwaItem {
    param($Collection, $Key)
    foreach ($el in $Collection) {
        $all = $true
        foreach ($k in $Key.Keys) {
            if ([string](ConvertTo-ConfigValue $el[$k]) -ine [string](ConvertTo-ConfigValue $Key[$k])) { $all = $false; break }
        }
        if ($all) { return $el }
    }
    return $null
}

function Get-IisConfigFile {
    if (-not $env:windir) { return '' }
    return (Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config')
}

function Backup-IisConfig {
    # A copy of applicationHost.config before every write: the last 10 kept,
    # and the copy from before the agent's first write kept for good
    # (applicationHost-before-agent.config).
    param($Agent)
    $file = Get-IisConfigFile
    if (-not $file -or -not (Test-Path -LiteralPath $file)) { return '' }
    $dir = Join-Path $Agent.Config.state_dir 'iis-backups'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $first = Join-Path $dir 'applicationHost-before-agent.config'
    if (-not (Test-Path -LiteralPath $first)) { Copy-Item -LiteralPath $file -Destination $first -Force }
    $copy = Join-Path $dir ('applicationHost-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff', [Globalization.CultureInfo]::InvariantCulture) + '.config')
    Copy-Item -LiteralPath $file -Destination $copy -Force
    $old = @(Get-ChildItem -LiteralPath $dir -Filter 'applicationHost-*.config' | Where-Object { $_.Name -cmatch '^applicationHost-[0-9]{8}-' } |
            Sort-Object Name -Descending | Select-Object -Skip 10)
    foreach ($f in $old) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
    return $copy
}

function Invoke-IisCommit {
    # Applies the changes in one commit of applicationHost.config, after a
    # backup. If IIS can't read its configuration afterwards, or a site that
    # answered before now answers 500 (a configuration error: 500.19, 500.5x),
    # the backup goes back. $true when the changes are in place; on any
    # failure the previous configuration stays.
    param([object[]]$Changes, $Agent, [switch]$NoProbe)
    $Changes = @($Changes | Where-Object { $null -ne $_ })
    if ($Changes.Count -eq 0) { return $true }
    $backup = ''
    try { $backup = Backup-IisConfig $Agent } catch {
        Write-AgentLog "IIS configuration not changed: the backup failed ($($_.Exception.Message))"
        return $false
    }
    $targets = @()
    if (-not $NoProbe) { $targets = @($Agent.ProbeTargets | Where-Object { $_ }) }
    $before = @{}
    foreach ($t in $targets) { $before[$t.Url + '|' + $t.Host] = Invoke-LocalProbe $t }
    $sm = $null
    try {
        $sm = Get-IisServerManager
        if ($null -eq $sm) { return $false }
        $ah = $sm.GetApplicationHostConfiguration()
        foreach ($c in $Changes) {
            $el = $ah.GetSection($c.Section)
            if ($c.Child) { $el = $el.GetChildElement($c.Child) }
            if ($c.Op -eq 'Set') {
                foreach ($k in $c.Attrs.Keys) { $el.SetAttributeValue($k, $c.Attrs[$k]) }
            } elseif ($c.Op -eq 'Add') {
                $coll = $el.GetCollection()
                $new = $coll.CreateElement($c.Item.Tag)
                Set-MwaBody $new $c.Item
                if ($c.ContainsKey('Index') -and $c.Index -ge 0) { [void]$coll.AddAt($c.Index, $new) } else { [void]$coll.Add($new) }
            } elseif ($c.Op -eq 'Remove') {
                $coll = $el.GetCollection()
                $found = Find-MwaItem $coll $c.Key
                if ($null -ne $found) { $coll.Remove($found) }
            }
        }
        $sm.CommitChanges()
    } catch {
        Write-AgentLog "IIS configuration not changed: $($_.Exception.Message)"
        return $false
    } finally {
        if ($null -ne $sm) { $sm.Dispose() }
    }
    $broken = ''
    try {
        $check = Get-IisServerManager
        $ah = $check.GetApplicationHostConfiguration()
        foreach ($s in @($Changes | ForEach-Object { $_.Section } | Select-Object -Unique)) { $null = $ah.GetSection($s) }
        $check.Dispose()
    } catch { $broken = "IIS can't read its configuration after the change ($($_.Exception.Message))" }
    if (-not $broken -and $targets.Count -gt 0) {
        Start-Sleep -Milliseconds 1500
        foreach ($t in $targets) {
            $after = Invoke-LocalProbe $t
            if (Test-ProbeBroken $before[$t.Url + '|' + $t.Host] $after) {
                $broken = ('{0} (Host: {1}) answers {2} after the change' -f $t.Url, $t.Host, $after.Status)
                break
            }
        }
    }
    if ($broken) {
        Write-AgentLog "$broken`: putting back $backup"
        if ($backup) {
            try { Copy-Item -LiteralPath $backup -Destination (Get-IisConfigFile) -Force } catch { Write-AgentLog "could not put back $backup`: $($_.Exception.Message)" }
        }
        return $false
    }
    return $true
}

function Get-ProbeTargets {
    # One local request per started site bound on the web ports (10 sites at
    # most), to see a change hasn't broken IIS: @{ Url; Host }.
    param($Snap, [int[]]$Ports)
    $out = New-Object System.Collections.ArrayList
    foreach ($site in @($Snap.Sites)) {
        if ($out.Count -ge 10) { break }
        if ($site.State -and $site.State -ne 'Started') { continue }
        $usable = @(@($site.Bindings) | Where-Object { @('http', 'https') -contains $_.Protocol -and @($Ports) -contains [int]$_.Port })
        $b = @($usable | Where-Object { $_.Protocol -eq 'http' }) + @($usable | Where-Object { $_.Protocol -eq 'https' }) | Select-Object -First 1
        if ($null -eq $b) { continue }
        $ip = [string]$b.Ip
        if (-not $ip -or $ip -eq '*' -or $ip -eq '0.0.0.0' -or $ip -eq '[::]') { $ip = '127.0.0.1' }
        $hostName = [string]$b.Host
        if (-not $hostName) { $hostName = 'localhost' }
        [void]$out.Add(@{ Url = ('{0}://{1}:{2}/' -f $b.Protocol, $ip, $b.Port); Host = $hostName })
    }
    return @($out.ToArray())
}

function Test-ProbeBroken {
    # A site that answered before and now answers 500, or shows IIS's own
    # configuration error page (500.19, 500.50-500.59), was broken by the change.
    param($Before, $After)
    if ($null -eq $After) { return $false }
    $err = 'HTTP Error 500\.(19|5[0-9])'
    $wasErr = $Before -and ($Before.Status -eq 500 -or [string]$Before.Body -match $err)
    if ($wasErr) { return $false }
    return ($After.Status -eq 500 -or [string]$After.Body -match $err)
}

function Invoke-LocalProbe {
    # GET / on this server, no cookie: @{ Status; Body } (the first 8 KB), Status 0 when it fails.
    param($Target)
    $resp = $null
    try {
        $req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Target.Url)
        $req.Method = 'GET'
        $req.Host = $Target.Host
        $req.Accept = 'text/html'
        $req.UserAgent = 'analytics-platform-agent-windows/' + $script:AgentVersion + ' (probe)'
        $req.AllowAutoRedirect = $false
        $req.Timeout = 5000
        $req.ReadWriteTimeout = 5000
        if ($Target.Url.StartsWith('https:', [StringComparison]::OrdinalIgnoreCase)) {
            # Our own server by address: its certificate names the site, not 127.0.0.1.
            $cb = Get-AcceptAnyCertificate
            if ($null -eq $cb) { return @{ Status = 0; Body = '' } }
            $req.ServerCertificateValidationCallback = $cb
        }
        try { $resp = $req.GetResponse() } catch [System.Net.WebException] { $resp = $_.Exception.Response }
        if ($null -eq $resp) { return @{ Status = 0; Body = '' } }
        $buf = New-Object byte[] 8192
        $stream = $resp.GetResponseStream()
        $n = 0
        while ($n -lt 8192) { $r = $stream.Read($buf, $n, 8192 - $n); if ($r -le 0) { break }; $n += $r }
        return @{ Status = [int]$resp.StatusCode; Body = [Text.Encoding]::UTF8.GetString($buf, 0, $n) }
    } catch {
        return @{ Status = 0; Body = '' }
    } finally { if ($resp) { $resp.Close() } }
}

function Get-AcceptAnyCertificate {
    # A certificate callback compiled once (a PowerShell script block can't be
    # one: it would run on a thread with no runspace).
    if (-not ('AnalyticsAgentProbe' -as [type])) {
        try {
            Add-Type -TypeDefinition 'public static class AnalyticsAgentProbe { public static bool Accept(object s, System.Security.Cryptography.X509Certificates.X509Certificate c, System.Security.Cryptography.X509Certificates.X509Chain h, System.Net.Security.SslPolicyErrors e) { return true; } }'
        } catch { return $null }
    }
    return [Delegate]::CreateDelegate([System.Net.Security.RemoteCertificateValidationCallback], [AnalyticsAgentProbe].GetMethod('Accept'))
}

# ---- Windows Firewall --------------------------------------------------------------

function Get-FirewallWanted {
    # The addresses each kind of our rules should block: @{ Lists; Bans; Origin }
    # as strings Windows Firewall takes. Nothing in monitor mode.
    param($Plan, [string[]]$BanKeys, [object[]]$Own)
    $w = @{ Lists = @(); Bans = @(); Origin = @() }
    if ($null -eq $Plan -or -not $Plan.block) { return $w }
    $lists = @(@($Plan.deny) + @($Plan.ban) + @($Plan.list) + @($Plan.shared))
    # A block rule beats any allow rule in Windows Firewall: allow is taken out.
    $w.Lists = @(Remove-IpRanges $lists $Plan.allow | ForEach-Object { Format-IpRange $_ })
    $bans = @(@($BanKeys) | ForEach-Object { ConvertTo-IpRange $_ } | Where-Object { $null -ne $_ })
    $w.Bans = @(Remove-IpRanges $bans $Plan.allow | ForEach-Object { Format-IpRange $_ })
    if ($Plan.origin) {
        $local = @($script:LocalRanges | ForEach-Object { ConvertTo-IpRange $_ })
        # IPv4-mapped IPv6 is IPv4 traffic: the IPv4 rules see it.
        $mapped = New-IpRange 6 $script:MappedBase ($script:MappedBase + $script:Pow2[32] - 1)
        $platform = @($script:PlatformRanges | ForEach-Object { ConvertTo-IpRange $_ })
        $allowed = @(Merge-IpRanges (@($Plan.origin.only) + $local + $platform + @($Own) + @($mapped)))
        $w.Origin = @(@(Get-IpComplement $allowed 4) + @(Get-IpComplement $allowed 6) | ForEach-Object { Format-IpRange $_ })
    }
    return $w
}

function Get-ChunkAssignment {
    # Which rule (by number) holds which address: an address already in a rule
    # stays there, gone ones are taken out, new ones fill the space left and
    # then new rules, so a change rewrites as few rules as it can.
    # $Current: number -> strings. Returns number -> strings (none empty).
    param([hashtable]$Current, [string[]]$Wanted, [int]$Max)
    $want = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($w in @($Wanted)) { [void]$want.Add($w) }
    $placed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $result = @{}
    foreach ($idx in @($Current.Keys | Sort-Object { [int]$_ })) {
        $keep = New-Object System.Collections.ArrayList
        foreach ($a in @($Current[$idx])) {
            if ($keep.Count -ge $Max) { break }
            if ($want.Contains($a) -and $placed.Add($a)) { [void]$keep.Add($a) }
        }
        $result[[int]$idx] = $keep
    }
    $pending = New-Object System.Collections.Queue
    foreach ($w in @($Wanted)) { if (-not $placed.Contains($w)) { [void]$placed.Add($w); $pending.Enqueue($w) } }
    foreach ($idx in @($result.Keys | Sort-Object)) {
        while ($pending.Count -gt 0 -and $result[$idx].Count -lt $Max) { [void]$result[$idx].Add($pending.Dequeue()) }
    }
    $next = 1
    while ($pending.Count -gt 0) {
        while ($result.ContainsKey($next)) { $next++ }
        $chunk = New-Object System.Collections.ArrayList
        while ($pending.Count -gt 0 -and $chunk.Count -lt $Max) { [void]$chunk.Add($pending.Dequeue()) }
        $result[$next] = $chunk
    }
    $out = @{}
    foreach ($idx in @($result.Keys)) { if ($result[$idx].Count -gt 0) { $out[$idx] = @($result[$idx].ToArray()) } }
    return $out
}

function Get-CanonicalAddresses {
    # Windows Firewall's way of writing them back, as the agent writes them.
    param([string[]]$Remote)
    $out = New-Object System.Collections.ArrayList
    foreach ($r in @($Remote)) {
        $range = ConvertTo-IpRange $r -FirewallForms
        if ($null -eq $range) { [void]$out.Add(([string]$r).ToLowerInvariant()) } else { [void]$out.Add((Format-IpRange $range)) }
    }
    return @($out.ToArray())
}

function Get-RuleName {
    param([string]$Kind, [string]$Protocol, [int]$Index)
    return ('{0}-{1}-{2}-{3:D3}' -f $script:RulePrefix, $Kind, $Protocol, $Index)
}

function Get-FirewallDesired {
    # Every rule that should exist: name -> @{ Name; Kind; Protocol; Ports; Addresses }.
    # $Current: our rules as Get-FirewallRules gives them.
    param($Wanted, [object[]]$Current, [int[]]$Ports, [int]$Max, [string[]]$Kinds = @('Lists', 'Bans', 'Origin'))
    $desired = [ordered]@{}
    if (@($Ports).Count -eq 0) { return $desired }
    foreach ($kind in $Kinds) {
        $cur = @{}
        foreach ($r in @($Current)) {
            if ($r.Name -cmatch ('^' + [regex]::Escape($script:RulePrefix) + '-' + $kind + '-(TCP|UDP)-([0-9]+)$')) {
                $idx = [int]$Matches[2]
                if ($Matches[1] -ceq 'TCP' -or -not $cur.ContainsKey($idx)) { $cur[$idx] = @(Get-CanonicalAddresses $r.Remote) }
            }
        }
        $assign = Get-ChunkAssignment $cur @($Wanted[$kind]) $Max
        foreach ($idx in @($assign.Keys | Sort-Object)) {
            foreach ($proto in 'TCP', 'UDP') {
                $name = Get-RuleName $kind $proto $idx
                $desired[$name] = @{ Name = $name; Kind = $kind; Protocol = $proto; Ports = @($Ports | Sort-Object); Addresses = @($assign[$idx]) }
            }
        }
    }
    return $desired
}

function Get-FirewallOps {
    # New, Set (in place) and Remove operations from what should exist and
    # what does. Adds and changes come before removals.
    param($Desired, [object[]]$Current, [string[]]$Kinds = @('Lists', 'Bans', 'Origin'))
    $byName = @{}
    foreach ($r in @($Current)) { $byName[$r.Name] = $r }
    $ops = New-Object System.Collections.ArrayList
    foreach ($name in @($Desired.Keys)) {
        $d = $Desired[$name]
        $op = @{ Op = 'New'; Name = $name; Protocol = $d.Protocol; Ports = @($d.Ports); Addresses = @($d.Addresses) }
        $cur = $byName[$name]
        if ($null -eq $cur) { [void]$ops.Add($op); continue }
        $same = ((@(Get-CanonicalAddresses $cur.Remote) | Sort-Object) -join ',') -ceq ((@($d.Addresses) | Sort-Object) -join ',') -and
            ((@($cur.Ports | ForEach-Object { [string]$_ }) | Sort-Object) -join ',') -ceq ((@($d.Ports | ForEach-Object { [string]$_ }) | Sort-Object) -join ',') -and
            [string]$cur.Protocol -eq $d.Protocol -and [string]$cur.Action -eq 'Block' -and [string]$cur.Direction -eq 'Inbound' -and [string]$cur.Enabled -eq 'True'
        if (-not $same) { $op.Op = 'Set'; [void]$ops.Add($op) }
    }
    $kindRe = '^' + [regex]::Escape($script:RulePrefix) + '-(' + ($Kinds -join '|') + ')-'
    foreach ($r in @($Current)) {
        if (-not $Desired.Contains($r.Name) -and $r.Name -cmatch $kindRe) { [void]$ops.Add(@{ Op = 'Remove'; Name = $r.Name }) }
    }
    return $ops.ToArray()
}

function Assert-SafeFirewallRule {
    # The last word before anything reaches Windows Firewall: only our own
    # rules, inbound blocks of named web ports for named addresses.
    param($Op)
    if (-not ([string]$Op.Name -cmatch ('^' + [regex]::Escape($script:RulePrefix) + '-(Lists|Bans|Origin)-(TCP|UDP)-[0-9]{3,}$'))) {
        throw "not one of the agent's rules: $($Op.Name)"
    }
    if ($Op.Op -eq 'Remove') { return }
    if ($Op.Op -ne 'New' -and $Op.Op -ne 'Set') { throw "unknown firewall operation $($Op.Op)" }
    if ($Op.Protocol -cne 'TCP' -and $Op.Protocol -cne 'UDP') { throw "a rule is TCP or UDP, not $($Op.Protocol)" }
    $ports = @($Op.Ports)
    if ($ports.Count -eq 0) { throw 'a rule without ports would block every port' }
    foreach ($p in $ports) {
        $n = Get-WholeNumber $p 1 65535
        if ($null -eq $n) { throw "not a port: $p" }
        if ($script:ProtectedPorts -contains [int]$n) { throw "port $n is never blocked by the agent" }
    }
    $addresses = @($Op.Addresses)
    if ($addresses.Count -eq 0) { throw 'a rule without addresses would block everyone' }
    if ($addresses.Count -gt $script:FirewallMaxPerRule) { throw "$($addresses.Count) addresses in one rule (at most $($script:FirewallMaxPerRule))" }
    foreach ($a in $addresses) {
        if ($null -eq (ConvertTo-IpRange $a -FirewallForms)) { throw "not an address or range: $a" }
    }
}

function Get-FirewallRules {
    # Our rules in Windows Firewall (persistent store, our group, our prefix),
    # or $null when they can't be read. The address and port filters are
    # read in one query each and matched by InstanceID, not one per rule.
    try {
        $res = Invoke-WithTimeout -Seconds $script:FirewallTimeout -ArgumentList @($script:FwGroup, $script:RulePrefix) -ScriptBlock {
            param($group, $prefix)
            $ErrorActionPreference = 'Stop'
            $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group $group -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name.StartsWith($prefix + '-', [StringComparison]::Ordinal) })
            if ($rules.Count -gt 0) {
                $af = @{}; $pf = @{}
                foreach ($f in @(Get-NetFirewallAddressFilter -PolicyStore PersistentStore)) { $af[[string]$f.InstanceID] = $f }
                foreach ($f in @(Get-NetFirewallPortFilter -PolicyStore PersistentStore)) { $pf[[string]$f.InstanceID] = $f }
                foreach ($r in $rules) {
                    $a = $af[[string]$r.InstanceID]; $p = $pf[[string]$r.InstanceID]
                    if ($null -eq $a) { $a = $r | Get-NetFirewallAddressFilter }
                    if ($null -eq $p) { $p = $r | Get-NetFirewallPortFilter }
                    [pscustomobject]@{ Name = $r.Name; Protocol = [string]$p.Protocol; Ports = @($p.LocalPort | ForEach-Object { [string]$_ })
                        Remote = @($a.RemoteAddress | ForEach-Object { [string]$_ }); Action = [string]$r.Action
                        Direction = [string]$r.Direction; Enabled = [string]$r.Enabled }
                }
            }
        }
        if ($res.Errors.Count -gt 0) { Write-AgentLog ('reading the firewall rules: ' + $res.Errors[0]); return $null }
        return , @($res.Output)
    } catch {
        Write-AgentLog "Windows Firewall can't be read: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-FirewallBatch {
    # Runs the operations in order; @{ Name; Ok; Error } for each. Every one
    # is checked by Assert-SafeFirewallRule first; one that fails it isn't run.
    param([object[]]$Ops)
    $results = New-Object System.Collections.ArrayList
    $safe = New-Object System.Collections.ArrayList
    foreach ($op in @($Ops)) {
        try { Assert-SafeFirewallRule $op; [void]$safe.Add($op) } catch { [void]$results.Add(@{ Name = $op.Name; Ok = $false; Error = $_.Exception.Message }) }
    }
    if ($safe.Count -eq 0) { return $results.ToArray() }
    try {
        $res = Invoke-WithTimeout -Seconds ($script:FirewallTimeout + 10 * $safe.Count) -ArgumentList ($safe.ToArray()), $script:FwGroup, $script:FwDescription -ScriptBlock {
            param($ops, $group, $description)
            foreach ($op in $ops) {
                try {
                    if ($op.Op -eq 'New') {
                        New-NetFirewallRule -Name $op.Name -DisplayName $op.Name -Group $group -Description $description -Direction Inbound -Action Block `
                            -Protocol $op.Protocol -LocalPort $op.Ports -RemoteAddress $op.Addresses -Profile Any -Enabled True -PolicyStore PersistentStore -ErrorAction Stop | Out-Null
                    } elseif ($op.Op -eq 'Set') {
                        Set-NetFirewallRule -Name $op.Name -PolicyStore PersistentStore -Direction Inbound -Action Block -Protocol $op.Protocol `
                            -LocalPort $op.Ports -RemoteAddress $op.Addresses -Profile Any -Enabled True -ErrorAction Stop
                    } else {
                        Remove-NetFirewallRule -Name $op.Name -PolicyStore PersistentStore -ErrorAction Stop
                    }
                    @{ Name = $op.Name; Ok = $true; Error = '' }
                } catch {
                    @{ Name = $op.Name; Ok = $false; Error = $_.Exception.Message }
                }
            }
        }
        foreach ($r in @($res.Output)) { [void]$results.Add($r) }
    } catch {
        foreach ($op in $safe) { [void]$results.Add(@{ Name = $op.Name; Ok = $false; Error = $_.Exception.Message }) }
    }
    return $results.ToArray()
}

function Get-FirewallInfo {
    # The firewall service and profiles, for Test-FirewallEnforces.
    try {
        $res = Invoke-WithTimeout -Seconds 60 -ScriptBlock {
            $svc = Get-Service -Name mpssvc -ErrorAction SilentlyContinue
            $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue | ForEach-Object {
                    @{ Name = [string]$_.Name; Enabled = [string]$_.Enabled; AllowLocalFirewallRules = [string]$_.AllowLocalFirewallRules } })
            $map = @{ DomainAuthenticated = 'Domain'; Private = 'Private'; Public = 'Public' }
            $active = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { $map[[string]$_.NetworkCategory] } | Where-Object { $_ })
            $status = ''
            if ($svc) { $status = [string]$svc.Status }
            @{ Service = $status; Profiles = $profiles; Active = $active }
        }
        return $res.Output[0]
    } catch { return $null }
}

function Test-FirewallEnforces {
    # Whether rules in the persistent store are enforced: '' or why not.
    param($Info)
    if ($null -eq $Info) { return "Windows Firewall's state can't be read" }
    if ($Info.Service -ne 'Running') { return "the Windows Defender Firewall service (mpssvc) isn't running: the agent's rules do nothing" }
    $profiles = @($Info.Profiles)
    if ($profiles.Count -eq 0) { return "Windows Firewall's profiles can't be read" }
    $active = @($Info.Active)
    foreach ($p in $profiles) {
        if ($active.Count -gt 0 -and $active -notcontains $p.Name) { continue }
        if ($p.Enabled -ne 'True') { return "Windows Firewall is off for the $($p.Name) profile: the agent's rules do nothing there" }
        if ($p.AllowLocalFirewallRules -eq 'False') { return "group policy ignores local firewall rules on the $($p.Name) profile: the agent's rules do nothing there" }
    }
    return ''
}

function ConvertFrom-NetshUrls {
    # The URLs HTTP.sys has registered, from `netsh http show servicestate view=requestq`.
    param([string]$Text)
    $out = New-Object System.Collections.ArrayList
    foreach ($m in [regex]::Matches([string]$Text, '(?i)\bhttps?://[^\s/]+:[0-9]{1,5}/\S*')) { [void]$out.Add($m.Value.ToLowerInvariant()) }
    return @($out.ToArray() | Select-Object -Unique)
}

function ConvertFrom-WinrmListeners {
    # The ports of WinRM's listeners, from `winrm enumerate winrm/config/listener`.
    param([string]$Text)
    $out = New-Object System.Collections.ArrayList
    foreach ($m in [regex]::Matches([string]$Text, '(?im)^\s*Port\s*=\s*([0-9]{1,5})\s*$')) { [void]$out.Add([int]$m.Groups[1].Value) }
    return @($out.ToArray() | Select-Object -Unique)
}

function Get-OriginConflicts {
    # Why locking the web ports to the origin would cut off something that
    # isn't the site: a remote access gateway or a management listener on
    # those ports. One reason per thing found.
    param($Facts, [int[]]$Ports)
    $out = New-Object System.Collections.ArrayList
    $services = @($Facts.Services)
    if ($services -contains 'TSGateway') { [void]$out.Add('Remote Desktop Gateway (TSGateway) is running') }
    if ($services -contains 'ServerManagementGateway' -or $services -contains 'WindowsAdminCenter') { [void]$out.Add('Windows Admin Center is running') }
    foreach ($url in @($Facts.Urls)) {
        if (-not ($url -match '^https?://[^\s/]+:([0-9]{1,5})(/\S*)$')) { continue }
        $port = [int]$Matches[1]; $path = $Matches[2]
        if (@($Ports) -notcontains $port) { continue }
        if ($path -like '/sra_*') { [void]$out.Add("an SSTP VPN listens on port $port") }
        elseif ($path -like '/wsman*') { [void]$out.Add("WinRM listens on port $port") }
        elseif ($path -like '/rpc*' -or $path -like '/remotedesktopgateway*') { [void]$out.Add("Remote Desktop Gateway listens on port $port") }
    }
    foreach ($port in @($Facts.WinrmPorts)) { if (@($Ports) -contains [int]$port) { [void]$out.Add("a WinRM listener is on port $port") } }
    if ($Facts.CompatHttp -and @($Ports) -contains 80) { [void]$out.Add('WinRM compatibility listener on port 80 is on') }
    if ($Facts.CompatHttps -and @($Ports) -contains 443) { [void]$out.Add('WinRM compatibility listener on port 443 is on') }
    return @($out.ToArray() | Select-Object -Unique)
}

function Get-GatewayFacts {
    # What runs on this server that the origin lock could cut off.
    $facts = @{ Services = @(); Urls = @(); WinrmPorts = @(); CompatHttp = $false; CompatHttps = $false }
    if (-not $env:windir) { return $facts }
    $facts.Services = @(Get-Service -Name 'TSGateway', 'ServerManagementGateway', 'WindowsAdminCenter' -ErrorAction SilentlyContinue |
            Where-Object { [string]$_.Status -eq 'Running' } | ForEach-Object { [string]$_.Name })
    $sys = Join-Path $env:windir 'System32'
    $r = Invoke-External (Join-Path $sys 'netsh.exe') @('http', 'show', 'servicestate', 'view=requestq')
    if ($r.Code -eq 0) { $facts.Urls = @(ConvertFrom-NetshUrls $r.Out) }
    $winrm = Join-Path $sys 'winrm.vbs'
    $cscript = Join-Path $sys 'cscript.exe'
    $r = Invoke-External $cscript @('//nologo', $winrm, 'enumerate', 'winrm/config/listener')
    if ($r.Code -eq 0) { $facts.WinrmPorts = @(ConvertFrom-WinrmListeners $r.Out) }
    $r = Invoke-External $cscript @('//nologo', $winrm, 'get', 'winrm/config/service')
    if ($r.Code -eq 0) {
        $facts.CompatHttp = [bool]($r.Out -match '(?im)EnableCompatibilityHttpListener\s*=\s*true')
        $facts.CompatHttps = [bool]($r.Out -match '(?im)EnableCompatibilityHttpsListener\s*=\s*true')
    }
    return $facts
}

function Update-OriginConflicts {
    # Looked at while the rules carry origin, every 10 minutes.
    param($Agent, [double]$Now)
    if (-not ($Agent.Plan -and $Agent.Plan.origin)) { $Agent.OriginBlock = $null; $Agent.OriginCheckedAt = 0.0; return }
    if ($null -ne $Agent.OriginBlock -and $Now -lt $Agent.OriginCheckedAt + 600) { return }
    $found = @(Get-OriginConflicts (Get-GatewayFacts) $Agent.Config.ports)
    $Agent.OriginBlock = ($found -join '; ')
    $Agent.OriginCheckedAt = $Now
    if ($Agent.OriginBlock) {
        Write-AgentNote $Agent 'origin' ("origin lock left off: $($Agent.OriginBlock), and locking the web ports to the origin would cut it off")
    } else { Write-AgentNote $Agent 'origin' '' }
}

# ---- IIS logs ----------------------------------------------------------------------

function Get-W3CFields {
    # The field positions of a "#Fields:" line, or $null if it isn't a sound one.
    param([string]$Line)
    if (-not $Line.StartsWith('#Fields:', [StringComparison]::Ordinal)) { return $null }
    $names = @($Line.Substring(8).Trim().Split(' ') | Where-Object { $_ })
    if ($names.Count -eq 0 -or $names.Count -gt 100) { return $null }
    $map = @{}
    for ($i = 0; $i -lt $names.Count; $i++) {
        if (-not ($names[$i] -cmatch '^[A-Za-z0-9()_.-]{1,64}$')) { return $null }
        $k = $names[$i].ToLowerInvariant()
        if (-not $map.ContainsKey($k)) { $map[$k] = $i }
    }
    return @{ Map = $map; Count = $names.Count; Valid = $map.ContainsKey('c-ip') }
}

function ConvertFrom-W3CLine {
    # One request from a log line, read by the positions of the "#Fields:"
    # line above it. The address is c-ip only (the connection's own, never a
    # header). A line with more or fewer fields than that is dropped: IIS
    # writes spaces in values as +, so the count is what it says.
    param([string]$Line, $Fields)
    if ($null -eq $Fields -or -not $Fields.Valid) { return $null }
    $parts = $Line.Split(' ')
    if ($parts.Count -ne $Fields.Count) { return $null }
    $m = $Fields.Map
    $ip = ConvertTo-IpNumber $parts[$m['c-ip']]
    if ($null -eq $ip) { return $null }
    $v = @{}
    foreach ($name in 'cs-method', 'cs-uri-stem', 'sc-status', 'sc-substatus', 'date', 'time', 'cs(user-agent)') {
        $x = ''
        if ($m.ContainsKey($name)) { $x = $parts[$m[$name]]; if ($x -ceq '-') { $x = '' } }
        $v[$name] = $x
    }
    $status = 0; $sub = 0
    [void][int]::TryParse($v['sc-status'], [ref]$status)
    [void][int]::TryParse($v['sc-substatus'], [ref]$sub)
    # What IIS itself writes: a date, a time and a method that look like it.
    # A line that doesn't is not IIS's own.
    if ($m.ContainsKey('date') -and -not ($v['date'] -cmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}$')) { return $null }
    if ($m.ContainsKey('time') -and -not ($v['time'] -cmatch '^[0-9]{2}:[0-9]{2}:[0-9]{2}$')) { return $null }
    if ($m.ContainsKey('cs-method') -and -not ($v['cs-method'] -cmatch '^[A-Za-z][A-Za-z0-9_-]{0,31}$')) { return $null }
    $time = 0.0
    $d = $v['date']
    $t = $v['time']
    if ($d -and $t) {
        $parsed = [DateTime]::MinValue
        if ([DateTime]::TryParseExact($d + ' ' + $t, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture,
                ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal), [ref]$parsed)) {
            $time = ($parsed.Ticks - 621355968000000000) / 10000000.0
        }
    }
    $ua = $v['cs(user-agent)'].Replace('+', ' ')
    if ($ua.Length -gt 300) { $ua = $ua.Substring(0, 300) }
    return @{ Ip = $ip; Method = $v['cs-method'].ToUpperInvariant(); Path = $v['cs-uri-stem']; Status = $status; SubStatus = $sub; Ua = $ua; Time = $time }
}

function New-LogTail {
    param([string]$Dir)
    return @{ Dir = $Dir; Path = $null; Pos = [long]0; Fields = $null; Rest = ''; InHeader = $false; HeaderOk = $false }
}

function Get-LogFiles {
    # IIS's W3C logs in a folder, oldest first.
    param([string]$Dir)
    try {
        $items = @(Get-ChildItem -LiteralPath $Dir -File -ErrorAction Stop | Where-Object { $_.Name -imatch '^(u_)?ex[0-9]{6,10}(_x)?\.log$' })
    } catch { return @() }
    return @($items | Sort-Object -Property LastWriteTimeUtc, Name | ForEach-Object { $_.FullName })
}

function Open-LogFile {
    param([string]$Path)
    return [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
}

function Get-HeaderFields {
    # The last "#Fields:" line of these lines that sits in an IIS header block:
    # consecutive # lines holding "#Software: Microsoft Internet Information
    # Services" before it. A # line anywhere else is not IIS's.
    param([string[]]$Lines, [int]$Start = 0)
    $last = $null; $in = $false; $ok = $false
    for ($i = $Start; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i].TrimEnd("`r")
        if (-not $line) { continue }
        if ($line[0] -eq '#') {
            if (-not $in) { $in = $true; $ok = $false }
            if ($line.StartsWith($script:IisSoftwareLine, [StringComparison]::Ordinal)) { $ok = $true }
            elseif ($ok) { $f = Get-W3CFields $line; if ($f) { $last = $f } }
        } else { $in = $false }
    }
    return $last
}

function Find-W3CFields {
    # The "#Fields:" line in force at $End: the last one before it (IIS writes
    # a new one when it restarts mid-file), else the file's first.
    param([string]$Path, [long]$End)
    $fs = $null
    try {
        $fs = Open-LogFile $Path
        $from = [math]::Max([long]0, $End - 4MB)
        $len = [int]($End - $from)
        $buf = New-Object byte[] $len
        [void]$fs.Seek($from, [IO.SeekOrigin]::Begin)
        $read = 0
        while ($read -lt $len) { $n = $fs.Read($buf, $read, $len - $read); if ($n -le 0) { break }; $read += $n }
        $lines = [Text.Encoding]::UTF8.GetString($buf, 0, $read).Split("`n")
        $start = 0
        if ($from -gt 0) { $start = 1 }
        $f = Get-HeaderFields $lines $start
        if ($f) { return $f }
        if ($from -gt 0) {
            $head = New-Object byte[] 65536
            [void]$fs.Seek(0, [IO.SeekOrigin]::Begin)
            $n = $fs.Read($head, 0, 65536)
            $f = Get-HeaderFields ([Text.Encoding]::UTF8.GetString($head, 0, $n).Split("`n")) 0
            if ($f) { return $f }
        }
    } catch { } finally { if ($fs) { $fs.Dispose() } }
    return $null
}

function Read-LogChunk {
    # Up to $Limit new bytes of the tail's file as requests, into $Out.
    # A backlog beyond four reads is skipped rather than chased; a truncated
    # file is read again from the top. $true when it reached the file's end.
    param($Tail, [long]$Limit, [System.Collections.ArrayList]$Out)
    $fs = $null
    $skipped = $false
    try {
        $fs = Open-LogFile $Tail.Path
        $size = $fs.Length
        if ($size -lt $Tail.Pos) { $Tail.Pos = 0; $Tail.Rest = ''; $Tail.InHeader = $false; $Tail.HeaderOk = $false }
        if ($size - $Tail.Pos -gt 4 * $Limit) { $Tail.Pos = $size - $Limit; $Tail.Rest = ''; $skipped = $true }
        $want = [int][math]::Min($size - $Tail.Pos, $Limit)
        if ($want -le 0) { return $true }
        $buf = New-Object byte[] $want
        [void]$fs.Seek($Tail.Pos, [IO.SeekOrigin]::Begin)
        $read = 0
        while ($read -lt $want) { $n = $fs.Read($buf, $read, $want - $read); if ($n -le 0) { break }; $read += $n }
        $Tail.Pos += $read
        $atEnd = $Tail.Pos -ge $size
    } catch {
        return $true
    } finally { if ($fs) { $fs.Dispose() } }
    $lines = ($Tail.Rest + [Text.Encoding]::UTF8.GetString($buf, 0, $read)).Split("`n")
    $Tail.Rest = $lines[$lines.Count - 1]
    if ($Tail.Rest.Length -gt 65536) { $Tail.Rest = '' }
    $start = 0
    if ($skipped) { $start = 1 }
    for ($i = $start; $i -lt $lines.Count - 1; $i++) {
        $line = $lines[$i].TrimEnd("`r")
        if (-not $line) { continue }
        if ($line[0] -eq '#') {
            if (-not $Tail.InHeader) { $Tail.InHeader = $true; $Tail.HeaderOk = $false }
            if ($line.StartsWith($script:IisSoftwareLine, [StringComparison]::Ordinal)) { $Tail.HeaderOk = $true }
            elseif ($Tail.HeaderOk) { $f = Get-W3CFields $line; if ($f) { $Tail.Fields = $f } }
            continue
        }
        $Tail.InHeader = $false
        $e = ConvertFrom-W3CLine $line $Tail.Fields
        if ($e) { [void]$Out.Add($e) }
    }
    return $atEnd
}

function Read-LogTail {
    # The requests logged in a folder since the last look. A log first seen
    # is read from its end; when IIS starts the next day's file, the old one is
    # read to its end and the new one from its start.
    param($Tail, [long]$Limit = $script:LogReadMax)
    $out = New-Object System.Collections.ArrayList
    $files = @(Get-LogFiles $Tail.Dir)
    if ($files.Count -eq 0) { return $out.ToArray() }
    $newest = $files[$files.Count - 1]
    if ($null -eq $Tail.Path) {
        $Tail.Path = $newest
        try { $size = (Get-Item -LiteralPath $newest).Length } catch { $size = 0 }
        $Tail.Pos = [long]$size
        $Tail.Rest = ''
        $Tail.Fields = Find-W3CFields $newest $size
        return $out.ToArray()
    }
    if ($Tail.Path -ne $newest) {
        if (Test-Path -LiteralPath $Tail.Path) {
            for ($i = 0; $i -lt 4; $i++) { if (Read-LogChunk $Tail $Limit $out) { break } }
        }
        $Tail.Path = $newest; $Tail.Pos = 0; $Tail.Rest = ''; $Tail.Fields = $null; $Tail.InHeader = $false; $Tail.HeaderOk = $false
    }
    [void](Read-LogChunk $Tail $Limit $out)
    return $out.ToArray()
}

function Test-TokenBucket {
    # One request against an address's bucket: $true when it's within the limit.
    # A bucket is [tokens, time]; time never runs backwards (log lines from
    # several files can arrive a little out of order).
    param([hashtable]$Buckets, [string]$Key, [double]$Now, [double]$Rate, [double]$Capacity)
    $b = $Buckets[$Key]
    if ($null -eq $b) {
        $b = New-Object double[] 2
        $b[0] = $Capacity; $b[1] = $Now
        $Buckets[$Key] = $b
    } elseif ($Now -gt $b[1]) {
        $b[0] = [math]::Min($Capacity, $b[0] + ($Now - $b[1]) * $Rate)
        $b[1] = $Now
    }
    if ($b[0] -ge 1) { $b[0] -= 1; return $true }
    return $false
}

function Limit-Buckets {
    # Full buckets are the same as none: dropped. Past $Max, the longest idle go.
    param([hashtable]$Buckets, [double]$Now, [double]$Rate, [double]$Capacity, [int]$Max)
    foreach ($k in @($Buckets.Keys)) {
        $b = $Buckets[$k]
        if ($b[0] + [math]::Max(0, $Now - $b[1]) * $Rate -ge $Capacity) { $Buckets.Remove($k) }
    }
    if ($Buckets.Count -gt $Max) {
        $drop = $Buckets.Count - [int]($Max * 0.9)
        foreach ($k in @($Buckets.Keys | Sort-Object { $Buckets[$_][1] } | Select-Object -First $drop)) { $Buckets.Remove($k) }
    }
}

# ---- Its services (sdk/protocols/services.md) ------------------------------------
#
# Every minute: whether each Windows service worth a light runs, and what it
# uses. The ones listed under "services" in the config and, unless
# "services_detect" is false, the common ones found here (IIS, SQL Server,
# MySQL, PostgreSQL, Redis, MongoDB, RabbitMQ...): a found one is shown while
# it runs or starts with Windows, and for a week after it last ran (saved in
# services.json, so a restart doesn't forget it), so a service that stopped is
# red rather than missing; one uninstalled goes at once. Reported as type
# "unit", the protocol's name for a service manager's own.
#
# What each uses comes from its process (Win32_Service's ProcessId): the
# working set and the CPU time between two rounds, as a share of the whole
# machine. Services that share one svchost process can't be told apart, so
# that process is counted once, for the first of them reported, and the
# others carry no figures rather than the same ones again. A service's child
# processes (IIS's w3wp workers are WAS's, not W3SVC's) aren't counted.
# Windows has no memory cap or kill count for a service: those are left out.

function Get-ServiceList {
    # The config's "services": names, or {"service": name, "name": label}.
    param($Entries)
    $out = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($e in @(Get-EntryList $Entries)) {
        $service = $null; $label = $null
        if ($e -is [string]) { $service = $e; $label = $e }
        elseif (Test-IsMap $e) {
            $service = Get-Prop $e 'service'
            $label = Get-Prop $e 'name' $service
        }
        if ($service -isnot [string] -or $label -isnot [string] -or $service -notmatch $script:ServiceNamePattern -or $label -notmatch $script:ServiceNamePattern) {
            Write-AgentLog "services: $(ConvertTo-Json -InputObject $e -Compress) needs a service's name, skipped"
            continue
        }
        if ($seen.ContainsKey($label.ToLowerInvariant())) { continue }
        $seen[$label.ToLowerInvariant()] = $true
        [void]$out.Add(@{ Service = $service; Name = $label.Trim() })
    }
    return @($out.ToArray() | Select-Object -First $script:ServicesMax)
}

function Get-WindowsServices {
    # Every service as @{ Name; State; StartMode; ProcessId }, or $null when
    # WMI couldn't be read. In a runspace of its own: a hung WMI can't stall the loop.
    try {
        $r = Invoke-WithTimeout {
            Get-CimInstance -ClassName Win32_Service -Property Name, State, StartMode, ProcessId -OperationTimeoutSec 20 -ErrorAction Stop |
                ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Name, $_.State, $_.StartMode, $_.ProcessId }
        } @() $script:ServicesTimeout
    } catch {
        return $null
    }
    if ($r.Errors.Count -gt 0) { return $null }
    $out = New-Object System.Collections.ArrayList
    foreach ($line in @($r.Output)) {
        $parts = ([string]$line).Split('|')
        if ($parts.Count -ne 4) { continue }
        $id = 0
        [void][int]::TryParse($parts[3], [ref]$id)
        [void]$out.Add(@{ Name = $parts[0]; State = $parts[1]; StartMode = $parts[2]; ProcessId = $id })
    }
    # The comma keeps an empty list a list: $null means it couldn't be read.
    return , @($out.ToArray())
}

function Get-ProcessReadings {
    # pid -> @{ Mem; Cpu; Start }: the working set in bytes, CPU seconds and
    # when it started (so a reused pid isn't paired with another process).
    # Each figure is $null where the process won't give it (a protected one).
    param([int[]]$Ids)
    $out = @{}
    foreach ($id in @($Ids)) {
        if ($id -le 4) { continue }
        $p = $null
        try { $p = [System.Diagnostics.Process]::GetProcessById($id) } catch { continue }
        $reading = @{ Mem = $null; Cpu = $null; Start = $null }
        try { $reading.Mem = [long]$p.WorkingSet64 } catch { }
        try { $reading.Cpu = [double]$p.TotalProcessorTime.TotalSeconds } catch { }
        try { $reading.Start = [long]$p.StartTime.ToUniversalTime().Ticks } catch { }
        try { $p.Dispose() } catch { }
        $out[$id] = $reading
    }
    return $out
}

function Get-ServiceChecks {
    # The checks of one round, in the protocol's shape, each with its Pid
    # (taken off before sending). Listed first, then the found ones by name.
    # $Seen (lower-cased name -> when it last ran) is brought up to date: a
    # found service that runs is noted, one no longer installed forgotten.
    param([object[]]$Services, [object[]]$Listed, [bool]$Detect, [hashtable]$Seen = @{}, [double]$Now = 0)
    $byName = @{}
    foreach ($svc in @($Services)) { $byName[([string]$svc.Name).ToLowerInvariant()] = $svc }
    # Whole UTC seconds. A time saved in the future was saved before the
    # clock was put back: it counts as now, or a stopped service would stay
    # until the clock caught up with it.
    $at = [math]::Floor($Now)
    foreach ($key in @($Seen.Keys)) { if ([double]$Seen[$key] -gt $at) { $Seen[$key] = $at } }
    $out = New-Object System.Collections.ArrayList
    $taken = @{}
    foreach ($l in @($Listed)) {
        $svc = $byName[$l.Service.ToLowerInvariant()]
        $taken[$l.Service.ToLowerInvariant()] = $true
        $check = [ordered]@{ name = $l.Name; type = 'unit'; target = $l.Service; ok = $false; detail = 'No such service'; ms = $null; auto = $false; Pid = 0 }
        if ($null -ne $svc) {
            $check.ok = $svc.State -eq 'Running'
            $check.detail = ''
            if (-not $check.ok) { $check.detail = [string]$svc.State }
            if ($check.ok) { $check.Pid = [int]$svc.ProcessId }
        }
        [void]$out.Add($check)
    }
    if ($Detect) {
        foreach ($svc in @($Services | Sort-Object -Property @{ Expression = { ([string]$_.Name).ToLowerInvariant() } })) {
            $name = [string]$svc.Name
            if ($taken.ContainsKey($name.ToLowerInvariant()) -or -not $script:DetectServices.IsMatch($name)) { continue }
            $ok = $svc.State -eq 'Running'
            $key = $name.ToLowerInvariant()
            if ($ok -and (-not $Seen.ContainsKey($key) -or $Now - [double]$Seen[$key] -ge $script:ServicesSeenEvery)) { $Seen[$key] = $at }
            $recent = $Seen.ContainsKey($key) -and $Now - [double]$Seen[$key] -le $script:ServicesKeepGone
            if (-not $ok -and $svc.StartMode -ne 'Auto' -and -not $recent) { continue }
            $detail = ''
            if (-not $ok) { $detail = [string]$svc.State }
            $id = 0
            if ($ok) { $id = [int]$svc.ProcessId }
            [void]$out.Add([ordered]@{ name = $name; type = 'unit'; target = $name; ok = $ok; detail = $detail; ms = $null; auto = $true; Pid = $id })
        }
    }
    foreach ($key in @($Seen.Keys)) {
        if (-not $byName.ContainsKey($key) -or $Now - [double]$Seen[$key] -gt $script:ServicesKeepGone) { $Seen.Remove($key) }
    }
    # The first of each name, as the collector keeps them.
    $names = @{}
    $kept = New-Object System.Collections.ArrayList
    foreach ($c in $out) {
        if ($names.ContainsKey($c.name.ToLowerInvariant())) { continue }
        $names[$c.name.ToLowerInvariant()] = $true
        [void]$kept.Add($c)
    }
    return @($kept.ToArray() | Select-Object -First $script:ServicesMax)
}

function Add-ServiceUsage {
    # Adds mem_mb and cpu_pct to each running check from its process, once
    # per process: the first check with a pid has it, the others sharing that
    # svchost have none. CPU needs this check's reading of the same process
    # from a round 1 to 300 seconds ago.
    param($Agent, [object[]]$Checks, [hashtable]$Readings, [double]$Now, [int]$Cores)
    $counted = @{}
    $kept = @{}
    foreach ($c in @($Checks)) {
        $id = [int]$c.Pid
        $c.Remove('Pid')
        if ($id -le 0 -or $counted.ContainsKey($id) -or -not $Readings.ContainsKey($id)) { continue }
        $counted[$id] = $true
        $r = $Readings[$id]
        if ($null -ne $r.Mem) { $c['mem_mb'] = [long][math]::Floor($r.Mem / 1MB) }
        $was = $Agent.UsagePrev[$c.name]
        if ($null -ne $was -and $Cores -gt 0 -and $null -ne $r.Cpu -and $null -ne $was.Cpu -and $was.Pid -eq $id -and $null -ne $r.Start -and $was.Start -eq $r.Start) {
            $elapsed = $Now - $was.At
            if ($elapsed -ge 1 -and $elapsed -le $script:UsageMaxPairSeconds -and $r.Cpu -ge $was.Cpu) {
                $c['cpu_pct'] = [math]::Round([math]::Min(100.0, 100.0 * ($r.Cpu - $was.Cpu) / ($elapsed * $Cores)), 1)
            }
        }
        $kept[$c.name] = @{ At = $Now; Pid = $id; Start = $r.Start; Cpu = $r.Cpu }
    }
    # Only what runs now: a stopped service's reading goes with it.
    $Agent.UsagePrev = $kept
}

function Set-ServiceSince {
    # for_s: how long each has been as it is now, as far as this run knows.
    param($Agent, [object[]]$Checks, [double]$Now)
    $since = @{}
    foreach ($c in @($Checks)) {
        $was = $Agent.ServiceSince[$c.name]
        if ($null -eq $was -or $was.Ok -ne $c.ok) { $was = @{ Ok = $c.ok; At = $Now } }
        $since[$c.name] = $was
        $c['for_s'] = [long][math]::Max(0, [math]::Floor($Now - $was.At))
    }
    $Agent.ServiceSince = $since
}

function ConvertTo-ServicesSeenJson {
    # services.json's text, in name order so the same contents are the same text.
    param([hashtable]$Seen)
    $sorted = [ordered]@{}
    foreach ($k in @($Seen.Keys | Sort-Object)) { $sorted[$k] = [double]$Seen[$k] }
    return (ConvertTo-Json -InputObject @{ seen = $sorted } -Depth 3 -Compress)
}

function Read-ServicesSeen {
    # services.json back as lower-cased name -> when it last ran; an
    # unreadable file is a fresh start, and an entry that isn't a service's
    # name and a number is dropped on its own.
    param([string]$Path)
    $seen = @{}
    try {
        if (Test-Path -LiteralPath $Path) {
            $saved = Get-Prop (ConvertFrom-Json ([IO.File]::ReadAllText($Path))) 'seen'
            if ($saved -is [System.Management.Automation.PSCustomObject]) {
                foreach ($p in @($saved.PSObject.Properties)) {
                    $v = $p.Value
                    if ($v -is [double] -or $v -is [decimal]) { $v = [math]::Floor($v) }
                    $at = Get-WholeNumber $v 0 1e11
                    if ($null -ne $at -and $p.Name -match $script:ServiceNamePattern) { $seen[$p.Name.ToLowerInvariant()] = [double]$at }
                }
            }
        }
    } catch { }
    return $seen
}

function Invoke-ServicesRound {
    # Once a minute: check, measure, report. The checks sent, or $null when
    # it wasn't time or Windows couldn't say (then nothing is sent, and the
    # dashboard keeps the last report).
    param($Agent, [double]$Now = 0, [switch]$Force)
    if ($Now -le 0) { $Now = Get-EpochNow }
    # A round due further off than one wait was set before the clock was put back.
    if (-not $Force -and $Now -lt $Agent.ServicesAt -and $Agent.ServicesAt - $Now -le $Agent.ServicesEvery) { return $null }
    $Agent.ServicesAt = $Now + $Agent.ServicesEvery
    $listed = @($Agent.Config.services)
    if ($listed.Count -eq 0 -and -not $Agent.Config.services_detect -and -not $Agent.ServicesReported) { return $null }
    # Windows always has services: none at all is a WMI that answered
    # nothing, not every one uninstalled (which would forget them all).
    $services = Get-WindowsServices
    if ($null -eq $services -or @($services).Count -eq 0) {
        Write-AgentNote $Agent 'services' "Windows' list of services can't be read: no services report this round"
        return $null
    }
    Write-AgentNote $Agent 'services' ''
    $before = ConvertTo-ServicesSeenJson $Agent.ServiceSeen
    $checks = @(Get-ServiceChecks $services $listed ($Agent.Config.services_detect -eq $true) $Agent.ServiceSeen $Now)
    $after = ConvertTo-ServicesSeenJson $Agent.ServiceSeen
    if ($after -cne $before) {
        try { Write-TextFile $Agent.ServicesFile $after } catch { Write-AgentLog "could not save the services seen: $($_.Exception.Message)" }
    }
    $ids = @($checks | Where-Object { $_.Pid -gt 0 } | ForEach-Object { [int]$_.Pid } | Sort-Object -Unique)
    Add-ServiceUsage $Agent $checks (Get-ProcessReadings $ids) $Now ([Environment]::ProcessorCount)
    Set-ServiceSince $Agent $checks $Now
    if ($checks.Count -eq 0 -and -not $Agent.ServicesReported) { return , $checks }
    $body = [ordered]@{ v = $script:ProtocolVersion; site_id = $Agent.Config.site_id; server_name = (Get-ServerName)
        client = ('windows-agent/' + $script:AgentVersion); checks = $checks }
    $res = Invoke-Collector $Agent.Config 'POST' '/events/services' $body @{} (Get-AgentUserAgent $Agent)
    if ($res.Status -eq 200 -or $res.Status -eq 202) {
        $Agent.ServicesReported = $checks.Count -gt 0
        $every = $null
        try { $every = Get-WholeNumber (Get-Prop (ConvertFrom-Json $res.Body) 'every') 30 86400 } catch { }
        if ($null -eq $every) { $every = $script:ServicesEvery }
        $Agent.ServicesEvery = [int]$every
        $Agent.ServicesAt = $Now + $Agent.ServicesEvery
    } elseif ($res.Status -ne 0) {
        Write-AgentLog "collector answered $($res.Status) to the services report"
    }
    return , $checks
}

# ---- Backups (sdk/protocols/backups.md, POST /events/backups) ---------------------
# The Linux agent's backups, for Windows: every night each database under
# "backups" (SQL Server, MySQL/MariaDB, PostgreSQL, MongoDB) is dumped with its
# own tool to a file, handed to restic and the file deleted; each folder is a
# snapshot of its own, read through a shadow copy (VSS) so open files are
# whole. restic encrypts it here, into the owner's own storage, with a password
# only they have. What reaches the collector: names, sizes, times, ok or not.
#
# A backup takes as long as it takes, so it runs in a process of its own
# (`analytics-agent.ps1 backup-worker`), which the agent's loop starts and
# restarts; the firewall never waits on it. A restore only when
# "allow_restore" is true in the config; before it, what is being replaced is
# backed up, alerts are paused, and if a part fails or a service that ran
# before stops, everything is put back.

$script:ResticVersion = '0.19.1'
# From the release's SHA256SUMS, whose signature by restic's release key
# (CF8F18F2844575973F79D4E191A6868BD3F7A907) was checked when this was pinned.
$script:ResticSha256 = @{
    amd64 = 'da948ad707ed690426473aaba2046cd61f8f90f6f0e7dab6be0d5796531de67d'
    '386' = '24147168e7988af20e4957d06ab7a9ba73792755150ce1ff270ad586c37fd160'
}
$script:BackupTag = 'sitegoose'
$script:BackupKinds = @('sqlserver', 'mysql', 'postgresql', 'mongodb')
$script:BackupTick = 30
$script:BackupReportEvery = 3600
$script:BackupRequestsEvery = 60
$script:BackupTimeout = 12 * 3600
$script:BackupQuick = 120
$script:BackupRunsSent = 60
$script:BackupPart = 64MB
$script:BackupLinkSeconds = 3600
$script:BackupDownloadKeep = 86400
$script:BackupAsideKeep = 7 * 86400
$script:BackupHealthWait = 60
$script:RestorePauseMinutes = 120
$script:BackupWorker = $null
$script:BackupWorkerAt = 0.0
$script:RunIdPattern = '^\d{8}T\d{6}Z$'
$script:DbNamePattern = '^[A-Za-z0-9_$.-]{1,128}$'
$script:MysqlSystem = @('information_schema', 'performance_schema', 'sys', 'mysql')
# Never swapped whole by a restore: putting one of these back by renaming
# would take Windows down with it. `restore ... -Into` copies them out instead.
$script:SystemFolderPattern = '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData|Users|inetpub)?$'
# "nightly", "weekly" (on "weekday") or "off" (only when asked). The dashboard's
# choice, handed over with the requests, wins over the config's.
$script:BackupSchedules = @('nightly', 'weekly', 'off')
$script:BackupWeekdays = @('sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat')  # [DayOfWeek]'s order
$script:BackupPruneEvery = 6.5 * 86400  # prune and check once a week, whatever the schedule
$script:BackupDiskSpare = 512MB
$script:BackupTimeFormat = '^([01]\d|2[0-3]):[0-5]\d$'

function Get-BackupDatabases {
    # Each { kind; target; label; only }. target "local" (SQL Server's default
    # instance), an instance (".\SQLEXPRESS", "host,1433") or a connection string.
    param($Entries)
    $out = New-Object System.Collections.ArrayList
    foreach ($e in @(Get-EntryList $Entries)) {
        if (-not (Test-IsMap $e)) { continue }
        if ($null -eq (Get-Prop $e 'mysql') -and $null -ne (Get-Prop $e 'mariadb')) { $kind = 'mysql'; $target = [string](Get-Prop $e 'mariadb') }
        else {
            $kind = $script:BackupKinds | Where-Object { (Get-Prop $e $_) -is [string] } | Select-Object -First 1
            if (-not $kind) { Write-AgentLog "backups: a database needs one of $($script:BackupKinds -join ', '), skipped"; continue }
            $target = ([string](Get-Prop $e $kind)).Trim()
        }
        $only = @(@(Get-EntryList (Get-Prop $e 'only')) | Where-Object { $_ -is [string] -and $_ -match $script:DbNamePattern })
        if ($kind -eq 'sqlserver') {
            if ($target -match '^sqlserver://') {
                $u = [Uri]$target
                if (@('localhost', '127.0.0.1', '::1', '.', $env:COMPUTERNAME) -notcontains $u.Host) {
                    Write-AgentLog "backups: SQL Server writes a backup on its own disk, so the agent backs up only the one on this server, not $($u.Host): skipped"
                    continue
                }
                $label = 'sqlserver ' + $u.Host
            } elseif ($target -eq 'local' -or $target -match '^[A-Za-z0-9_.\\,-]{1,128}$') {
                $label = 'sqlserver ' + $target
            } else { Write-AgentLog 'backups: sqlserver needs "local", an instance or sqlserver://user:password@host, skipped'; continue }
        } else {
            $schemes = @{ mysql = '^(mysql|mariadb)://'; postgresql = '^postgres(ql)?://'; mongodb = '^mongodb(\+srv)?://' }
            if ($target -notmatch $schemes[$kind]) {
                Write-AgentLog "backups: on Windows $kind needs a connection string (it has no local login to borrow), skipped"
                continue
            }
            $u = [Uri]($target -replace '^mongodb\+srv://', 'mongodb://')
            $label = $kind + ' ' + $u.Host
            if ($u.Port -gt 0) { $label += ':' + $u.Port }
        }
        [void]$out.Add(@{ kind = $kind; target = $target; label = $label; only = $only })
    }
    return @($out.ToArray() | Select-Object -First 20)
}

function Get-BackupConfig {
    # The "backups" section filled in, or $null when it names no repository.
    param($Config)
    $raw = $Config['backups']
    if (-not (Test-IsMap $raw)) { return $null }
    $repo = [string](Get-Prop $raw 'repository' '')
    if (-not $repo.Trim()) { return $null }
    $dir = Split-Path -Parent ([string]$Config.config_path)
    $b = @{ repository = $repo.Trim(); allow_restore = ((Get-Prop $raw 'allow_restore') -eq $true); region = [string](Get-Prop $raw 'region' '') }
    $b.password_file = [string](Get-Prop $raw 'password_file' '')
    if (-not $b.password_file) { $b.password_file = Join-Path $dir 'backup-password.txt' }
    $b.env = @{}
    $envMap = Get-Prop $raw 'env'
    if (Test-IsMap $envMap) {
        $pairs = $envMap.PSObject.Properties | ForEach-Object { @{ Name = $_.Name; Value = $_.Value } }
        if ($envMap -is [System.Collections.IDictionary]) { $pairs = $envMap.Keys | ForEach-Object { @{ Name = [string]$_; Value = $envMap[$_] } } }
        foreach ($p in @($pairs)) {
            if ($p.Name -cmatch '^(AWS_[A-Z_]+|B2_[A-Z_]+|AZURE_[A-Z_]+|GOOGLE_[A-Z_]+|RESTIC_REST_[A-Z_]+)$') { $b.env[$p.Name] = [string]$p.Value }
        }
    }
    $b.at = [string](Get-Prop $raw 'at' '03:00')
    if ($b.at -notmatch $script:BackupTimeFormat) { $b.at = '03:00' }
    $b.schedule = ([string](Get-Prop $raw 'schedule' 'nightly')).ToLowerInvariant()
    if ($script:BackupSchedules -notcontains $b.schedule) { $b.schedule = 'nightly' }
    $day = ([string](Get-Prop $raw 'weekday' 'sun')).ToLowerInvariant()
    if ($day.Length -gt 3) { $day = $day.Substring(0, 3) }
    $b.weekday = $(if ($script:BackupWeekdays -contains $day) { $day } else { 'sun' })
    $keep = Get-Prop $raw 'keep'
    $b.keep = [ordered]@{ daily = 14; weekly = 8; monthly = 12 }
    foreach ($k in @('daily', 'weekly', 'monthly')) {
        $n = Get-WholeNumber (Get-Prop $keep $k) 0 1000
        if ($null -ne $n) { $b.keep[$k] = [int]$n }
    }
    $b.exclude = @(@(Get-EntryList (Get-Prop $raw 'exclude' @('node_modules', '*.tmp', 'App_Data\Logs'))) | Where-Object { $_ -is [string] -and $_ })
    $b.databases = @(Get-BackupDatabases (Get-Prop $raw 'databases'))
    $b.folders = @(@(Get-EntryList (Get-Prop $raw 'folders')) | Where-Object { $_ -is [string] -and $_ -match '^[A-Za-z]:\\' } |
        ForEach-Object { $_.TrimEnd('\') } | Select-Object -Unique)
    $b.state_file = Join-Path $Config.state_dir 'backups.json'
    $b.temp = Join-Path $Config.state_dir 'backup-temp'
    # A download is made here first: a drive with room for it. A folder of
    # ours inside it, since what's left in it after a day is deleted.
    $tempDir = [string](Get-Prop $raw 'temp_dir' '')
    if ($tempDir -match '^[A-Za-z]:\\') { $b.temp = [IO.Path]::Combine($tempDir, 'sitegoose-backup-temp') }
    $b.cache = Join-Path $Config.state_dir 'restic-cache'
    $b.config = $Config
    return $b
}

function Join-ProcessArguments {
    # One command line Windows splits back into exactly these arguments
    # (backslashes before a quote doubled, as CommandLineToArgvW reads them).
    param([string[]]$Arguments)
    $parts = foreach ($a in @($Arguments)) {
        if ($a -and $a -notmatch '[\s"]') { $a; continue }
        $s = '"'
        $slashes = 0
        foreach ($ch in $a.ToCharArray()) {
            if ($ch -eq '\') { $slashes++; continue }
            if ($ch -eq '"') { $s += ('\' * ($slashes * 2 + 1)) + '"' } else { $s += ('\' * $slashes) + $ch }
            $slashes = 0
        }
        $s + ('\' * ($slashes * 2)) + '"'
    }
    return ($parts -join ' ')
}

function Get-ErrTail {
    param([string]$Text)
    $lines = @(([string]$Text) -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 3)
    $t = ($lines -join ' / ').Trim()
    if ($t.Length -gt 300) { $t = $t.Substring(0, 300) }
    return $t
}

function Invoke-BackupProcess {
    # @{ Code; Out; Err }; Code $null when it couldn't start or ran past
    # $Seconds (then it and what it started are killed). Stdin from a file,
    # stdout to a file when asked: dumps are far bigger than memory. A $null
    # in $Env takes that variable out.
    param([string]$File, [string[]]$Arguments = @(), [hashtable]$Env = @{}, [string]$StdinFile = '', [string]$StdoutFile = '', [int]$Seconds = $script:BackupQuick,
        [IO.Stream]$StdoutStream = $null)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = Join-ProcessArguments $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = [bool]$StdinFile
    $psi.CreateNoWindow = $true
    foreach ($k in $Env.Keys) {
        if ($null -eq $Env[$k]) { [void]$psi.EnvironmentVariables.Remove($k) } else { $psi.EnvironmentVariables[$k] = [string]$Env[$k] }
    }
    try { $proc = [System.Diagnostics.Process]::Start($psi) } catch { return @{ Code = $null; Out = ''; Err = $_.Exception.Message } }
    $err = $proc.StandardError.ReadToEndAsync()
    $sink = $null; $copy = $null; $out = $null
    try {
        if ($StdoutFile) { $sink = [IO.File]::Create($StdoutFile); $copy = $proc.StandardOutput.BaseStream.CopyToAsync($sink) }
        elseif ($StdoutStream) { $copy = $proc.StandardOutput.BaseStream.CopyToAsync($StdoutStream, 1MB) }
        else { $out = $proc.StandardOutput.ReadToEndAsync() }
        if ($StdinFile) {
            $in = [IO.File]::OpenRead($StdinFile)
            try { $in.CopyTo($proc.StandardInput.BaseStream) } catch { } finally { $in.Dispose(); try { $proc.StandardInput.Close() } catch { } }
        }
        $finished = $true
        if ($StdoutStream) {
            # Where it goes can refuse more (a download over its size): then it
            # is stopped, or it would wait on a full pipe for ever.
            try { $finished = $copy.Wait($Seconds * 1000) }
            catch { Stop-ProcessTree $proc; throw $_.Exception.GetBaseException() }
        }
        if (-not $finished -or -not $proc.WaitForExit($Seconds * 1000)) {
            Stop-ProcessTree $proc
            return @{ Code = $null; Out = ''; Err = "took longer than $([int]($Seconds / 60)) minutes, stopped" }
        }
        $proc.WaitForExit()
        if ($copy) { $copy.Wait() }
    } finally { if ($sink) { $sink.Dispose() } }
    $text = ''
    if ($out) { $text = $out.Result }
    return @{ Code = $proc.ExitCode; Out = $text; Err = (Get-ErrTail $err.Result) }
}

function Stop-ProcessTree {
    param($Process)
    [void](Invoke-External 'taskkill.exe' @('/T', '/F', '/PID', [string]$Process.Id) 30)
    try { if (-not $Process.HasExited) { $Process.Kill() } } catch { }
}

function Get-BackupUserAgent {
    return 'analytics-platform-agent-windows/' + $script:AgentVersion + ' (backups)'
}

function Get-ResticPath {
    $own = ''
    if ($env:ProgramData) { $own = Join-Path $env:ProgramData 'AnalyticsAgent\restic.exe' }
    if ($own -and (Test-Path -LiteralPath $own)) { return $own }
    $found = Get-Command restic -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.Source }
    if ($own) { return $own }
    return 'restic'
}

function Invoke-Restic {
    param($Bc, [string[]]$Arguments, [int]$Seconds = $script:BackupQuick, [hashtable]$Env = @{}, [string]$StdinFile = '', [string]$StdoutFile = '', [IO.Stream]$StdoutStream = $null)
    $all = @{}
    foreach ($k in $Bc.env.Keys) { $all[$k] = $Bc.env[$k] }
    $all.RESTIC_REPOSITORY = $Bc.repository
    $all.RESTIC_PASSWORD_FILE = $Bc.password_file
    # Only the file: one in the environment would win over it.
    $all.RESTIC_PASSWORD = $null
    $all.RESTIC_PASSWORD_COMMAND = $null
    $all.RESTIC_CACHE_DIR = $Bc.cache
    $all.RESTIC_PROGRESS_FPS = '0.0167'
    foreach ($k in $Env.Keys) { $all[$k] = $Env[$k] }
    return Invoke-BackupProcess (Get-ResticPath) $Arguments $all $StdinFile $StdoutFile $Seconds $StdoutStream
}

function Get-ResticVersion {
    param($Bc)
    $r = Invoke-Restic $Bc @('version')
    $m = [regex]::Match([string]$r.Out, 'restic (\d+)\.(\d+)\.(\d+)')
    if ($r.Code -ne 0 -or -not $m.Success) { return $null }
    return [version]('{0}.{1}.{2}' -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value)
}

function Get-BackupSetupProblem {
    # @(code, text) of what stops backups running, or $null.
    param($Bc)
    $v = Get-ResticVersion $Bc
    if (-not $v) { return @('restic_missing', "restic isn't installed: run analytics-agent.ps1 backup-setup") }
    if ($v -lt [version]'0.17.0') { return @('restic_old', "restic $v is too old (0.17 or later): run analytics-agent.ps1 backup-setup") }
    if (-not (Test-Path -LiteralPath $Bc.password_file)) { return @('no_password', "no password file at $($Bc.password_file): run analytics-agent.ps1 backup-setup") }
    $r = Invoke-Restic $Bc @('cat', 'config')
    if ($r.Code -eq 10) {
        $r = Invoke-Restic $Bc @('init')
        if ($r.Code -eq 0) { Write-AgentLog ('backups: new repository made at ' + (Get-ShownRepository $Bc.repository)); return $null }
    }
    if ($r.Code -eq 12) { return @('wrong_password', "the password file doesn't open this repository") }
    if ($r.Code -ne 0) { return @('repository', "can't reach the repository: $($r.Err)") }
    return $null
}

function Get-ShownRepository {
    param([string]$Repository)
    $t = $Repository -replace '//[^/@\s]*:[^/@\s]*@', '//'
    $t = $t -replace '^(sftp:)[^@:/]*:[^@]*@', '$1'
    if ($t.Length -gt 200) { $t = $t.Substring(0, 200) }
    return $t
}

function Read-BackupState {
    param($Bc)
    $s = @{}
    if (Test-Path -LiteralPath $Bc.state_file) {
        try {
            $j = ConvertFrom-Json ([IO.File]::ReadAllText($Bc.state_file))
            foreach ($p in $j.PSObject.Properties) { $s[$p.Name] = $p.Value }
        } catch { }
    }
    foreach ($k in 'downloads', 'aside') { $s[$k] = @(Get-EntryList $s[$k]) }
    return $s
}

function Save-BackupState {
    param($Bc, $State)
    Write-TextFile $Bc.state_file (ConvertTo-Json -InputObject $State -Depth 8 -Compress)
}

function ConvertTo-ResticPath {
    # C:\inetpub\wwwroot -> /C/inetpub/wwwroot, how restic names it inside a snapshot.
    param([string]$Folder)
    if ($Folder -match '^([A-Za-z]):\\?(.*)$') { return ('/' + $Matches[1].ToUpperInvariant() + '/' + ($Matches[2] -replace '\\', '/')).TrimEnd('/') }
    return $Folder
}

# -- The databases' own tools --

function Find-BackupTool {
    # The tool's path: on PATH, else where its installer puts it (newest version first).
    param([string[]]$Names, [string[]]$Globs = @())
    foreach ($n in $Names) {
        $c = Get-Command $n -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { return $c.Source }
    }
    foreach ($g in $Globs) {
        $hit = @(Get-ChildItem -Path $g -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1)
        if ($hit.Count) { return $hit[0].FullName }
    }
    return $null
}

function Get-ToolFor {
    param([string]$Kind, [string]$Use)
    $pf = $env:ProgramFiles
    switch ("$Kind/$Use") {
        'sqlserver/dump' { return Find-BackupTool @('sqlcmd.exe') @("$pf\Microsoft SQL Server\Client SDK\ODBC\*\Tools\Binn\SQLCMD.EXE", "$pf\Microsoft SQL Server\*\Tools\Binn\SQLCMD.EXE") }
        'mysql/dump' { return Find-BackupTool @('mariadb-dump.exe', 'mysqldump.exe') @("$pf\MariaDB *\bin\mariadb-dump.exe", "$pf\MySQL\MySQL Server *\bin\mysqldump.exe") }
        'mysql/client' { return Find-BackupTool @('mariadb.exe', 'mysql.exe') @("$pf\MariaDB *\bin\mariadb.exe", "$pf\MySQL\MySQL Server *\bin\mysql.exe") }
        'postgresql/dump' { return Find-BackupTool @('pg_dump.exe') @("$pf\PostgreSQL\*\bin\pg_dump.exe") }
        'postgresql/restore' { return Find-BackupTool @('pg_restore.exe') @("$pf\PostgreSQL\*\bin\pg_restore.exe") }
        'mongodb/dump' { return Find-BackupTool @('mongodump.exe') @("$pf\MongoDB\Tools\*\bin\mongodump.exe") }
        'mongodb/restore' { return Find-BackupTool @('mongorestore.exe') @("$pf\MongoDB\Tools\*\bin\mongorestore.exe") }
    }
    return $null
}

function New-SecretFile {
    # A file only SYSTEM and Administrators can read (it inherits the state
    # folder's ACL), for a password no command line may show.
    param($Bc, [string]$Text, [string]$Ending)
    if (-not (Test-Path -LiteralPath $Bc.temp)) { New-Item -ItemType Directory -Path $Bc.temp -Force | Out-Null }
    $path = Join-Path $Bc.temp ('secret-' + [guid]::NewGuid().ToString('N') + $Ending)
    [IO.File]::WriteAllText($path, $Text, (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

function Split-UserInfo {
    # user and password from a URL, each unescaped on its own (a password may hold ':').
    param([Uri]$Url)
    $info = $Url.UserInfo
    $i = $info.IndexOf(':')
    if ($i -lt 0) { return @([Uri]::UnescapeDataString($info), '') }
    return @([Uri]::UnescapeDataString($info.Substring(0, $i)), [Uri]::UnescapeDataString($info.Substring($i + 1)))
}

function Get-DbSession {
    # How to run one database's tools: @{ Env; Args (connection options); Files
    # (secret files to delete) }. Passwords go in the environment or a file.
    param($Bc, $Db)
    $s = @{ Env = @{}; Args = @(); Files = @() }
    if ($Db.kind -eq 'sqlserver') {
        if ($Db.target -match '^sqlserver://') {
            $u = [Uri]$Db.target
            $server = $u.Host
            if ($u.Port -gt 0) { $server += ',' + $u.Port }
            $user, $pass = Split-UserInfo $u
            $s.Args = @('-S', $server, '-U', $user)
            $s.Env.SQLCMDPASSWORD = $pass
        } else {
            $server = $Db.target
            if ($server -eq 'local') { $server = '.' }
            $s.Args = @('-S', $server, '-E')
        }
        return $s
    }
    $u = [Uri]($Db.target -replace '^mongodb\+srv://', 'mongodb://')
    $user, $pass = Split-UserInfo $u
    if ($Db.kind -eq 'mysql') {
        $port = 3306
        if ($u.Port -gt 0) { $port = $u.Port }
        $f = New-SecretFile $Bc ("[client]`nhost={0}`nport={1}`nuser={2}`npassword=`"{3}`"`n" -f $u.Host, $port, $user, ($pass -replace '\\', '\\' -replace '"', '\"')) '.cnf'
        $s.Files = @($f)
        $s.Args = @("--defaults-extra-file=$f")
    } elseif ($Db.kind -eq 'postgresql') {
        $port = 5432
        if ($u.Port -gt 0) { $port = $u.Port }
        $s.Env = @{ PGHOST = $u.Host; PGPORT = [string]$port; PGUSER = $user; PGPASSWORD = $pass; PGCONNECT_TIMEOUT = '10' }
    } else {
        $f = New-SecretFile $Bc ('uri: ' + (ConvertTo-Json $Db.target) + "`n") '.yaml'
        $s.Files = @($f)
        $s.Args = @("--config=$f")
    }
    return $s
}

function Close-DbSession {
    param($Session)
    foreach ($f in @($Session.Files)) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
}

function Get-SqlName {
    param([string]$Name)
    return '[' + ($Name -replace '\]', ']]') + ']'
}

function Invoke-SqlCmd {
    param($Db, $Session, [string]$Sql, [int]$Seconds = $script:BackupQuick)
    $tool = Get-ToolFor 'sqlserver' 'dump'
    if (-not $tool) { return @{ Code = $null; Out = ''; Err = 'sqlcmd.exe not found (it comes with SQL Server''s tools)' } }
    return Invoke-BackupProcess $tool (@($Session.Args) + @('-b', '-h', '-1', '-W', '-Q', ('SET NOCOUNT ON; ' + $Sql))) $Session.Env '' '' $Seconds
}

function Get-DbNames {
    # The databases in it to dump; throws saying why not.
    param($Bc, $Db, $Session)
    if ($Db.kind -eq 'mongodb') { return @('all') }
    if ($Db.kind -eq 'postgresql') {
        $name = [Uri]::UnescapeDataString(([Uri]$Db.target).AbsolutePath.Trim('/'))
        if (-not $name) { $name = 'postgres' }
        return @($name)
    }
    if ($Db.kind -eq 'sqlserver') {
        $r = Invoke-SqlCmd $Db $Session 'SELECT name FROM sys.databases WHERE database_id > 4 AND state = 0 ORDER BY name'
    } else {
        $tool = Get-ToolFor 'mysql' 'client'
        if (-not $tool) { throw 'mysql.exe not found' }
        $r = Invoke-BackupProcess $tool (@($Session.Args) + @('--batch', '--skip-column-names', '-e', 'SHOW DATABASES')) $Session.Env
    }
    if ($r.Code -ne 0) { throw "couldn't list its databases: $($r.Err)" }
    $names = @(([string]$r.Out) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match $script:DbNamePattern })
    if ($Db.kind -eq 'mysql') { $names = @($names | Where-Object { $script:MysqlSystem -notcontains $_ }) }
    if (@($Db.only).Count) { $names = @($names | Where-Object { $Db.only -contains $_ }) }
    return $names
}

function Get-SqlBackupFolder {
    # SQL Server's own backup folder: the one place its service account can
    # always write and read (2019 and later say where, older ones in the
    # registry). The state folder only if neither does, which it can't write.
    param($Bc, $Db, $Session)
    $r = Invoke-SqlCmd $Db $Session ("DECLARE @p nvarchar(4000) = CAST(SERVERPROPERTY('InstanceDefaultBackupPath') AS nvarchar(4000)); " +
        "IF @p IS NULL EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'BackupDirectory', @p OUTPUT; SELECT @p")
    $dir = ([string]$r.Out).Trim()
    if ($r.Code -eq 0 -and $dir -and $dir -ne 'NULL' -and (Test-Path -LiteralPath $dir)) { return $dir }
    return $Bc.temp
}

function Get-ItemPrefix {
    param($Db)
    if ($Db.kind -eq 'sqlserver' -and $Db.target -notmatch '^sqlserver://') { $where = $Db.target }
    else { $where = ([Uri]($Db.target -replace '^mongodb\+srv://', 'mongodb://')).Host }
    return $Db.kind + '/' + ($where -replace '[^A-Za-z0-9_.-]', '_')
}

function Save-DbDump {
    # Dumps one database to $Path with its own tool; @{ Code; Err }.
    param($Bc, $Db, $Session, [string]$Name, [string]$Path)
    switch ($Db.kind) {
        'sqlserver' {
            # COPY_ONLY: the owner's own backup chain (differentials, logs) stays as it was.
            return Invoke-SqlCmd $Db $Session ("BACKUP DATABASE {0} TO DISK = N'{1}' WITH COPY_ONLY, INIT, FORMAT, CHECKSUM" -f (Get-SqlName $Name), ($Path -replace "'", "''")) $script:BackupTimeout
        }
        'mysql' {
            $tool = Get-ToolFor 'mysql' 'dump'
            if (-not $tool) { return @{ Code = $null; Err = 'mysqldump.exe not found' } }
            return Invoke-BackupProcess $tool (@($Session.Args) + @('--single-transaction', '--quick', '--routines', '--triggers', '--events',
                '--hex-blob', '--add-drop-database', "--result-file=$Path", '--databases', $Name)) $Session.Env '' '' $script:BackupTimeout
        }
        'postgresql' {
            $tool = Get-ToolFor 'postgresql' 'dump'
            if (-not $tool) { return @{ Code = $null; Err = 'pg_dump.exe not found' } }
            return Invoke-BackupProcess $tool @('-Fc', '-f', $Path, '-d', $Name) $Session.Env '' '' $script:BackupTimeout
        }
        'mongodb' {
            $tool = Get-ToolFor 'mongodb' 'dump'
            if (-not $tool) { return @{ Code = $null; Err = 'mongodump.exe not found' } }
            return Invoke-BackupProcess $tool (@("--archive=$Path", '--gzip', '--quiet') + @($Session.Args)) $Session.Env '' '' $script:BackupTimeout
        }
    }
}

function Get-DumpEnding {
    param([string]$Kind)
    return @{ sqlserver = '.bak'; mysql = '.sql'; postgresql = '.pgdump'; mongodb = '.archive.gz' }[$Kind]
}

function Get-ResticSummary {
    param([string]$Out)
    $lines = @(([string]$Out) -split "`r?`n")
    for ($i = $lines.Count - 1; $i -ge 0; $i--) {
        try { $j = ConvertFrom-Json $lines[$i] } catch { continue }
        if ($j.message_type -eq 'summary') { return $j }
    }
    return $null
}

function New-BackupItem {
    param([string]$Kind, [string]$Name, $Result, [double]$Began)
    $s = $null
    $ok = $Result.Code -eq 0 -or ($Kind -eq 'folder' -and $Result.Code -eq 3)
    if ($ok) { $s = Get-ResticSummary $Result.Out }
    $err = ''
    if ($Result.Code -eq 3) { $err = "some files couldn't be read: " + $Result.Err }
    elseif (-not $ok) { $err = $Result.Err; if (-not $err) { $err = "exit $($Result.Code)" } }
    $item = [ordered]@{ kind = $Kind; name = $Name; ok = $ok; seconds = [int]((Get-EpochNow) - $Began); bytes = $null; added = $null; error = $err }
    if ($s) { $item.bytes = [long]$s.total_bytes_processed; $item.added = [long]$s.data_added }
    return $item
}

function Backup-Database {
    param($Bc, $Db, [string[]]$Tags, $Only)
    $session = Get-DbSession $Bc $Db
    $items = New-Object System.Collections.ArrayList
    try {
        try { $names = @(Get-DbNames $Bc $Db $session) } catch { return @([ordered]@{ kind = 'database'; name = $Db.label; ok = $false; error = $_.Exception.Message }) }
        $folder = $Bc.temp
        if ($Db.kind -eq 'sqlserver') { $folder = Get-SqlBackupFolder $Bc $Db $session }
        if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        foreach ($n in $names) {
            $name = (Get-ItemPrefix $Db) + '/' + $n + (Get-DumpEnding $Db.kind)
            if ($null -ne $Only -and $Only -notcontains $name) { continue }
            $began = Get-EpochNow
            $path = Join-Path $folder ('sitegoose-' + [guid]::NewGuid().ToString('N') + (Get-DumpEnding $Db.kind))
            try {
                $d = Save-DbDump $Bc $Db $session $n $path
                if ($d.Code -ne 0) {
                    $e = $d.Err
                    if (-not $e) { $e = "exit $($d.Code)" }
                    [void]$items.Add([ordered]@{ kind = 'database'; name = $name; ok = $false; seconds = [int]((Get-EpochNow) - $began); error = $e })
                    continue
                }
                $r = Invoke-Restic $Bc (@('backup', '--json', '--host', (Get-ServerName), '--stdin', '--stdin-filename', $name) + $Tags + @('--tag', 'kind:database')) $script:BackupTimeout @{} $path
                [void]$items.Add((New-BackupItem 'database' $name $r $began))
            } finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        }
    } finally { Close-DbSession $session }
    return @($items.ToArray())
}

function Backup-Folder {
    param($Bc, [string]$Folder, [string[]]$Tags)
    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) {
        return [ordered]@{ kind = 'folder'; name = $Folder; ok = $false; missing = $true; error = "the folder doesn't exist" }
    }
    $began = Get-EpochNow
    $args2 = @('backup', '--json', '--host', (Get-ServerName)) + $Tags + @('--tag', 'kind:folder')
    # A shadow copy: files IIS or SQL Server hold open are read whole. Windows only.
    if ($env:OS -eq 'Windows_NT') { $args2 += '--use-fs-snapshot' }
    foreach ($x in $Bc.exclude) { $args2 += @('--exclude', $x) }
    $r = Invoke-Restic $Bc ($args2 + @('--', $Folder)) $script:BackupTimeout
    return New-BackupItem 'folder' $Folder $r $began
}

function Invoke-BackupRun {
    # One run: every database's dumps and every folder (or the names in
    # $Only). The run's record, kept as the last unless it's a safety copy.
    param($Bc, [string]$Trigger = 'nightly', $Only = $null)
    $state = Read-BackupState $Bc
    $run = [DateTime]::UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    $record = [ordered]@{ run = $run; trigger = $Trigger; started_at = (ConvertTo-IsoTime (Get-EpochNow)); items = @(); error = ''; state = 'failed' }
    $problem = Get-BackupSetupProblem $Bc
    if ($problem) {
        $record.error = $problem[1]
        $record.setup = $problem[0]
    } else {
        $tags = @('--tag', $script:BackupTag, '--tag', "run:$run", '--tag', "trigger:$Trigger")
        if ($Trigger -eq 'before-restore') { $tags += @('--tag', 'before-restore') }
        $items = New-Object System.Collections.ArrayList
        foreach ($db in $Bc.databases) { foreach ($i in @(Backup-Database $Bc $db $tags $Only)) { [void]$items.Add($i) } }
        foreach ($f in $Bc.folders) { if ($null -eq $Only -or $Only -contains $f) { [void]$items.Add((Backup-Folder $Bc $f $tags)) } }
        $record.items = @($items.ToArray())
        $failed = @($record.items | Where-Object { -not $_.ok })
        if ($record.items.Count -eq 0) { $record.error = 'nothing to back up: list databases or folders under "backups"' }
        elseif ($failed.Count -eq 0) { $record.state = 'ok' }
        elseif ($failed.Count -lt $record.items.Count) { $record.state = 'partial' }
        if ($Trigger -eq 'nightly' -and $record.items.Count) {
            $forget = @('forget', '--tag', $script:BackupTag, '--keep-daily', [string]$Bc.keep.daily, '--keep-weekly', [string]$Bc.keep.weekly, '--keep-monthly', [string]$Bc.keep.monthly)
            # Pruning rewrites the storage, so once a week, with the check.
            $weekly = (Get-EpochNow) - [double](Get-Prop $state 'pruned_at' 0) -ge $script:BackupPruneEvery
            if ($weekly) { $forget += '--prune' }
            $f = Invoke-Restic $Bc $forget $script:BackupTimeout
            if ($f.Code -ne 0) { $record.forget = $f.Err }
            if ($weekly) {
                $c = Invoke-Restic $Bc @('check', '--read-data-subset=5%') $script:BackupTimeout
                $state.check = [ordered]@{ at = (ConvertTo-IsoTime (Get-EpochNow)); ok = $c.Code -eq 0; error = $(if ($c.Code -eq 0) { '' } else { $c.Err }) }
                $state.pruned_at = Get-EpochNow
            }
        }
    }
    $record.finished_at = ConvertTo-IsoTime (Get-EpochNow)
    if ($Trigger -ne 'before-restore') { $state.last = $record }
    if ($Trigger -eq 'nightly') { $state.last_day = (Get-Date).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
    Save-BackupState $Bc $state
    $why = ''
    if ($record.error) { $why = ', ' + $record.error }
    Write-AgentLog ('backups: {0} {1}, {2} part(s){3}' -f $Trigger, $record.state, @($record.items).Count, $why)
    return $record
}

function Get-BackupRuns {
    # restic's snapshots of ours as runs, newest first: @{ run; at; trigger; items = @{ name; kind; snapshot; id; bytes } }.
    param($Bc)
    $r = Invoke-Restic $Bc @('snapshots', '--json', '--tag', $script:BackupTag)
    if ($r.Code -ne 0) { throw "couldn't list the backups: $($r.Err)" }
    $runs = @{}
    foreach ($snap in @(ConvertFrom-Json ([string]$r.Out))) {
        $tags = @($snap.tags)
        $run = @($tags | Where-Object { $_ -like 'run:*' } | ForEach-Object { $_.Substring(4) } | Where-Object { $_ -match $script:RunIdPattern }) | Select-Object -First 1
        if (-not $run) { continue }
        if (-not $runs.ContainsKey($run)) {
            $trigger = @($tags | Where-Object { $_ -match '^trigger:(nightly|manual|before-restore)$' } | ForEach-Object { $_.Substring(8) }) | Select-Object -First 1
            if (-not $trigger -and $tags -contains 'before-restore') { $trigger = 'before-restore' }
            if (-not $trigger) { $trigger = 'nightly' }
            $runs[$run] = [ordered]@{ run = $run; at = ([string]$snap.time).Substring(0, 19) + 'Z'; trigger = $trigger; items = New-Object System.Collections.ArrayList }
        }
        $kind = 'folder'
        if ($tags -contains 'kind:database') { $kind = 'database' }
        $path = [string]@($snap.paths)[0]
        $name = $path
        if ($kind -eq 'database') {
            # The name given to --stdin-filename, however restic made it a path.
            $m = [regex]::Match(($path -replace '\\', '/'), '(?:^|/)((?:sqlserver|mysql|postgresql|mongodb)/.+)$')
            if (-not $m.Success) { continue }
            $name = $m.Groups[1].Value
        }
        $bytes = $null
        if ($snap.summary) { $bytes = [long]$snap.summary.total_bytes_processed }
        [void]$runs[$run].items.Add([ordered]@{ name = $name; kind = $kind; snapshot = [string]$snap.short_id; id = [string]$snap.id; bytes = $bytes; path = $path })
    }
    return @($runs.Values | Sort-Object { $_.run } -Descending)
}

function Find-BackupRun {
    param($Bc, [string]$Run, [string[]]$Names = @())
    if ($Run -notmatch $script:RunIdPattern) { throw 'no such backup' }
    $found = @(Get-BackupRuns $Bc | Where-Object { $_.run -eq $Run }) | Select-Object -First 1
    if (-not $found) { throw "that backup isn't in the repository any more" }
    $items = @($found.items | Where-Object { $Names.Count -eq 0 -or $Names -contains $_.name })
    $missing = @($Names | Where-Object { @($items | ForEach-Object { $_.name }) -notcontains $_ })
    if ($missing.Count) { throw "that backup doesn't have $($missing -join ', ')" }
    return @{ Run = $found; Items = $items }
}

function Send-BackupReport {
    param($Bc)
    $problem = Get-BackupSetupProblem $Bc
    $runs = @()
    $repoBytes = $null
    if (-not $problem) {
        try { $runs = @(Get-BackupRuns $Bc) } catch { $problem = @('repository', $_.Exception.Message) }
        $st = Invoke-Restic $Bc @('stats', '--json', '--mode', 'raw-data')
        try { if ($st.Code -eq 0) { $repoBytes = [long](ConvertFrom-Json $st.Out).total_size } } catch { }
    }
    $state = Read-BackupState $Bc
    $plan = Get-BackupSchedule $Bc $state
    $sent = @($runs | Select-Object -First $script:BackupRunsSent | ForEach-Object {
            [ordered]@{ run = $_.run; at = $_.at; trigger = $_.trigger; items = @($_.items | ForEach-Object { [ordered]@{ name = $_.name; kind = $_.kind; snapshot = $_.snapshot; bytes = $_.bytes } }) }
        })
    $offset = [TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now)
    $sign = '+'
    if ($offset.Ticks -lt 0) { $sign = '-' }
    $version = Get-ResticVersion $Bc
    $body = [ordered]@{
        v = $script:ProtocolVersion; site_id = $Bc.config.site_id; host = (Get-ServerName); client = ('windows-agent/' + $script:AgentVersion)
        restic = $(if ($version) { [string]$version } else { $null })
        setup = $(if ($problem) { $problem[0] } else { $null }); setup_detail = $(if ($problem) { $problem[1] } else { '' })
        settings = [ordered]@{
            repository = (Get-ShownRepository $Bc.repository); at = $plan.at; schedule = $plan.schedule; weekday = $plan.weekday; schedule_from = $plan.from
            # A folder on this server: gone with it, so the page says so.
            local = $Bc.repository -match '^([A-Za-z]:\\|local:)'
            timezone = ('{0}{1:00}{2:00}' -f $sign, [math]::Abs($offset.Hours), [math]::Abs($offset.Minutes))
            keep = $Bc.keep; allow_restore = $Bc.allow_restore; can_download = $null -ne (Get-S3Location $Bc)
            folders = @($Bc.folders); databases = @($Bc.databases | ForEach-Object { $_.label }); skipped = @()
        }
        last = $state.last; check = $state.check; runs = $sent; repo_bytes = $repoBytes
    }
    $res = Invoke-Collector $Bc.config 'POST' '/events/backups' $body @{} (Get-BackupUserAgent)
    if ($res.Status -ne 200 -and $res.Status -ne 202) { Write-AgentLog "collector answered $($res.Status) to the backups report"; return $false }
    return $true
}

# -- S3, for a download link --

function Get-S3Location {
    param($Bc)
    if ($Bc.repository -notmatch '^s3:') { return $null }
    $rest = $Bc.repository.Substring(3)
    if ($rest -notmatch '^https?://') { $rest = 'https://' + $rest }
    try { $u = [Uri]$rest } catch { return $null }
    $path = $u.AbsolutePath.Trim('/').Split('/', 2)
    if (-not $u.Host -or -not $path[0]) { return $null }
    $region = $Bc.region
    if (-not $region) {
        $region = 'us-east-1'
        if ($u.Host -match '^([a-z0-9-]+)\.your-objectstorage\.com$') { $region = $Matches[1] }
        elseif ($u.Host -match '^s3[.-]([a-z0-9-]+)\.' -and @('amazonaws', 'external-1') -notcontains $Matches[1]) { $region = $Matches[1] }
    }
    $prefix = ''
    if ($path.Count -gt 1) { $prefix = $path[1].Trim('/') }
    return @{ scheme = $u.Scheme; host = $u.Authority; bucket = $path[0]; prefix = $prefix; region = $region }
}

function Get-HmacSha256 {
    param([byte[]]$Key, [string]$Text)
    $h = New-Object System.Security.Cryptography.HMACSHA256 (, $Key)
    try { return $h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) } finally { $h.Dispose() }
}

function Get-Sha256OfBytes {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

function ConvertTo-S3Escaped {
    param([string]$Text, [bool]$KeepSlash = $false)
    $e = [Uri]::EscapeDataString($Text)
    # EscapeDataString leaves !*'() as they are on older .NET; SigV4 wants them encoded.
    $e = $e.Replace('!', '%21').Replace('*', '%2A').Replace("'", '%27').Replace('(', '%28').Replace(')', '%29')
    if ($KeepSlash) { $e = $e.Replace('%2F', '/') }
    return $e
}

function Get-S3Signed {
    # SigV4: @{ Url; Headers }. $Presign: seconds a link stays good (signed in the query).
    param($Loc, [string]$Method, [string]$Key, [hashtable]$Query = @{}, [hashtable]$Headers = @{}, [string]$PayloadHash, [string]$Access, [string]$Secret,
        [string]$Token = '', [DateTime]$Now = [DateTime]::UtcNow, [int]$Presign = 0)
    $stamp = $Now.ToString("yyyyMMdd'T'HHmmss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    $day = $Now.ToString('yyyyMMdd', [Globalization.CultureInfo]::InvariantCulture)
    $scope = "$day/$($Loc.region)/s3/aws4_request"
    $segments = @(@((ConvertTo-S3Escaped $Loc.bucket), (ConvertTo-S3Escaped $Key $true)) | Where-Object { $_ })
    $path = '/' + ($segments -join '/')
    $q = @{}
    foreach ($k in $Query.Keys) { $q[$k] = $Query[$k] }
    $h = @{ host = $Loc.host }
    if ($Presign) {
        $q['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256'; $q['X-Amz-Credential'] = "$Access/$scope"; $q['X-Amz-Date'] = $stamp
        $q['X-Amz-Expires'] = [string]$Presign; $q['X-Amz-SignedHeaders'] = 'host'
        if ($Token) { $q['X-Amz-Security-Token'] = $Token }
        $PayloadHash = 'UNSIGNED-PAYLOAD'
    } else {
        foreach ($k in $Headers.Keys) { $h[$k.ToLowerInvariant()] = $Headers[$k] }
        $h['x-amz-date'] = $stamp; $h['x-amz-content-sha256'] = $PayloadHash
        if ($Token) { $h['x-amz-security-token'] = $Token }
    }
    $names = @($h.Keys | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -CaseSensitive)
    $canonQuery = (@($q.Keys | Sort-Object -CaseSensitive | ForEach-Object { (ConvertTo-S3Escaped $_) + '=' + (ConvertTo-S3Escaped ([string]$q[$_])) }) -join '&')
    $canonHeaders = (@($names | ForEach-Object { $_ + ':' + (([string]$h[$_]).Trim() -replace '\s+', ' ') + "`n" }) -join '')
    $canonical = @($Method, $path, $canonQuery, $canonHeaders, ($names -join ';'), $PayloadHash) -join "`n"
    $toSign = @('AWS4-HMAC-SHA256', $stamp, $scope, (Get-Sha256OfBytes ([Text.Encoding]::UTF8.GetBytes($canonical)))) -join "`n"
    $k = [Text.Encoding]::UTF8.GetBytes('AWS4' + $Secret)
    foreach ($part in @($day, $Loc.region, 's3', 'aws4_request')) { $k = Get-HmacSha256 $k $part }
    $signature = ((Get-HmacSha256 $k $toSign) | ForEach-Object { $_.ToString('x2') }) -join ''
    $url = "$($Loc.scheme)://$($Loc.host)$path"
    if ($Presign) { return @{ Url = "$url`?$canonQuery&X-Amz-Signature=$signature"; Headers = @{} } }
    $sent = @{}
    foreach ($n in $names) { if ($n -ne 'host') { $sent[$n] = $h[$n] } }
    $sent['Authorization'] = "AWS4-HMAC-SHA256 Credential=$Access/$scope, SignedHeaders=$($names -join ';'), Signature=$signature"
    if ($canonQuery) { $url += "?$canonQuery" }
    return @{ Url = $url; Headers = $sent }
}

function Invoke-S3 {
    # One signed call; @{ Headers; Body (text) }, or throws.
    param($Bc, $Loc, [string]$Method, [string]$Key, [hashtable]$Query = @{}, [byte[]]$Body = @(), [hashtable]$Headers = @{})
    $s = Get-S3Signed $Loc $Method $Key $Query $Headers (Get-Sha256OfBytes $Body) $Bc.env.AWS_ACCESS_KEY_ID $Bc.env.AWS_SECRET_ACCESS_KEY ([string]$Bc.env.AWS_SESSION_TOKEN)
    $req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($s.Url)
    $req.Method = $Method
    $req.Timeout = 300000
    $req.ReadWriteTimeout = 300000
    $req.ServicePoint.Expect100Continue = $false
    foreach ($k in $s.Headers.Keys) {
        if ($k -eq 'content-type') { $req.ContentType = $s.Headers[$k] } else { $req.Headers[$k] = $s.Headers[$k] }
    }
    if ($Method -eq 'PUT' -or $Method -eq 'POST') {
        $req.ContentLength = $Body.Length
        $st = $req.GetRequestStream()
        try { $st.Write($Body, 0, $Body.Length) } finally { $st.Close() }
    }
    $resp = $req.GetResponse()
    try {
        $hd = @{}
        foreach ($k in $resp.Headers.AllKeys) { $hd[$k.ToLowerInvariant()] = $resp.Headers[$k] }
        $text = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd()
        return @{ Headers = $hd; Body = $text }
    } finally { $resp.Close() }
}

function Get-S3DownloadKey {
    # Beside the repository, never inside it: restic owns everything under its prefix.
    param($Loc, [string]$Name)
    return (@('sitegoose-downloads', ($Loc.prefix -replace '[^A-Za-z0-9._-]', '_'), $Name) | Where-Object { $_ }) -join '/'
}

function Send-S3File {
    # Uploads a file in parts; its size.
    param($Bc, $Loc, [string]$Key, [string]$Path)
    $start = Invoke-S3 $Bc $Loc 'POST' $Key @{ uploads = '' } @() @{ 'content-type' = 'application/octet-stream' }
    $m = [regex]::Match($start.Body, '<UploadId>([^<]+)</UploadId>')
    if (-not $m.Success) { throw "the bucket didn't start the upload" }
    $id = $m.Groups[1].Value
    $tags = New-Object System.Collections.ArrayList
    $file = [IO.File]::OpenRead($Path)
    try {
        $buffer = New-Object byte[] $script:BackupPart
        do {
            $read = 0
            while ($read -lt $buffer.Length) { $n = $file.Read($buffer, $read, $buffer.Length - $read); if ($n -le 0) { break }; $read += $n }
            if ($read -eq 0 -and $tags.Count -gt 0) { break }
            $part = New-Object byte[] $read
            [Array]::Copy($buffer, $part, $read)
            $r = Invoke-S3 $Bc $Loc 'PUT' $Key @{ partNumber = [string]($tags.Count + 1); uploadId = $id } $part
            [void]$tags.Add($r.Headers['etag'])
        } while ($read -eq $buffer.Length)
        $xml = '<CompleteMultipartUpload>' + ((0..($tags.Count - 1) | ForEach-Object { '<Part><PartNumber>{0}</PartNumber><ETag>{1}</ETag></Part>' -f ($_ + 1), $tags[$_] }) -join '') + '</CompleteMultipartUpload>'
        [void](Invoke-S3 $Bc $Loc 'POST' $Key @{ uploadId = $id } ([Text.Encoding]::UTF8.GetBytes($xml)))
    } catch {
        try { [void](Invoke-S3 $Bc $Loc 'DELETE' $Key @{ uploadId = $id }) } catch { }
        throw
    } finally { $file.Dispose() }
    return (Get-Item -LiteralPath $Path).Length
}

function Get-BackupDumpArguments {
    # restic dump of one part: a folder as a zip, a database as its tool's own file.
    param($Item)
    if ($Item.kind -eq 'folder') { return @('dump', '--archive', 'zip', $Item.id, (ConvertTo-ResticPath $Item.name)) }
    return @('dump', $Item.id, ('/' + ((ConvertTo-ResticPath $Item.path) -replace '\\', '/').TrimStart('/')))
}

function Export-BackupItem {
    # One part of a run written to $Path: a folder as a zip, a database as its tool's own file.
    param($Bc, $Item, [string]$Path)
    $r = Invoke-Restic $Bc (Get-BackupDumpArguments $Item) $script:BackupTimeout @{} '' $Path
    if ($r.Code -ne 0) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue; throw "restic couldn't read it: $($r.Err)" }
}

function Get-BackupDownloadName {
    # shop-20261107.zip, shop-20261107.sql.gz, Shop-20261107.bak.gz; several parts: web-1-20261107.zip.
    param([string]$Run, $Items)
    $Items = @($Items)
    if ($Items.Count -ne 1) {
        $server = ((Get-ServerName) -replace '[^A-Za-z0-9._-]+', '-').Trim('-')
        if ($server.Length -gt 60) { $server = $server.Substring(0, 60) }
        if (-not $server) { $server = 'server' }
        return "$server-$($Run.Substring(0, 8)).zip"
    }
    $item = $Items[0]
    $base = (Split-Path -Leaf ($item.name.TrimEnd('\', '/'))) -replace '[^A-Za-z0-9._-]+', '-'
    if (-not $base) { $base = 'backup' }
    $stem, $rest = $base.Split('.', 2)
    $ending = ''
    if ($rest) { $ending = '.' + $rest }
    if ($item.kind -eq 'folder') { $ending += '.zip' } elseif ($ending -notlike '*.gz') { $ending += '.gz' }
    return "$stem-$($Run.Substring(0, 8))$ending"
}

function Get-BackupMemberName {
    # A part's name inside a run's zip: a folder as its own zip, a dump by its own name.
    param($Item)
    if ($Item.kind -ne 'folder') { return $Item.name }
    $n = ($Item.name -replace '[:\\/]+', '_').Trim('_')
    if (-not $n) { $n = 'root' }
    return $n + '.zip'
}

function Copy-BackupDump {
    param($Bc, $Item, [IO.Stream]$Stream)
    $r = Invoke-Restic $Bc (Get-BackupDumpArguments $Item) $script:BackupTimeout @{} '' '' $Stream
    if ($r.Code -ne 0) { throw "restic couldn't read $($Item.name): $($r.Err)" }
}

function Write-BackupPackage {
    # A download's content into $Out, written as it goes ($Out needn't seek):
    # one part as its own file (gzipped unless it's a zip or a .gz already),
    # or several in one zip.
    param($Bc, $Items, [IO.Stream]$Out)
    $Items = @($Items)
    $packed = { param($i) $i.kind -eq 'folder' -or $i.name -like '*.gz' }
    if ($Items.Count -eq 1) {
        if (& $packed $Items[0]) { Copy-BackupDump $Bc $Items[0] $Out; return }
        $gz = New-Object IO.Compression.GZipStream($Out, [IO.Compression.CompressionMode]::Compress, $true)
        try { Copy-BackupDump $Bc $Items[0] $gz } finally { $gz.Dispose() }
        return
    }
    Add-Type -AssemblyName System.IO.Compression
    $zip = New-Object IO.Compression.ZipArchive($Out, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        foreach ($item in $Items) {
            $level = [IO.Compression.CompressionLevel]::Optimal
            if (& $packed $item) { $level = [IO.Compression.CompressionLevel]::NoCompression }
            $member = $zip.CreateEntry((Get-BackupMemberName $item), $level).Open()
            try { Copy-BackupDump $Bc $item $member } finally { $member.Dispose() }
        }
    } finally { $zip.Dispose() }
}

function Format-ByteSize {
    param([double]$Bytes)
    foreach ($unit in 'bytes', 'KB', 'MB', 'GB') {
        if ($Bytes -lt 1024) {
            if ($unit -eq 'bytes') { return '{0} bytes' -f [long]$Bytes }
            return ('{0:0.0} {1}' -f $Bytes, $unit).Replace(',', '.')
        }
        $Bytes /= 1024
    }
    return ('{0:0.0} TB' -f $Bytes).Replace(',', '.')
}

function Assert-BackupRoom {
    # The temp folder made, with room for about $Items' size and some over.
    param($Bc, $Items)
    if (-not (Test-Path -LiteralPath $Bc.temp)) { New-Item -ItemType Directory -Path $Bc.temp -Force | Out-Null }
    $need = [long]$script:BackupDiskSpare
    foreach ($i in @($Items)) { if ($i.bytes) { $need += [long]$i.bytes } }
    $free = (New-Object IO.DriveInfo ([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Bc.temp)))).AvailableFreeSpace
    if ($free -lt $need) {
        throw ('making it needs about {0} free in {1}, and {2} is ("temp_dir" under "backups" puts it elsewhere)' -f (Format-ByteSize $need), $Bc.temp, (Format-ByteSize $free))
    }
}

function Invoke-BackupDownload {
    # One part, or several (a run's all when $Names is empty) in one zip. To
    # the owner's bucket with a link for an hour, or, with $Hosted
    # (public_key, max_bytes), encrypted for the browser that asked and put
    # in our storage for a day.
    param($Bc, [string]$Run, [string[]]$Names = @(), $Hosted = $null, [string]$RequestId = '')
    $loc = $null
    if (-not $Hosted) {
        $loc = Get-S3Location $Bc
        if (-not $loc) { throw "a download link needs the backups in an S3 bucket; on the server, analytics-agent.ps1 export $Run PART FILE writes it to a file" }
    }
    $items = @((Find-BackupRun $Bc $Run @($Names)).Items)
    $filename = Get-BackupDownloadName $Run $items
    Assert-BackupRoom $Bc $items
    if ($Hosted) { return Invoke-HostedDownload $Bc $items $filename $Hosted $RequestId }
    $file = Join-Path $Bc.temp ('backup-download-' + [guid]::NewGuid().ToString('N'))
    try {
        $out = [IO.File]::Create($file)
        try { Write-BackupPackage $Bc $items $out } finally { $out.Dispose() }
        $key = Get-S3DownloadKey $loc (([guid]::NewGuid().ToString('N').Substring(0, 16)) + '-' + $filename)
        $size = Send-S3File $Bc $loc $key $file
    } finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }
    $state = Read-BackupState $Bc
    $state.downloads = @($state.downloads) + @([ordered]@{ key = $key; at = (Get-EpochNow) })
    Save-BackupState $Bc $state
    $disposition = 'attachment; filename="' + ($filename -replace '[^A-Za-z0-9._-]', '_') + '"'
    $link = Get-S3Signed $loc 'GET' $key @{ 'response-content-disposition' = $disposition } @{} '' $Bc.env.AWS_ACCESS_KEY_ID $Bc.env.AWS_SECRET_ACCESS_KEY ([string]$Bc.env.AWS_SESSION_TOKEN) ([DateTime]::UtcNow) $script:BackupLinkSeconds
    return [ordered]@{ url = $link.Url; expires_at = (ConvertTo-IsoTime ((Get-EpochNow) + $script:BackupLinkSeconds)); bytes = $size; filename = $filename }
}

# -- Downloads kept for a day in our storage --
#
# Encrypted here for the browser that asked, so the file in our storage is
# one nobody but that browser can open: a random 32-byte secret, wrapped with
# the browser's RSA-OAEP public key (its private key never leaves it), and
# the file in the format of sdk/protocols/backups.md, "A download kept for a
# day": AES-256-CTR in 4 MB chunks, each with an HMAC-SHA256 tag over its
# number and whether it's the last, so a file cut short or reordered fails.
# The same bytes as the Linux agent's, pinned by sdk/protocols/download-cases.json.

$script:DownloadChunk = 4MB
$script:DownloadLabels = @('sitegoose-download-v1 enc', 'sitegoose-download-v1 mac')
$script:DownloadWriterSource = @'
using System;
using System.IO;
using System.Security.Cryptography;

namespace SiteGoose {
    // A stream that writes the encrypted download into another. Finish() seals
    // the last chunk; a writer disposed without it leaves a file that fails.
    public class DownloadWriter : Stream {
        readonly Stream inner;
        readonly ICryptoTransform ecb;
        readonly HMACSHA256 mac;
        readonly byte[] header = new byte[12];
        readonly byte[] counter = new byte[16];
        readonly byte[] buffer, counters, keystream;
        readonly int chunk;
        readonly long limit;
        int filled;
        long index, written;
        bool finished;

        public bool TooBig { get; private set; }

        public DownloadWriter(Stream inner, ICryptoTransform ecb, byte[] macKey, int chunk, long limit) {
            if (chunk <= 0 || chunk % 16 != 0) throw new ArgumentException("a chunk is a whole number of AES blocks");
            this.inner = inner;
            this.ecb = ecb;
            this.mac = new HMACSHA256(macKey);
            this.chunk = chunk;
            this.limit = limit;
            buffer = new byte[chunk];
            counters = new byte[chunk];
            keystream = new byte[chunk];
            System.Text.Encoding.ASCII.GetBytes("SGDL0001", 0, 8, header, 0);
            header[8] = (byte)(chunk >> 24); header[9] = (byte)(chunk >> 16); header[10] = (byte)(chunk >> 8); header[11] = (byte)chunk;
            inner.Write(header, 0, header.Length);
            written = header.Length;
        }

        public override void Write(byte[] data, int offset, int count) {
            if (finished) throw new InvalidOperationException("the download is already finished");
            while (count > 0) {
                // A full chunk is sealed only once more follows: the last one says so.
                if (filled == chunk) Seal(false);
                int n = Math.Min(count, chunk - filled);
                Buffer.BlockCopy(data, offset, buffer, filled, n);
                filled += n; offset += n; count -= n;
            }
        }

        public void Finish() {
            if (finished) return;
            Seal(true);
            finished = true;
            inner.Flush();
        }

        void Seal(bool last) {
            written += filled + 32;
            if (written > limit) { TooBig = true; throw new IOException("the download is over its size limit"); }
            int blocks = (filled + 15) / 16;
            for (int b = 0; b < blocks; b++) {
                Buffer.BlockCopy(counter, 0, counters, b * 16, 16);
                for (int i = 15; i >= 0 && ++counter[i] == 0; i--) { }
            }
            if (blocks > 0) ecb.TransformBlock(counters, 0, blocks * 16, keystream, 0);
            for (int i = 0; i < filled; i++) buffer[i] ^= keystream[i];
            byte[] meta = new byte[9];
            for (int i = 0; i < 8; i++) meta[i] = (byte)(index >> (56 - 8 * i));
            meta[8] = (byte)(last ? 1 : 0);
            mac.Initialize();
            mac.TransformBlock(header, 0, header.Length, null, 0);
            mac.TransformBlock(meta, 0, meta.Length, null, 0);
            mac.TransformFinalBlock(buffer, 0, filled);
            inner.Write(buffer, 0, filled);
            inner.Write(mac.Hash, 0, 32);
            filled = 0;
            index++;
        }

        protected override void Dispose(bool disposing) {
            if (disposing) { mac.Dispose(); ecb.Dispose(); }
            base.Dispose(disposing);
        }

        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return !finished; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override void Flush() { inner.Flush(); }
        public override int Read(byte[] b, int o, int c) { throw new NotSupportedException(); }
        public override long Seek(long o, SeekOrigin s) { throw new NotSupportedException(); }
        public override void SetLength(long v) { throw new NotSupportedException(); }
    }
}
'@

function New-DownloadWriter {
    # The encrypting stream over $Inner, from the download's secret. AES is
    # made here, not in the C#, so the C# needs nothing PowerShell 5.1 and 7
    # don't both reference.
    param([IO.Stream]$Inner, [byte[]]$Secret, [int]$Chunk = $script:DownloadChunk, [long]$Limit = [long]::MaxValue)
    if (-not ('SiteGoose.DownloadWriter' -as [type])) { Add-Type -TypeDefinition $script:DownloadWriterSource }
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
        $aes.Key = Get-HmacSha256 $Secret $script:DownloadLabels[0]
        $ecb = $aes.CreateEncryptor()
    } finally { $aes.Dispose() }
    return New-Object SiteGoose.DownloadWriter($Inner, $ecb, (Get-HmacSha256 $Secret $script:DownloadLabels[1]), $Chunk, $Limit)
}

function ConvertFrom-Base64Url {
    param([string]$Text)
    $t = $Text.Replace('-', '+').Replace('_', '/')
    switch ($t.Length % 4) { 2 { $t += '==' } 3 { $t += '=' } }
    return , [Convert]::FromBase64String($t)
}

function ConvertTo-UnsignedBig {
    # A big-endian unsigned number as a BigInteger (which reads little-endian, signed).
    param([byte[]]$Bytes)
    $le = New-Object byte[] ($Bytes.Length + 1)
    for ($i = 0; $i -lt $Bytes.Length; $i++) { $le[$i] = $Bytes[$Bytes.Length - 1 - $i] }
    return New-Object System.Numerics.BigInteger (, $le)
}

function Get-Mgf1 {
    param([byte[]]$Seed, [int]$Length)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $out = New-Object IO.MemoryStream
    try {
        for ($n = 0; $out.Length -lt $Length; $n++) {
            $c = [BitConverter]::GetBytes([uint32]$n)
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($c) }
            $h = $sha.ComputeHash([byte[]]($Seed + $c))
            $out.Write($h, 0, $h.Length)
        }
        $all = $out.ToArray()
        return , [byte[]]$all[0..($Length - 1)]
    } finally { $sha.Dispose(); $out.Dispose() }
}

function Get-XorBytes {
    param([byte[]]$A, [byte[]]$B)
    $r = New-Object byte[] $A.Length
    for ($i = 0; $i -lt $A.Length; $i++) { $r[$i] = $A[$i] -bxor $B[$i] }
    return , $r
}

function Protect-OaepSha256 {
    # RSA-OAEP with SHA-256 (RFC 8017, empty label) of $Message for a JWK
    # public key {kty: "RSA", n, e}, as WebCrypto decrypts it. The browser's
    # own key: never one of ours. By hand because .NET Framework's RSA does
    # OAEP with SHA-1 only.
    param($PublicKey, [byte[]]$Message)
    $bad = "the download's key isn't an RSA public key"
    if (-not (Test-IsMap $PublicKey) -or [string](Get-Prop $PublicKey 'kty' '') -ne 'RSA') { throw $bad }
    try { $nb = ConvertFrom-Base64Url ([string](Get-Prop $PublicKey 'n' '')); $eb = ConvertFrom-Base64Url ([string](Get-Prop $PublicKey 'e' '')) } catch { throw $bad }
    $skip = 0
    while ($skip -lt $nb.Length -and $nb[$skip] -eq 0) { $skip++ }
    $bits = 0
    if ($skip -lt $nb.Length) { $bits = ($nb.Length - $skip - 1) * 8 + [Convert]::ToString($nb[$skip], 2).Length }
    $n = ConvertTo-UnsignedBig $nb
    $e = ConvertTo-UnsignedBig $eb
    if ($bits -lt 2048 -or $bits -gt 4096 -or $e -ne 65537) { throw "the download's key isn't a 2048 to 4096-bit RSA key" }
    $k = [int][math]::Ceiling($bits / 8)
    $h = 32
    if ($Message.Length -gt $k - 2 * $h - 2) { throw 'too long to wrap' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $lHash = $sha.ComputeHash([byte[]]@()) } finally { $sha.Dispose() }
    $block = [byte[]]($lHash + (New-Object byte[] ($k - $Message.Length - 2 * $h - 2)) + @([byte]1) + $Message)
    $seed = New-Object byte[] $h
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($seed) } finally { $rng.Dispose() }
    $masked = Get-XorBytes $block (Get-Mgf1 $seed ($k - $h - 1))
    $maskedSeed = Get-XorBytes $seed (Get-Mgf1 $masked $h)
    $c = [System.Numerics.BigInteger]::ModPow((ConvertTo-UnsignedBig ([byte[]](@([byte]0) + $maskedSeed + $masked))), $e, $n)
    $le = $c.ToByteArray()
    $out = New-Object byte[] $k
    for ($i = 0; $i -lt [math]::Min($le.Length, $k); $i++) { $out[$k - 1 - $i] = $le[$i] }
    return , $out
}

function Invoke-HostedDownload {
    param($Bc, $Items, [string]$Filename, $Hosted, [string]$RequestId)
    $secret = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($secret) } finally { $rng.Dispose() }
    # Wrapped first: a key that won't do is said before an hour of work.
    $wrapped = Protect-OaepSha256 (Get-Prop $Hosted 'public_key') $secret
    $limit = Get-WholeNumber (Get-Prop $Hosted 'max_bytes') 1 1e15
    if ($null -eq $limit) { throw "the dashboard didn't say how big a file may be" }
    $path = Join-Path $Bc.temp ('backup-download-' + [guid]::NewGuid().ToString('N') + '.sgdl')
    try {
        $file = [IO.File]::Create($path)
        $sealer = $null
        try {
            $sealer = New-DownloadWriter $file $secret $script:DownloadChunk ([long]$limit)
            Write-BackupPackage $Bc $Items $sealer
            $sealer.Finish()
        } catch {
            if ($sealer -and $sealer.TooBig) { throw ('it comes to more than the {0} a file your plan allows; download its parts one at a time' -f (Format-ByteSize $limit)) }
            throw
        } finally {
            if ($sealer) { $sealer.Dispose() }
            $file.Dispose()
        }
        $size = (Get-Item -LiteralPath $path).Length
        Send-HostedUpload $Bc $RequestId $path $size
    } finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    return [ordered]@{ hosted = $true; wrapped_key = [Convert]::ToBase64String($wrapped); bytes = $size; filename = $Filename }
}

function Send-UploadPart {
    # One part of an upload to a link the collector signed; its ETag.
    param([string]$Url, [byte[]]$Data)
    $req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Url)
    $req.Method = 'PUT'
    $req.Timeout = 300000
    $req.ReadWriteTimeout = 300000
    $req.ServicePoint.Expect100Continue = $false
    $req.ContentLength = $Data.Length
    $st = $req.GetRequestStream()
    try { $st.Write($Data, 0, $Data.Length) } finally { $st.Close() }
    $resp = $req.GetResponse()
    try { return [string]$resp.Headers['ETag'] } finally { $resp.Close() }
}

function Send-HostedUpload {
    # The encrypted file to our storage, in parts, through links the collector signs.
    param($Bc, [string]$RequestId, [string]$Path, [long]$Size)
    $who = [ordered]@{ site_id = $Bc.config.site_id; host = (Get-ServerName); id = $RequestId }
    $body = [ordered]@{}
    foreach ($k in $who.Keys) { $body[$k] = $who[$k] }
    $body.bytes = $Size
    $res = Invoke-Collector $Bc.config 'POST' '/events/backups/upload' $body @{} (Get-BackupUserAgent)
    $answer = $null
    try { $answer = ConvertFrom-Json ([string]$res.Body) } catch { }
    if ($res.Status -ne 200) {
        $why = [string](Get-Prop $answer 'error' '')
        if (-not $why) { $why = "the collector answered $($res.Status) to the upload" }
        throw $why
    }
    $partSize = Get-WholeNumber (Get-Prop $answer 'part_size') 1 1GB
    $parts = @(Get-EntryList (Get-Prop $answer 'parts'))
    if ($null -eq $partSize -or $parts.Count -eq 0) { throw "the collector didn't say where to upload it" }
    $done = New-Object System.Collections.ArrayList
    $file = [IO.File]::OpenRead($Path)
    try {
        $buffer = New-Object byte[] ([int]$partSize)
        foreach ($p in $parts) {
            $read = 0
            while ($read -lt $buffer.Length) { $n = $file.Read($buffer, $read, $buffer.Length - $read); if ($n -le 0) { break }; $read += $n }
            $data = New-Object byte[] $read
            [Array]::Copy($buffer, $data, $read)
            $etag = $null
            for ($try = 1; $null -eq $etag; $try++) {
                try { $etag = Send-UploadPart ([string]$p.url) $data }
                catch {
                    if ($try -ge 3) { throw "the upload failed: $($_.Exception.Message)" }
                    Start-Sleep -Seconds (5 * $try)
                }
            }
            [void]$done.Add([ordered]@{ n = $p.n; etag = $etag })
        }
    } finally { $file.Dispose() }
    $who.parts = @($done.ToArray())
    $res = Invoke-Collector $Bc.config 'POST' '/events/backups/upload/done' $who @{} (Get-BackupUserAgent)
    if ($res.Status -ne 200) { throw "the collector answered $($res.Status) when the upload finished" }
}

# -- Putting a run back --

function Get-RunningServices {
    $svcs = Get-WindowsServices
    if ($null -eq $svcs) { return @() }
    # The config's services (already read by Read-AgentConfig) and the ones found.
    return @(Get-ServiceChecks $svcs @($script:BackupServicesListed) $true @{} (Get-EpochNow) | Where-Object { $_.ok } | ForEach-Object { $_.name })
}

function Restore-BackupItem {
    # Puts one part back, adding to $Done how to undo it.
    param($Bc, $Item, [string]$RequestId, [System.Collections.ArrayList]$Done)
    $tag = ($RequestId -replace '[^A-Za-z0-9]', '')
    if ($tag.Length -gt 12) { $tag = $tag.Substring(0, 12) }
    if ($Item.kind -eq 'folder') {
        $folder = $Item.name.TrimEnd('\')
        if ($folder -match $script:SystemFolderPattern) {
            throw "$folder is a system folder, never swapped whole: analytics-agent.ps1 restore RUN `"$folder`" -Into D:\somewhere copies it out"
        }
        $parent = Split-Path -Parent $folder
        $leaf = Split-Path -Leaf $folder
        $staging = Join-Path $parent ".sitegoose-restore-$tag-$leaf"
        $aside = Join-Path $parent ".sitegoose-before-$tag-$leaf"
        $r = Invoke-Restic $Bc @('restore', ($Item.id + ':' + (ConvertTo-ResticPath $folder)), '--target', $staging) $script:BackupTimeout
        if ($r.Code -ne 0) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue; throw "${folder}: restic couldn't restore it: $($r.Err)" }
        $moved = $false
        if (Test-Path -LiteralPath $folder) {
            try { [IO.Directory]::Move($folder, $aside); $moved = $true } catch { }
            if (-not $moved) {
                # A file in it is open (IIS holds some): mirror over it instead.
                # Undone from the safety copy, not by moving back.
                $m = Invoke-BackupProcess 'robocopy.exe' @($staging, $folder, '/MIR', '/COPY:DAT', '/R:2', '/W:2', '/NFL', '/NDL', '/NP') @{} '' '' $script:BackupTimeout
                Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
                [void]$Done.Add(@{ kind = 'folder'; folder = $folder; aside = $null; name = $Item.name })
                if ($null -eq $m.Code -or $m.Code -ge 8) { throw "${folder}: robocopy couldn't copy it over (exit $($m.Code))" }
                return
            }
        }
        [IO.Directory]::Move($staging, $folder)
        $kept = $null
        if ($moved) { $kept = $aside }
        [void]$Done.Add(@{ kind = 'folder'; folder = $folder; aside = $kept; created = -not $moved; name = $Item.name })
        return
    }
    $db = $Bc.databases | Where-Object { $Item.name.StartsWith((Get-ItemPrefix $_) + '/') } | Select-Object -First 1
    if (-not $db) { throw "$($Item.name): that database isn't under `"backups`" in the config any more" }
    $session = Get-DbSession $Bc $db
    $folder = $Bc.temp
    if ($db.kind -eq 'sqlserver') { $folder = Get-SqlBackupFolder $Bc $db $session }
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    $file = Join-Path $folder ('sitegoose-restore-' + [guid]::NewGuid().ToString('N') + (Get-DumpEnding $db.kind))
    try {
        Export-BackupItem $Bc $Item $file
        [void]$Done.Add(@{ kind = 'database'; name = $Item.name })
        $dbName = (Split-Path -Leaf $Item.name) -replace ([regex]::Escape((Get-DumpEnding $db.kind)) + '$'), ''
        # It goes into T-SQL and command lines: only a name the agent itself backs up.
        if ($dbName -notmatch $script:DbNamePattern) { throw "$($Item.name): not a database name the agent backs up" }
        switch ($db.kind) {
            'sqlserver' {
                $n = Get-SqlName $dbName
                $sql = ("IF DB_ID(N'{0}') IS NOT NULL ALTER DATABASE {1} SET SINGLE_USER WITH ROLLBACK IMMEDIATE; " +
                    "BEGIN TRY RESTORE DATABASE {1} FROM DISK = N'{2}' WITH REPLACE, CHECKSUM; END TRY " +
                    "BEGIN CATCH IF DB_ID(N'{0}') IS NOT NULL ALTER DATABASE {1} SET MULTI_USER; THROW; END CATCH; ALTER DATABASE {1} SET MULTI_USER;") -f ($dbName -replace "'", "''"), $n, ($file -replace "'", "''")
                $r = Invoke-SqlCmd $db $session $sql $script:BackupTimeout
            }
            'mysql' {
                $r = Invoke-BackupProcess (Get-ToolFor 'mysql' 'client') @($session.Args) $session.Env $file '' $script:BackupTimeout
            }
            'postgresql' {
                # One transaction: a restore that fails half way leaves the database as it was.
                $tool = Get-ToolFor 'postgresql' 'restore'
                $r = Invoke-BackupProcess $tool @('--clean', '--if-exists', '--single-transaction', '--exit-on-error', '-d', $dbName, $file) $session.Env '' '' $script:BackupTimeout
                if ($r.Code -ne 0 -and $r.Err -match 'database ".*" does not exist') {
                    # Dropped since: made again from the dump (CREATE DATABASE can't be in a transaction).
                    $r = Invoke-BackupProcess $tool @('--create', '--exit-on-error', '-d', 'postgres', $file) $session.Env '' '' $script:BackupTimeout
                }
            }
            'mongodb' {
                $r = Invoke-BackupProcess (Get-ToolFor 'mongodb' 'restore') (@("--archive=$file", '--gzip', '--drop', '--quiet') + @($session.Args)) $session.Env '' '' $script:BackupTimeout
            }
        }
        if ($r.Code -ne 0) { throw "$($Item.name): $($r.Err)" }
    } finally {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        Close-DbSession $session
    }
}

function Set-AlertPause {
    param($Bc, [int]$Minutes, [string]$Note = '')
    $body = [ordered]@{ site_id = $Bc.config.site_id }
    if ($Minutes -gt 0) { $body.minutes = $Minutes; $body.note = $Note } else { $body.end = $true }
    $res = Invoke-Collector $Bc.config 'POST' '/events/maintenance' $body @{} (Get-BackupUserAgent)
    return $res.Status -eq 200
}

function Undo-BackupRestore {
    param($Bc, [System.Collections.ArrayList]$Done, [string]$SafetyRun, [string]$RequestId)
    $problems = New-Object System.Collections.ArrayList
    $fromSafety = New-Object System.Collections.ArrayList
    for ($i = $Done.Count - 1; $i -ge 0; $i--) {
        $d = $Done[$i]
        if ($d.kind -eq 'folder' -and $d.aside) {
            try {
                $failed = $d.folder + '.sitegoose-failed'
                [IO.Directory]::Move($d.folder, $failed)
                [IO.Directory]::Move($d.aside, $d.folder)
                Remove-Item -LiteralPath $failed -Recurse -Force -ErrorAction SilentlyContinue
            } catch { [void]$problems.Add("$($d.folder): $($_.Exception.Message)") }
        } elseif ($d.kind -eq 'folder' -and $d.created) {
            # Wasn't there before the restore: gone again.
            try { Remove-Item -LiteralPath $d.folder -Recurse -Force -ErrorAction Stop } catch { [void]$problems.Add("$($d.folder): $($_.Exception.Message)") }
        } else { [void]$fromSafety.Add($d.name) }
    }
    if ($fromSafety.Count) {
        try {
            $found = Find-BackupRun $Bc $SafetyRun @()
            $back = New-Object System.Collections.ArrayList
            foreach ($item in @($found.Items | Where-Object { $fromSafety -contains $_.name })) { Restore-BackupItem $Bc $item ('u' + $RequestId) $back }
        } catch { [void]$problems.Add($_.Exception.Message) }
    }
    if ($problems.Count) { return "Undoing it failed too ($($problems -join '; ')): backup $SafetyRun has them as they were" }
    return 'Everything was put back as it was'
}

function Invoke-BackupRestore {
    # Puts the run's parts (all when $Names is empty) back; @{ steps; aside;
    # safety_run }, or throws with what went wrong, after undoing it.
    param($Bc, [string]$Run, [string[]]$Names, [string]$RequestId)
    $items = @((Find-BackupRun $Bc $Run $Names).Items)
    if (-not $items.Count) { throw 'that backup has nothing to restore' }
    $steps = New-Object System.Collections.ArrayList
    $paused = Set-AlertPause $Bc $script:RestorePauseMinutes "Restoring the backup of $Run"
    if ($paused) { [void]$steps.Add('alerts paused') } else { [void]$steps.Add("alerts couldn't be paused") }
    try {
        $safety = Invoke-BackupRun $Bc 'before-restore' @($items | ForEach-Object { $_.name })
        $failed = @($safety.items | Where-Object { -not $_.ok -and -not $_.missing })
        if ($safety.setup -or $failed.Count) {
            $why = $safety.error
            if (-not $why) { $why = (@($failed | ForEach-Object { "$($_.name): $($_.error)" }) -join '; ') }
            throw "nothing was changed: the copy of how things are now failed ($why)"
        }
        [void]$steps.Add("copied how things are now, as backup $($safety.run)")
        $before = @(Get-RunningServices)
        $done = New-Object System.Collections.ArrayList
        try {
            foreach ($item in $items) { Restore-BackupItem $Bc $item $RequestId $done; [void]$steps.Add('put back ' + $item.name) }
            $down = @()
            for ($i = 0; $i -lt ($script:BackupHealthWait / 10); $i++) {
                Start-Sleep -Seconds 10
                $now = @(Get-RunningServices)
                $down = @($before | Where-Object { $now -notcontains $_ })
                if (-not $down.Count) { break }
            }
            if ($down.Count) { throw "$($down -join ', ') stopped after the restore" }
        } catch {
            $err = $_.Exception.Message
            [void]$steps.Add("failed: $err")
            throw ("$err. " + (Undo-BackupRestore $Bc $done $safety.run $RequestId))
        }
        $aside = @($done | Where-Object { $_.aside } | ForEach-Object { $_.aside })
        if ($aside.Count) {
            $state = Read-BackupState $Bc
            $state.aside = @($state.aside) + @($aside | ForEach-Object { [ordered]@{ path = $_; at = (Get-EpochNow) } })
            Save-BackupState $Bc $state
        }
        [void]$steps.Add('services running as before')
        return [ordered]@{ steps = @($steps.ToArray()); aside = $aside; safety_run = $safety.run }
    } finally {
        if ($paused) { [void](Set-AlertPause $Bc 0) }
    }
}

# -- The worker --

function Send-BackupAnswer {
    param($Bc, [string]$Id, [string]$State, $Fields = @{})
    $body = [ordered]@{ site_id = $Bc.config.site_id; host = (Get-ServerName); id = $Id; state = $State }
    foreach ($k in $Fields.Keys) { $body[$k] = $Fields[$k] }
    $res = Invoke-Collector $Bc.config 'POST' '/events/backups/requests' $body @{} (Get-BackupUserAgent)
    if ($res.Status -ne 200 -and $res.Status -ne 202) { Write-AgentLog "collector answered $($res.Status) to a backup request's $State" }
}

function Invoke-BackupRequests {
    # What the dashboard asked; $true when something changed (the report then goes again).
    param($Bc)
    $res = Invoke-Collector $Bc.config 'GET' ("/events/backups/requests?site_id={0}&host={1}" -f $Bc.config.site_id, [Uri]::EscapeDataString((Get-ServerName))) $null @{} (Get-BackupUserAgent)
    if ($res.Status -ne 200) { return $false }
    try {
        $answer = ConvertFrom-Json $res.Body
        $asked = @(Get-EntryList $answer.requests)
    } catch { return $false }
    $changed = $false
    # The schedule set on the dashboard (null: none, the config's).
    $p = $answer.PSObject.Properties['schedule']
    if ($p) {
        $wanted = $null
        if (Test-IsMap $p.Value) { $wanted = $p.Value }
        $state = Read-BackupState $Bc
        if ((ConvertTo-Json -InputObject $wanted -Compress -Depth 3) -ne (ConvertTo-Json -InputObject $state.schedule -Compress -Depth 3)) {
            $state.schedule = $wanted
            Save-BackupState $Bc $state
            $changed = $true
        }
    }
    foreach ($a in @($asked | Select-Object -First 5)) {
        $id = [string]$a.id
        if (-not $id) { continue }
        $changed = $true
        Send-BackupAnswer $Bc $id 'running'
        $hosted = $null
        if (Test-IsMap $a.hosted) { $hosted = $a.hosted }
        try {
            if ($a.kind -eq 'download') {
                $names = @(@(Get-EntryList $a.items) | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -First 200)
                if ($a.item) { $names = @([string]$a.item) }
                $result = Invoke-BackupDownload $Bc ([string]$a.run) $names $hosted $id
            } elseif ($a.kind -eq 'backup') {
                $record = Invoke-BackupRun $Bc 'manual'
                $result = [ordered]@{ run = $record.run; steps = @("backed up: $($record.state)") }
                if ($a.download -eq $true) {
                    if ($record.state -eq 'failed') {
                        $why = $record.error
                        if (-not $why) { $why = (@($record.items | Where-Object { -not $_.ok } | ForEach-Object { "$($_.name): $($_.error)" }) -join '; ') }
                        throw "the backup failed, so there is nothing to download: $why"
                    }
                    $more = Invoke-BackupDownload $Bc $record.run @() $hosted $id
                    foreach ($k in $more.Keys) { $result[$k] = $more[$k] }
                }
            } elseif ($a.kind -eq 'restore') {
                if (-not $Bc.allow_restore) {
                    throw "restoring from the dashboard is off on this server: set `"allow_restore`": true under `"backups`" in $($Bc.config.config_path), or run analytics-agent.ps1 restore there"
                }
                $result = Invoke-BackupRestore $Bc ([string]$a.run) @(@($a.items) | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -First 100) $id
            } else { throw 'unknown request' }
            Send-BackupAnswer $Bc $id 'done' $result
        } catch {
            $msg = $_.Exception.Message
            if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
            Send-BackupAnswer $Bc $id 'failed' @{ error = $msg }
        }
    }
    return $changed
}

function Clear-BackupLeftovers {
    param($Bc)
    $state = Read-BackupState $Bc
    $now = Get-EpochNow
    $loc = Get-S3Location $Bc
    $keep = @()
    foreach ($d in @($state.downloads)) {
        if ($now - [double]$d.at -lt $script:BackupDownloadKeep) { $keep += $d; continue }
        try { if ($loc) { [void](Invoke-S3 $Bc $loc 'DELETE' ([string]$d.key)) } } catch { Write-AgentLog "backups: an old download couldn't be deleted: $($_.Exception.Message)"; $keep += $d }
    }
    $aside = @()
    foreach ($e in @($state.aside)) {
        if ($now - [double]$e.at -lt $script:BackupAsideKeep) { $aside += $e }
        elseif ((Split-Path -Leaf ([string]$e.path)) -like '.sitegoose-before-*') { Remove-Item -LiteralPath ([string]$e.path) -Recurse -Force -ErrorAction SilentlyContinue }
    }
    # What a killed run left in the temp folder: option files with passwords, dumps.
    if (Test-Path -LiteralPath $Bc.temp) {
        Get-ChildItem -LiteralPath $Bc.temp -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddDays(-1) } |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
    }
    if ($keep.Count -ne @($state.downloads).Count -or $aside.Count -ne @($state.aside).Count) {
        $state.downloads = $keep
        $state.aside = $aside
        Save-BackupState $Bc $state
    }
}

function Get-BackupSchedule {
    # When the backups run: what the dashboard set, else the config.
    param($Bc, $State)
    $w = $State.schedule
    $s = [string](Get-Prop $w 'schedule' '')
    if ((Test-IsMap $w) -and $script:BackupSchedules -ccontains $s) {
        $at = [string](Get-Prop $w 'at' '')
        if ($at -notmatch $script:BackupTimeFormat) { $at = $Bc.at }
        $day = [string](Get-Prop $w 'weekday' '')
        if ($script:BackupWeekdays -cnotcontains $day) { $day = $Bc.weekday }
        return @{ schedule = $s; at = $at; weekday = $day; from = 'dashboard' }
    }
    return @{ schedule = $Bc.schedule; at = $Bc.at; weekday = $Bc.weekday; from = 'config' }
}

function Test-BackupDue {
    param($Bc, $State, [DateTime]$Now = (Get-Date))
    $plan = Get-BackupSchedule $Bc $State
    if ($plan.schedule -eq 'off' -or ($plan.schedule -eq 'weekly' -and $script:BackupWeekdays[[int]$Now.DayOfWeek] -ne $plan.weekday)) { return $false }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    return $Now.ToString('HH:mm', $inv) -ge $plan.at -and [string]$State.last_day -ne $Now.ToString('yyyy-MM-dd', $inv)
}

function Invoke-BackupWorker {
    # The backup process: its own loop, one of it at a time, ending when the
    # agent that started it ($Parent) has (an update then runs new code).
    param($Bc, [int]$Parent = 0)
    $mutex = New-Object System.Threading.Mutex($false, 'Global\AnalyticsAgentBackups')
    $owned = $false
    try { $owned = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
    if (-not $owned) { $mutex.Dispose(); return 0 }
    $script:BackupServicesListed = $Bc.config.services
    Write-AgentLog 'backups worker started'
    $nextReport = 0.0
    $nextPoll = 0.0
    try {
        while ($true) {
            $now = Get-EpochNow
            try {
                if ($now -ge $nextPoll) {
                    $nextPoll = $now + $script:BackupRequestsEvery
                    if (Invoke-BackupRequests $Bc) { $nextReport = 0 }
                }
                if (Test-BackupDue $Bc (Read-BackupState $Bc)) { [void](Invoke-BackupRun $Bc 'nightly'); $nextReport = 0 }
                if ((Get-EpochNow) -ge $nextReport) { $nextReport = (Get-EpochNow) + $script:BackupReportEvery; [void](Send-BackupReport $Bc) }
                Clear-BackupLeftovers $Bc
            } catch { Write-AgentLog "backups round failed: $($_.Exception.Message)" }
            if ($Parent -and -not (Get-Process -Id $Parent -ErrorAction SilentlyContinue)) { Write-AgentLog 'backups worker stopped: the agent did'; return 0 }
            Start-Sleep -Seconds $script:BackupTick
        }
    } finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
}

function Start-BackupWorker {
    # From the agent's loop: the worker running when backups are set up,
    # started again (at most once a minute) if it stopped.
    param($Config, [string]$ConfigPath)
    $now = Get-EpochNow
    if ($now - $script:BackupWorkerAt -lt 60) { return }
    $script:BackupWorkerAt = $now
    if ($script:BackupWorker -and -not $script:BackupWorker.HasExited) { return }
    if (-not (Get-BackupConfig $Config)) { return }
    $shell = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $shell
    $psi.Arguments = Join-ProcessArguments @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:AgentPath, 'backup-worker', [string]$PID, '-ConfigPath', $ConfigPath)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    try { $script:BackupWorker = [System.Diagnostics.Process]::Start($psi) } catch { Write-AgentLog "backups worker didn't start: $($_.Exception.Message)" }
}

function Install-Restic {
    # restic at %ProgramData%\AnalyticsAgent\restic.exe, from its release,
    # checked against the pinned hash.
    $arch = 'amd64'
    if (-not [Environment]::Is64BitOperatingSystem) { $arch = '386' }
    $url = "https://github.com/restic/restic/releases/download/v$($script:ResticVersion)/restic_$($script:ResticVersion)_windows_$arch.zip"
    $dir = Join-Path $env:ProgramData 'AnalyticsAgent'
    $zip = Join-Path $dir 'restic-download.zip'
    (New-Object System.Net.WebClient).DownloadFile($url, $zip)
    try {
        $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne $script:ResticSha256[$arch]) { throw "restic's download didn't match its checksum, so it wasn't installed." }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [IO.Compression.ZipFile]::OpenRead($zip)
        try {
            $entry = @($archive.Entries | Where-Object { $_.Name -like 'restic*.exe' })[0]
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $dir 'restic.exe'), $true)
        } finally { $archive.Dispose() }
    } finally { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
}

function Invoke-BackupCommand {
    param($Config, [string]$Command, [string[]]$Rest = @(), [string]$Into = '', [bool]$Yes = $false)
    $bc = Get-BackupConfig $Config
    if (-not $bc) { Write-Host "Backups are off: add a `"backups`" section with a `"repository`" to $($Config.config_path)."; return 1 }
    $script:BackupServicesListed = $Config.services
    switch ($Command) {
        'backup-worker' {
            $parent = 0
            if (@($Rest).Count) { [void][int]::TryParse($Rest[0], [ref]$parent) }
            return Invoke-BackupWorker $bc $parent
        }
        'backup-setup' {
            $v = Get-ResticVersion $bc
            if (-not $v -or $v -lt [version]'0.17.0') { Write-Host "Installing restic $($script:ResticVersion)..."; Install-Restic }
            Write-Host ('restic ' + (Get-ResticVersion $bc))
            if (-not (Test-Path -LiteralPath $bc.password_file)) {
                $bytes = New-Object byte[] 32
                [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
                $password = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
                Write-TextFile $bc.password_file ($password + "`n")
                Write-Host "`nThe backups' password, in $($bc.password_file):`n`n    $password`n"
                Write-Host 'Keep it in your password manager now. Without it no backup can be read, and if this server is lost,'
                Write-Host "so is the copy in that file. Nobody else has it: we can't recover it for you.`n"
            }
            $p = Get-BackupSetupProblem $bc
            if ($p) { Write-Host ('Not ready: ' + $p[1]); return 1 }
            Write-Host ('Repository ready: ' + (Get-ShownRepository $bc.repository))
            Write-Host "Backs up every night at $($bc.at) (this server's time). analytics-agent.ps1 backup runs one now."
            return 0
        }
        'backup' {
            $r = Invoke-BackupRun $bc 'manual'
            Write-Host ('backup {0}: {1} {2}' -f $r.run, $r.state, $r.error)
            foreach ($i in @($r.items)) { Write-Host ('  {0,-4} {1} {2}' -f $(if ($i.ok) { 'ok' } else { 'FAIL' }), $i.name, $i.error) }
            [void](Send-BackupReport $bc)
            if ($r.state -eq 'ok') { return 0 } else { return 1 }
        }
        'backups' {
            foreach ($run in @(Get-BackupRuns $bc)) {
                Write-Host ('{0}  {1}  {2}' -f $run.run, $run.at, $run.trigger)
                foreach ($i in $run.items) { Write-Host ('    {0,-8} {1}' -f $i.kind, $i.name) }
            }
            return 0
        }
        'export' {
            if (@($Rest).Count -ne 3) { Write-Host 'analytics-agent.ps1 export RUN PART FILE'; return 2 }
            $item = (Find-BackupRun $bc $Rest[0] @($Rest[1])).Items[0]
            Export-BackupItem $bc $item $Rest[2]
            Write-Host ('written to ' + $Rest[2])
            return 0
        }
        'restore' {
            if (-not @($Rest).Count) { Write-Host 'analytics-agent.ps1 restore RUN [PART...] [-Into FOLDER] [-Yes]'; return 2 }
            $names = @($Rest | Select-Object -Skip 1)
            $found = Find-BackupRun $bc $Rest[0] $names
            if ($Into) {
                $into = $Into
                New-Item -ItemType Directory -Path $into -Force | Out-Null
                foreach ($item in $found.Items) {
                    $target = Join-Path $into (($item.name -replace '[:\\/]+', '_').Trim('_'))
                    if ($item.kind -eq 'folder') {
                        $r = Invoke-Restic $bc @('restore', ($item.id + ':' + (ConvertTo-ResticPath $item.name)), '--target', $target) $script:BackupTimeout
                        if ($r.Code -ne 0) { Write-Host "$($item.name): $($r.Err)"; return 1 }
                    } else { Export-BackupItem $bc $item $target }
                    Write-Host "  $($item.name) -> $target"
                }
                Write-Host 'Copied out; nothing live was changed.'
                return 0
            }
            Write-Host "This replaces, on this server, with backup $($Rest[0]):"
            foreach ($item in $found.Items) { Write-Host ('  {0,-8} {1}' -f $item.kind, $item.name) }
            Write-Host 'How they are now is backed up first, and put back if anything fails.'
            if (-not $Yes -and (Read-Host 'Type restore to go on') -ne 'restore') { Write-Host 'Nothing was changed.'; return 1 }
            $result = Invoke-BackupRestore $bc $Rest[0] $names ('cli' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            foreach ($s in $result.steps) { Write-Host "  $s" }
            foreach ($a in $result.aside) { Write-Host "  the folder as it was is kept a week at $a" }
            [void](Send-BackupReport $bc)
            return 0
        }
    }
    return 2
}

# ---- The agent ---------------------------------------------------------------------

function New-Agent {
    param($Config)
    $a = @{
        Config = $Config
        StateFile = Join-Path $Config.state_dir 'state.json'
        BansFile = Join-Path $Config.state_dir 'bans.json'
        ServicesFile = Join-Path $Config.state_dir 'services.json'
        ETag = ''; RulesJson = ''; Rules = $null; Plan = $null; PlanOf = ''
        Running = @{}
        Iis = @{ dipr_ours = $false; dipr_original = $null; allow_added = @(); check_rule_digest = ''; check_outbound_digest = ''; check_day = -1
            check_added_variable = $false; check_page = ''; deny_added = @(); limits_held = '' }
        LastSnap = $null
        Notes = @{}
        Bans = New-Object System.Collections.Hashtable
        IisDenied = New-Object System.Collections.Hashtable
        IisBansAt = 0.0
        IisBansApplied = ''
        OriginBlock = $null
        OriginCheckedAt = 0.0
        ProbeTargets = @()
        BansApplied = $null
        BansSaved = ''
        Buckets = New-Object System.Collections.Hashtable
        ClassCache = New-Object System.Collections.Hashtable
        Sets = $null
        Tails = @{}
        Events = New-Object System.Collections.Hashtable
        Challenged = New-Object System.Collections.Hashtable
        ChallengedAt = 0.0
        PrunedAt = 0.0
        CheckRetryAt = 0.0
        FwUsable = $false
        FwCurrent = $null
        Own = @()
        ServicesAt = 0.0
        ServicesEvery = $script:ServicesEvery
        ServicesReported = $false
        ServiceSince = @{}
        ServiceSeen = @{}
        UsagePrev = @{}
    }
    $a.ServiceSeen = Read-ServicesSeen $a.ServicesFile
    foreach ($l in $script:Layers) { $a.Running[$l] = $false }
    try {
        if (Test-Path -LiteralPath $a.StateFile) {
            $saved = ConvertFrom-Json ([IO.File]::ReadAllText($a.StateFile))
            $a.ETag = [string](Get-Prop $saved 'etag' '')
            $a.RulesJson = [string](Get-Prop $saved 'rules' '')
            if ($a.RulesJson) { $a.Rules = ConvertFrom-Json $a.RulesJson }
            $running = Get-Prop $saved 'running'
            foreach ($l in $script:Layers) { $a.Running[$l] = (Get-Prop $running $l) -eq $true }
            $iis = Get-Prop $saved 'iis'
            if ($iis) {
                $a.Iis.dipr_ours = (Get-Prop $iis 'dipr_ours') -eq $true
                $orig = Get-Prop $iis 'dipr_original'
                if ($orig) {
                    $a.Iis.dipr_original = @{}
                    foreach ($p in $orig.PSObject.Properties) { $a.Iis.dipr_original[$p.Name] = $p.Value }
                }
                $a.Iis.allow_added = @(Get-EntryList (Get-Prop $iis 'allow_added') | Where-Object { $_ -is [string] })
                $a.Iis.check_rule_digest = [string](Get-Prop $iis 'check_rule_digest' '')
                $a.Iis.check_outbound_digest = [string](Get-Prop $iis 'check_outbound_digest' '')
                $a.Iis.check_day = [long](Get-Prop $iis 'check_day' -1)
                $a.Iis.check_added_variable = (Get-Prop $iis 'check_added_variable') -eq $true
                $a.Iis.check_page = [string](Get-Prop $iis 'check_page' '')
                $a.Iis.deny_added = @(Get-EntryList (Get-Prop $iis 'deny_added') | Where-Object { $_ -is [string] })
                $a.Iis.limits_held = [string](Get-Prop $iis 'limits_held' '')
            }
        }
    } catch {
        Write-AgentLog "state file unreadable, starting afresh: $($_.Exception.Message)"
    }
    try {
        if (Test-Path -LiteralPath $a.BansFile) {
            $saved = ConvertFrom-Json ([IO.File]::ReadAllText($a.BansFile))
            foreach ($p in @((Get-Prop $saved 'bans').PSObject.Properties)) {
                $b = $p.Value
                if (Test-ValidBan $p.Name $b) {
                    $a.Bans[$p.Name] = @{ rule = [string]$b.rule; first = [double]$b.first; until = [double]$b.until; hits = [long]$b.hits
                        reported = [bool]$b.reported; enforced = [bool]$b.enforced }
                }
            }
        }
    } catch { }
    return $a
}

function Test-ValidBan {
    # An entry of bans.json as the agent writes it; anything else is dropped.
    param([string]$Key, $Ban)
    $ip = ConvertTo-IpNumber ($Key.Split('/')[0])
    if ($null -eq $ip -or (Get-FloodKey $ip) -cne $Key) { return $false }
    if ($null -eq $Ban) { return $false }
    $rule = Get-Prop $Ban 'rule'
    if ($rule -cne 'rate' -and $rule -cne 'flood') { return $false }
    foreach ($k in 'first', 'until', 'hits') {
        $v = Get-Prop $Ban $k
        if ($null -eq $v -or $v -is [bool] -or -not ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal])) { return $false }
        if ([double]$v -lt 0) { return $false }
    }
    return ((Get-Prop $Ban 'reported') -is [bool]) -and ((Get-Prop $Ban 'enforced') -is [bool])
}

function Save-AgentState {
    param($Agent)
    $state = [ordered]@{ etag = $Agent.ETag; rules = $Agent.RulesJson; running = $Agent.Running; iis = $Agent.Iis; notes = $Agent.Notes; saved = (ConvertTo-IsoTime (Get-EpochNow)) }
    Write-TextFile $Agent.StateFile (ConvertTo-Json -InputObject $state -Depth 6 -Compress)
}

function Save-AgentBans {
    param($Agent)
    $text = ConvertTo-Json -InputObject @{ bans = $Agent.Bans } -Depth 4 -Compress
    if ($text -ceq $Agent.BansSaved) { return }
    Write-TextFile $Agent.BansFile $text
    $Agent.BansSaved = $text
}

function Get-AgentLayers {
    param($Agent)
    return @($script:Layers | Where-Object { $Agent.Running[$_] })
}

function Get-AgentUserAgent {
    # " no-rate" unless something here counts requests (the dashboard warns then).
    param($Agent)
    $rate = '; no-rate'
    if ($Agent.Running['logs'] -or $Agent.Running['iis']) { $rate = '' }
    return ('analytics-platform-agent-windows/{0} (windows{1})' -f $script:AgentVersion, $rate)
}

function Get-ServerName {
    $name = ''
    try { $name = [System.Net.Dns]::GetHostName() } catch { $name = [string]$env:COMPUTERNAME }
    if ($name.Length -gt 100) { $name = $name.Substring(0, 100) }
    return $name
}

function Invoke-Collector {
    # @{ Status; Headers; Body }; Status 0 when the collector can't be reached.
    param($Config, [string]$Method, [string]$PathAndQuery, $Body = $null, [hashtable]$Headers = @{}, [string]$UserAgent = '')
    $resp = $null
    try {
        $req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create(([string]$Config.endpoint).TrimEnd('/') + $PathAndQuery)
        $req.Method = $Method
        $req.Timeout = $script:HttpTimeoutMs
        $req.ReadWriteTimeout = $script:HttpTimeoutMs
        $req.UserAgent = $UserAgent
        $req.Accept = 'application/json'
        # No "Expect: 100-continue" round trip before each report.
        $req.ServicePoint.Expect100Continue = $false
        $req.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
        $req.Headers['Authorization'] = 'Bearer ' + $Config.secret
        foreach ($k in $Headers.Keys) { $req.Headers[$k] = [string]$Headers[$k] }
        if ($null -ne $Body) {
            $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject $Body -Depth 6 -Compress))
            $req.ContentType = 'application/json'
            $req.ContentLength = $bytes.Length
            $stream = $req.GetRequestStream()
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Close()
        }
        $resp = $req.GetResponse()
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) {
            Write-AgentLog "could not reach the collector: $($_.Exception.Message)"
            return @{ Status = 0; Headers = @{}; Body = '' }
        }
    } catch {
        Write-AgentLog "could not reach the collector: $($_.Exception.Message)"
        return @{ Status = 0; Headers = @{}; Body = '' }
    }
    try {
        $headers = @{}
        foreach ($k in $resp.Headers.AllKeys) { $headers[$k.ToLowerInvariant()] = $resp.Headers[$k] }
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream(), [Text.Encoding]::UTF8)
        $text = $reader.ReadToEnd()
        $reader.Dispose()
        return @{ Status = [int]$resp.StatusCode; Headers = $headers; Body = $text }
    } catch {
        return @{ Status = 0; Headers = @{}; Body = '' }
    } finally { $resp.Close() }
}

function Invoke-RulesFetch {
    # New rules into the agent when there are some; a failure keeps the old.
    param($Agent)
    $headers = @{ 'X-Firewall-Layers' = ((Get-AgentLayers $Agent) -join ' '); 'X-Server-Name' = (Get-ServerName) }
    if ($Agent.ETag) { $headers['If-None-Match'] = $Agent.ETag }
    $res = Invoke-Collector $Agent.Config 'GET' ('/events/firewall/rules?site_id=' + $Agent.Config.site_id) $null $headers (Get-AgentUserAgent $Agent)
    if ($res.Status -eq 200) {
        try { $rules = ConvertFrom-Json $res.Body } catch { Write-AgentLog 'the collector sent rules that are not JSON: kept the old ones'; return }
        $v = Get-Prop $rules 'v'
        if (($v -is [int] -or $v -is [long]) -and $v -eq $script:ProtocolVersion) {
            $Agent.Rules = $rules
            $Agent.RulesJson = $res.Body
            $etag = ''
            if ($res.Headers.ContainsKey('etag')) { $etag = [string]$res.Headers['etag'] }
            $Agent.ETag = $etag
        } else {
            Write-AgentLog 'rules of an unknown version ignored'
        }
    } elseif ($res.Status -ne 0 -and $res.Status -ne 304) {
        Write-AgentLog "collector answered $($res.Status) to rules"
    }
}

function Add-AgentEvent {
    # Identical (ip, rule, action, method, path) are one row with hits; at
    # most MaxReportRows rows wait, the rest are dropped.
    param($Agent, [string]$Ip, [string]$Rule, [string]$Action, [string]$Method = '', [string]$Path = '', [string]$Ua = '', [long]$Hits = 1, [double]$At = 0)
    if ($Path.Length -gt 300) { $Path = $Path.Substring(0, 300) }
    $key = $Ip + '|' + $Rule + '|' + $Action + '|' + $Method + '|' + $Path
    $row = $Agent.Events[$key]
    if ($null -ne $row) { $row['hits'] = [long]$row['hits'] + $Hits; return }
    if ($Agent.Events.Count -ge $script:MaxReportRows) { return }
    if ($At -le 0) { $At = Get-EpochNow }
    $Agent.Events[$key] = [ordered]@{ at = (ConvertTo-IsoTime $At); ip = $Ip; rule = $Rule; action = $Action; method = $Method; path = $Path; user_agent = $Ua; hits = $Hits }
}

function Send-AgentEvents {
    param($Agent)
    if ($Agent.Events.Count -eq 0) { return }
    $rows = @($Agent.Events.Values)
    $Agent.Events = New-Object System.Collections.Hashtable
    for ($i = 0; $i -lt $rows.Count; $i += $script:Batch) {
        $last = [math]::Min($i + $script:Batch, $rows.Count) - 1
        $body = [ordered]@{ site_id = $Agent.Config.site_id; events = @($rows[$i..$last]) }
        $res = Invoke-Collector $Agent.Config 'POST' '/events/firewall/events' $body @{} (Get-AgentUserAgent $Agent)
        if ($res.Status -ne 200 -and $res.Status -ne 202) { Write-AgentLog "collector answered $($res.Status) to events" }
    }
}

function Set-AgentPlan {
    # The plan of the rules, and the address sets the log reader looks in.
    param($Agent)
    $of = Get-Sha256Hex ([string]$Agent.RulesJson)
    if ($Agent.Plan -and $of -ceq $Agent.PlanOf) { return }
    $p = Get-AgentPlan $Agent.Rules
    $Agent.Plan = $p
    $Agent.PlanOf = $of
    $Agent.Own = @(Get-OwnRanges)
    $local = @($script:LocalRanges | ForEach-Object { ConvertTo-IpRange $_ })
    $exempt = @($local)
    if ($p.flood) { $exempt = @($p.flood.exempt) }
    $originOk = @()
    if ($p.origin) { $originOk = @($p.origin.only) + $local + @($script:PlatformRanges | ForEach-Object { ConvertTo-IpRange $_ }) }
    $Agent.Sets = @{
        allow = New-IpSet $p.allow; deny = New-IpSet $p.deny; ban = New-IpSet $p.ban; list = New-IpSet $p.list; shared = New-IpSet $p.shared
        exempt = New-IpSet (@($exempt) + @($Agent.Own)); origin = New-IpSet (@($originOk) + @($Agent.Own))
    }
    $Agent.ClassCache = New-Object System.Collections.Hashtable
}

function Get-AddressClass {
    # What the rules say of one address (cached): its flood key, whether it's
    # exempt from the limits, the list it's on and whether the origin lock
    # keeps it out.
    param($Agent, $Ip)
    $text = Format-IpNumber $Ip.F $Ip.N
    $c = $Agent.ClassCache[$text]
    if ($null -ne $c) { return $c }
    $s = $Agent.Sets
    $list = ''
    if (-not (Test-IpSet $s.allow $Ip)) {
        if (Test-IpSet $s.deny $Ip) { $list = 'deny' }
        elseif (Test-IpSet $s.ban $Ip) { $list = 'ban' }
        elseif (Test-IpSet $s.list $Ip) { $list = 'list' }
        elseif (Test-IpSet $s.shared $Ip) { $list = 'shared' }
    }
    $c = @{ Ip = $text; Key = (Get-FloodKey $Ip); Exempt = (Test-IpSet $s.exempt $Ip); List = $list
        Outside = ($null -ne $Agent.Plan.origin -and -not $Agent.OriginBlock -and -not (Test-IpSet $s.origin $Ip)) }
    if ($Agent.ClassCache.Count -ge $script:ClassCacheMax) { $Agent.ClassCache = New-Object System.Collections.Hashtable }
    $Agent.ClassCache[$text] = $c
    return $c
}

function Add-AgentBan {
    # An address (or /64) over a limit: banned in Windows Firewall when it can
    # be (block mode), else only watched; reported once either way.
    param($Agent, [string]$Key, [string]$Rule, [double]$Now)
    $b = $Agent.Bans[$Key]
    if ($null -ne $b -and $b.until -gt $Now) { $b.hits = [long]$b.hits + 1; return }
    if ($Agent.Bans.Count -ge $script:BansMax) {
        # A tenth at once, the soonest to end: one sort per many bans, not per ban.
        $drop = [math]::Max(1, [int]($script:BansMax / 10))
        foreach ($k in @($Agent.Bans.Keys | Sort-Object { $Agent.Bans[$_].until } | Select-Object -First $drop)) { $Agent.Bans.Remove($k) }
    }
    $length = $script:FloodBanDefault
    if ($Agent.Plan.flood) { $length = [double]$Agent.Plan.flood.ban }
    $Agent.Bans[$Key] = @{ rule = $Rule; first = $Now; until = $Now + $length; hits = [long]1; reported = $false
        enforced = [bool]($Agent.Plan.block -and $Agent.FwUsable) }
}

function Invoke-LogEntry {
    # One logged request: the browser check's, IIS's limits', a watched list
    # match (monitor mode), and the page limit.
    param($Agent, $Entry, [double]$Now)
    $p = $Agent.Plan
    if ($null -eq $p -or -not $p.enabled) { return }
    $c = Get-AddressClass $Agent $Entry.Ip
    $sub = $Agent.Config.check_substatus
    if ($Entry.Status -eq 503 -and $Entry.SubStatus -eq $sub) {
        if ($Agent.Challenged.ContainsKey($c.Ip)) { $Agent.Challenged[$c.Ip] = $Agent.Challenged[$c.Ip] + 1 }
        elseif ($Agent.Challenged.Count -lt 10000) { $Agent.Challenged[$c.Ip] = 1 }
        return
    }
    if ($p.block -and ($Entry.SubStatus -eq 501 -or $Entry.SubStatus -eq 502) -and @(401, 403, 404) -contains $Entry.Status) {
        # Turned away by IIS's Dynamic IP Restrictions (501 too many at once,
        # 502 too fast). IIS counts images and scripts too, so this is no page
        # limit: nothing is banned for it, and it is reported as `flood`,
        # `monitor`, which the collector neither bans on the site's other
        # servers nor shares (firewall.md: only `block` events do).
        if (-not $c.Exempt) { Add-IisDenied $Agent $c.Key $Now }
        return
    }
    if (-not $p.block) {
        if ($c.List) { Add-AgentEvent $Agent $c.Ip $c.List 'monitor' $Entry.Method $Entry.Path $Entry.Ua 1 $Now }
        if ($c.Outside) { Add-AgentEvent $Agent $c.Key 'origin' 'monitor' '' '' '' 1 $Now }
    }
    $f = $p.flood
    if ($null -eq $f -or -not $f.req_rate -or -not $Agent.Config.logs -or $c.Exempt) { return }
    if ($script:StaticRegex.IsMatch($Entry.Path)) { return }
    $b = $Agent.Bans[$c.Key]
    if ($null -ne $b -and $b.until -gt $Now) { $b.hits = [long]$b.hits + 1; return }
    $t = $Entry.Time
    if ($t -le 0) { $t = $Now }
    if (-not (Test-TokenBucket $Agent.Buckets $c.Key $t ([double]$f.req_rate) ([double]$f.req_burst + 1))) {
        Add-AgentBan $Agent $c.Key 'rate' $Now
    }
}

function Add-IisDenied {
    param($Agent, [string]$Key, [double]$Now)
    $d = $Agent.IisDenied[$Key]
    if ($null -ne $d -and $d.until -gt $Now) { $d.hits = [long]$d.hits + 1; return }
    if ($Agent.IisDenied.Count -ge $script:IisDeniedMax) {
        $drop = [math]::Max(1, [int]($script:IisDeniedMax / 10))
        foreach ($k in @($Agent.IisDenied.Keys | Sort-Object { $Agent.IisDenied[$_].until } | Select-Object -First $drop)) { $Agent.IisDenied.Remove($k) }
    }
    $length = $script:FloodBanDefault
    if ($Agent.Plan.flood) { $length = [double]$Agent.Plan.flood.ban }
    $Agent.IisDenied[$Key] = @{ first = $Now; until = $Now + $length; hits = [long]1; reported = $false }
}

function Get-DueBans {
    # Each ban reported once: BanReportAfter after it started, or when it ends
    # if sooner. Ended ones go BanSlack later.
    param($Agent, [double]$Now)
    foreach ($k in @($Agent.Bans.Keys)) {
        $b = $Agent.Bans[$k]
        if (-not $b.reported -and ($b.until -le $Now -or $Now - $b.first -ge $script:BanReportAfter)) {
            $action = 'monitor'
            if ($b.enforced) { $action = 'block' }
            Add-AgentEvent $Agent $k $b.rule $action '' '' '' ([math]::Max(1, [long]$b.hits)) $b.first
            $b.reported = $true
        }
        if ($b.until + $script:BanSlack -le $Now) { $Agent.Bans.Remove($k) }
    }
    foreach ($k in @($Agent.IisDenied.Keys)) {
        $d = $Agent.IisDenied[$k]
        if (-not $d.reported -and ($d.until -le $Now -or $Now - $d.first -ge $script:BanReportAfter)) {
            Add-AgentEvent $Agent $k 'flood' 'monitor' '' '' '' ([math]::Max(1, [long]$d.hits)) $d.first
            $d.reported = $true
        }
        if ($d.until -le $Now) { $Agent.IisDenied.Remove($k) }
    }
}

function Get-EnforcedBanKeys {
    param($Agent, [double]$Now)
    return @($Agent.Bans.Keys | Where-Object { $Agent.Bans[$_].enforced -and $Agent.Bans[$_].until -gt $Now } | Sort-Object)
}

function Update-Firewall {
    # Our rules in Windows Firewall as the plan (and the bans) say, changed in
    # place. -BansOnly: only the ban rules, from what was read last.
    param($Agent, [double]$Now, [switch]$BansOnly)
    $cfg = $Agent.Config
    $p = $Agent.Plan
    $kinds = @('Lists', 'Bans', 'Origin')
    if ($BansOnly) { $kinds = @('Bans') }
    $current = $null
    if ($BansOnly -and $null -ne $Agent.FwCurrent) { $current = $Agent.FwCurrent } else { $current = Get-FirewallRules }
    if ($null -eq $current) {
        $Agent.FwCurrent = $null
        $Agent.FwUsable = $false
        $Agent.Running['windows-firewall'] = $false
        $Agent.Running['origin'] = $false
        return $false
    }
    $current = @($current)
    $banKeys = @(Get-EnforcedBanKeys $Agent $Now)
    $wantPlan = $p
    if ($p -and $p.origin -and $Agent.OriginBlock) {
        # Something other than the site answers on the web ports (see
        # Get-OriginConflicts): the lock would cut it off, so it isn't put in place.
        $wantPlan = $p.Clone()
        $wantPlan.origin = $null
    }
    if (-not $cfg.windows_firewall -or @($cfg.ports).Count -eq 0) { $wantPlan = $null }
    $wanted = Get-FirewallWanted $wantPlan $banKeys $Agent.Own
    $desired = Get-FirewallDesired $wanted $current $cfg.ports $cfg.firewall_chunk $kinds
    $ops = @(Get-FirewallOps $desired $current $kinds)
    $failed = @{}
    if ($ops.Count -gt 0) {
        $results = @(Invoke-FirewallBatch $ops)
        $byName = @{}
        foreach ($r in $current) { $byName[$r.Name] = $r }
        foreach ($r in $results) {
            $op = @($ops | Where-Object { $_.Name -ceq $r.Name })[0]
            if (-not $r.Ok) {
                $failed[$r.Name] = $true
                Write-AgentLog ("firewall rule {0} not changed ({1}): {2}" -f $r.Name, $op.Op, $r.Error)
                continue
            }
            if ($op.Op -eq 'Remove') { $byName.Remove($r.Name) }
            else {
                $byName[$r.Name] = [pscustomobject]@{ Name = $op.Name; Protocol = $op.Protocol; Ports = @($op.Ports | ForEach-Object { [string]$_ })
                    Remote = @($op.Addresses); Action = 'Block'; Direction = 'Inbound'; Enabled = 'True' }
            }
        }
        $Agent.FwCurrent = @($byName.Values)
        $news = @($ops | Where-Object { $_.Op -ne 'Remove' -and -not $failed.ContainsKey($_.Name) }).Count
        $gone = @($ops | Where-Object { $_.Op -eq 'Remove' -and -not $failed.ContainsKey($_.Name) }).Count
        if ($news + $gone -gt 0) { Write-AgentLog ("Windows Firewall: {0} rule(s) written, {1} removed" -f $news, $gone) }
    } else {
        $Agent.FwCurrent = $current
    }
    if ($BansOnly) { return ($failed.Count -eq 0) }
    $why = Test-FirewallEnforces (Get-FirewallInfo)
    $Agent.FwUsable = [bool]($cfg.windows_firewall -and -not $why -and @($cfg.ports).Count -gt 0)
    Write-AgentNote $Agent 'firewall' $why
    $listsOk = @($failed.Keys | Where-Object { $_ -match '-Lists-' }).Count -eq 0
    $originOk = @($failed.Keys | Where-Object { $_ -match '-Origin-' }).Count -eq 0
    $Agent.Running['windows-firewall'] = [bool]($p.block -and $Agent.FwUsable -and $listsOk)
    $Agent.Running['origin'] = [bool]($p.block -and $p.origin -and -not $Agent.OriginBlock -and $Agent.FwUsable -and $originOk)
    return ($failed.Count -eq 0)
}

function Get-IisLimitsRestore {
    # The changes that take the agent's IIS request limits away: the owner's
    # own values back, and the allow entries the agent added out.
    param($Agent, $Snap)
    $changes = New-Object System.Collections.ArrayList
    $present = @()
    if ($Snap.IpSecurity) { $present = @($Snap.IpSecurity.Entries) }
    foreach ($key in @($Agent.Iis.allow_added)) {
        if ($present -contains $key) {
            $two = $key.Split('|')
            [void]$changes.Add(@{ Op = 'Remove'; Section = 'system.webServer/security/ipSecurity'; Child = ''; Key = @{ ipAddress = $two[0]; subnetMask = $two[1] } })
        }
    }
    if ($Agent.Iis.dipr_ours) {
        $orig = $Agent.Iis.dipr_original
        if ($null -eq $orig) {
            $orig = @{ denyAction = 'Forbidden'; enableLoggingOnlyMode = $false; rateEnabled = $false; maxRequests = 20; intervalMs = 200; concEnabled = $false; maxConcurrent = 5 }
        }
        foreach ($c in @(Get-DiprChanges $orig)) { [void]$changes.Add($c) }
    }
    return $changes.ToArray()
}

function Update-IisLimits {
    # IIS's Dynamic IP Restrictions at server level, from flood, in block mode,
    # with the exempt ranges as allow entries; taken away otherwise.
    param($Agent)
    $p = $Agent.Plan
    $cfg = $Agent.Config
    $want = [bool]($cfg.iis_limits -and $p -and $p.block -and $p.flood -and ($p.flood.req_rate -or $p.flood.conn_max))
    $snap = Get-IisSnapshot $cfg
    $Agent.LastSnap = $snap
    $Agent.ProbeTargets = @(Get-ProbeTargets $snap $cfg.ports)
    $ours = [bool]$Agent.Iis.dipr_ours -or @($Agent.Iis.allow_added).Count -gt 0
    $digest = Get-IpPathsDigest $snap
    $held = [bool]($Agent.Iis.limits_held -and $Agent.Iis.limits_held -ceq $digest)
    if (-not $held) { $Agent.Iis.limits_held = '' }
    $why = ''
    if ($want -and $p.origin) {
        # Locked to the origin, every visitor comes through the proxy's exempt
        # addresses: IIS's limits would add only the risk of limiting them.
        $why = "IIS request limits left off while the site is locked to its origin (origin.only): every visitor then comes through the proxy's exempt addresses"
    } elseif ($want) {
        $why = Get-IisLimitsBlocker $snap ([bool]$Agent.Iis.dipr_ours) (Test-PublicIPv6 $Agent.Own) $held
    }
    if (-not $want -or $why) {
        if ($want) { Write-AgentNote $Agent 'iis' $why } else { Write-AgentNote $Agent 'iis' '' }
        if ($ours -and $snap.Installed -and -not $snap.Error -and $snap.Dipr) {
            if (Invoke-IisCommit (Get-IisLimitsRestore $Agent $snap) $Agent) {
                $Agent.Iis.dipr_ours = $false; $Agent.Iis.dipr_original = $null; $Agent.Iis.allow_added = @()
                Save-AgentState $Agent
                Write-AgentLog 'IIS request limits taken away: the earlier settings are back'
            }
        }
        $Agent.Running['iis'] = $false
        return
    }
    $desired = Get-DiprDesired $p.flood
    $entries = @(Get-ExemptAllowEntries $p.flood.exempt)
    $wantedKeys = @($entries | ForEach-Object { $_.Key })
    $present = @($snap.IpSecurity.Entries)
    $changes = New-Object System.Collections.ArrayList
    $added = New-Object System.Collections.ArrayList
    foreach ($key in @($Agent.Iis.allow_added)) {
        if ($wantedKeys -contains $key -and $present -contains $key) { [void]$added.Add($key) }
        elseif ($present -contains $key) {
            $two = $key.Split('|')
            [void]$changes.Add(@{ Op = 'Remove'; Section = 'system.webServer/security/ipSecurity'; Child = ''; Key = @{ ipAddress = $two[0]; subnetMask = $two[1] } })
        }
    }
    foreach ($e in $entries) {
        # One already there is the owner's (or ours): never added twice, never ours to remove.
        if ($present -contains $e.Key) { continue }
        # Allow entries go first: IIS takes the first entry that matches, and
        # the agent's own deny entries (bans) come last.
        [void]$changes.Add(@{ Op = 'Add'; Section = 'system.webServer/security/ipSecurity'; Child = ''; Index = 0
                Item = @{ Tag = 'add'; Attrs = [ordered]@{ ipAddress = $e.ipAddress; subnetMask = $e.subnetMask; allowed = $true } } })
        [void]$added.Add($e.Key)
    }
    if (-not (Test-DiprSame $snap.Dipr $desired)) { foreach ($c in @(Get-DiprChanges $desired)) { [void]$changes.Add($c) } }
    if (-not $Agent.Iis.dipr_ours) {
        # Saved before the first write, so the owner's values can go back.
        $Agent.Iis.dipr_original = $snap.Dipr
        $Agent.Iis.dipr_ours = $true
        Save-AgentState $Agent
    }
    if ($changes.Count -gt 0) {
        if (-not (Invoke-IisCommit $changes.ToArray() $Agent)) {
            Write-AgentNote $Agent 'iis' 'IIS request limits not changed (see above)'
            $Agent.Running['iis'] = $false
            return
        }
        $Agent.Iis.allow_added = @($added.ToArray())
        Save-AgentState $Agent
        Write-AgentLog ('IIS request limits in place: {0} requests in 10 s and {1} at once per address, {2} exempt ranges' -f
            $desired.maxRequests, $desired.maxConcurrent, $wantedKeys.Count)
        $snap = Get-IisSnapshot $cfg
        $Agent.LastSnap = $snap
    } else {
        $Agent.Iis.allow_added = @($added.ToArray())
    }
    # The check before writing can't see a <clear/> while the server had no
    # entries at all. Seen now: the limits go, and stay off (held) until the
    # sites' configuration changes, rather than going on and off every round.
    foreach ($path in @($snap.Paths)) {
        if (-not $path.ContainsKey('IpEntries')) { continue }
        $have = @($path.IpEntries)
        $missing = @($wantedKeys | Where-Object { $have -notcontains $_ })
        if ($missing.Count -gt 0) {
            Write-AgentNote $Agent 'iis' ("{0}{1} clears the server's IP restrictions, so the exempt ranges wouldn't be exempt there: IIS request limits taken away" -f $path.Site, $path.Path)
            $Agent.Iis.limits_held = Get-IpPathsDigest $snap
            if (Invoke-IisCommit (Get-IisLimitsRestore $Agent $snap) $Agent) {
                $Agent.Iis.dipr_ours = $false; $Agent.Iis.dipr_original = $null; $Agent.Iis.allow_added = @()
            }
            Save-AgentState $Agent
            $Agent.Running['iis'] = $false
            return
        }
    }
    Write-AgentNote $Agent 'iis' ''
    $Agent.Running['iis'] = $true
}

function Get-IisBanChanges {
    # IIS ipSecurity deny entries for the bans in force (IPv4, the latest
    # IisDenyMax): a ban then also stops requests on connections that were
    # open before the Windows Firewall rule. Entries the owner has are never
    # added or removed. @{ Changes; Mine }.
    param($Agent, $Snap, [double]$Now)
    $section = 'system.webServer/security/ipSecurity'
    $present = @()
    if ($Snap -and $Snap.IpSecurity) { $present = @($Snap.IpSecurity.Entries) }
    $wanted = New-Object System.Collections.ArrayList
    $bans = @(Get-EnforcedBanKeys $Agent $Now | Where-Object { $_ -notmatch '[:/]' } | Sort-Object { $Agent.Bans[$_].until } -Descending | Select-Object -First $script:IisDenyMax)
    foreach ($k in $bans) { [void]$wanted.Add((Get-IpSecurityKey $k '255.255.255.255')) }
    $changes = New-Object System.Collections.ArrayList
    $mine = New-Object System.Collections.ArrayList
    foreach ($key in @($Agent.Iis.deny_added)) {
        if ($present -notcontains $key) { continue }
        if ($wanted -contains $key) { [void]$mine.Add($key); continue }
        $two = $key.Split('|')
        [void]$changes.Add(@{ Op = 'Remove'; Section = $section; Child = ''; Key = @{ ipAddress = $two[0]; subnetMask = $two[1] } })
    }
    foreach ($key in $wanted) {
        if ($present -contains $key) { continue }
        $two = $key.Split('|')
        [void]$changes.Add(@{ Op = 'Add'; Section = $section; Child = ''; Index = -1
                Item = @{ Tag = 'add'; Attrs = [ordered]@{ ipAddress = $two[0]; subnetMask = $two[1]; allowed = $false } } })
        [void]$mine.Add($key)
    }
    return @{ Changes = @($changes.ToArray()); Mine = @($mine.ToArray()) }
}

function Update-IisBans {
    # The bans as IIS deny entries, as far as IIS's IP restrictions are there
    # and deny no one unlisted; at most every IisBansEvery seconds.
    param($Agent, [double]$Now)
    $snap = $Agent.LastSnap
    if ($null -eq $snap -or -not $snap.Installed -or $snap.Error) { return }
    $usable = [bool]($Agent.Config.iis_limits -and @($snap.Modules) -contains 'IpRestrictionModule' -and $snap.IpSecurity -and $snap.IpSecurity.AllowUnlisted)
    if (-not $usable -and @($Agent.Iis.deny_added).Count -eq 0) { return }
    $plan = Get-IisBanChanges $Agent $snap $Now
    if (-not $usable) { $plan = Get-IisBanChanges @{ Bans = @{}; Iis = $Agent.Iis } $snap $Now }
    $Agent.IisBansAt = $Now
    if (@($plan.Changes).Count -eq 0) { $Agent.Iis.deny_added = @($plan.Mine); return }
    if (Invoke-IisCommit $plan.Changes $Agent -NoProbe) {
        $Agent.Iis.deny_added = @($plan.Mine)
        # What IIS now holds, without reading it all again.
        $entries = New-Object System.Collections.ArrayList
        foreach ($e in @($snap.IpSecurity.Entries)) { [void]$entries.Add($e) }
        foreach ($c in $plan.Changes) {
            if ($c.Op -eq 'Add') { [void]$entries.Add((Get-IpSecurityKey $c.Item.Attrs.ipAddress $c.Item.Attrs.subnetMask)) }
            else { [void]$entries.Remove((Get-IpSecurityKey $c.Key.ipAddress $c.Key.subnetMask)) }
        }
        $snap.IpSecurity.Entries = @($entries.ToArray())
        Save-AgentState $Agent
    }
}

function Get-IisCheckRemoval {
    # The changes that take the browser check out of IIS: the rule, the
    # outbound rules and their precondition, the server variable if the agent
    # added it, and every 503 error page entry pointing at the check page,
    # whatever its sub-status.
    param($Agent, $Snap, [string]$PagePath)
    $changes = New-Object System.Collections.ArrayList
    if (@($Snap.GlobalRules) -contains $script:CheckRuleName) {
        [void]$changes.Add(@{ Op = 'Remove'; Section = 'system.webServer/rewrite/globalRules'; Child = ''; Key = @{ name = $script:CheckRuleName } })
    }
    foreach ($o in $script:CheckOutbound) {
        if (@($Snap.OutboundRules) -contains $o.Name) {
            [void]$changes.Add(@{ Op = 'Remove'; Section = 'system.webServer/rewrite/outboundRules'; Child = ''; Key = @{ name = $o.Name } })
        }
    }
    if (@($Snap.PreConditions) -contains $script:CheckPreCondition) {
        [void]$changes.Add(@{ Op = 'Remove'; Section = 'system.webServer/rewrite/outboundRules'; Child = 'preConditions'; Key = @{ name = $script:CheckPreCondition } })
    }
    if ($Agent.Iis.check_added_variable -and @($Snap.ServerVariables) -contains $script:CheckVariable) {
        [void]$changes.Add(@{ Op = 'Remove'; Section = 'system.webServer/rewrite/allowedServerVariables'; Child = ''; Key = @{ name = $script:CheckVariable } })
    }
    foreach ($sub in @(Get-CheckPageEntries $Agent $Snap $PagePath)) {
        [void]$changes.Add(@{ Op = 'Remove'; Section = 'system.webServer/httpErrors'; Child = ''; Key = @{ statusCode = 503; subStatusCode = $sub } })
    }
    return $changes.ToArray()
}

function Get-CheckPageEntries {
    # The sub-statuses of the 503 error page entries that point at the check
    # page (this one, or the one an earlier run wrote).
    param($Agent, $Snap, [string]$PagePath)
    $pages = @($PagePath.ToLowerInvariant())
    if ($Agent.Iis.check_page) { $pages += ([string]$Agent.Iis.check_page).ToLowerInvariant() }
    $subs = New-Object System.Collections.ArrayList
    foreach ($key in @($Snap.HttpErrors)) {
        if (-not ($key -match '^503\.([0-9]+)\|(.*)$')) { continue }
        $sub = [int]$Matches[1]
        if ($pages -contains $Matches[2] -and -not $subs.Contains($sub)) { [void]$subs.Add($sub) }
    }
    return @($subs.ToArray())
}

function Get-IisCheckSupportChanges {
    # The error page, the server variable and the outbound header rules, as
    # far as they're missing. Conflict: the owner's own 503.<sub> page.
    param($Agent, $Snap, [string]$PagePath)
    $sub = $Agent.Config.check_substatus
    $support = Get-CheckSupport $PagePath $sub
    $changes = New-Object System.Collections.ArrayList
    $mine = Get-HttpErrorKey 503 $sub $PagePath
    # The page's entry under an earlier check_substatus goes.
    foreach ($old in @(Get-CheckPageEntries $Agent $Snap $PagePath)) {
        if ($old -ne $sub) { [void]$changes.Add(@{ Op = 'Remove'; Section = 'system.webServer/httpErrors'; Child = ''; Key = @{ statusCode = 503; subStatusCode = $old } }) }
    }
    if (@($Snap.HttpErrors) -notcontains $mine) {
        $prefix = ('503.{0}|' -f $sub)
        $other = @($Snap.HttpErrors | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
        if ($other.Count -gt 0) {
            $previous = ''
            if ($Agent.Iis.check_page) { $previous = Get-HttpErrorKey 503 $sub $Agent.Iis.check_page }
            if (-not $previous -or $other -notcontains $previous) {
                return @{ Conflict = ("IIS already has an error page for 503.{0}: set check_substatus to an unused number in the agent's config" -f $sub); Changes = @() }
            }
            [void]$changes.Add(@{ Op = 'Remove'; Section = 'system.webServer/httpErrors'; Child = ''; Key = @{ statusCode = 503; subStatusCode = $sub } })
        }
        [void]$changes.Add(@{ Op = 'Add'; Section = 'system.webServer/httpErrors'; Child = ''; Index = -1; Item = $support.HttpError })
    }
    $addVariable = $false
    if (@($Snap.ServerVariables) -notcontains $script:CheckVariable) {
        [void]$changes.Add(@{ Op = 'Add'; Section = 'system.webServer/rewrite/allowedServerVariables'; Child = ''; Index = -1; Item = $support.Variable })
        $addVariable = $true
    }
    $outboundDigest = Get-Sha256Hex ((@($support.Outbound | ForEach-Object { ConvertTo-ConfigXml $_ }) -join "`n") + (ConvertTo-ConfigXml @{ Tag = 'p'; Attrs = $support.PreCondition.Attrs }))
    $haveAll = (@($Snap.PreConditions) -contains $script:CheckPreCondition) -and
        (@($script:CheckOutbound | Where-Object { @($Snap.OutboundRules) -notcontains $_.Name }).Count -eq 0)
    if (-not $haveAll -or $Agent.Iis.check_outbound_digest -cne $outboundDigest) {
        foreach ($o in $script:CheckOutbound) {
            if (@($Snap.OutboundRules) -contains $o.Name) {
                [void]$changes.Add(@{ Op = 'Remove'; Section = 'system.webServer/rewrite/outboundRules'; Child = ''; Key = @{ name = $o.Name } })
            }
        }
        if (@($Snap.PreConditions) -contains $script:CheckPreCondition) {
            [void]$changes.Add(@{ Op = 'Remove'; Section = 'system.webServer/rewrite/outboundRules'; Child = 'preConditions'; Key = @{ name = $script:CheckPreCondition } })
        }
        [void]$changes.Add(@{ Op = 'Add'; Section = 'system.webServer/rewrite/outboundRules'; Child = 'preConditions'; Index = -1; Item = $support.PreCondition })
        foreach ($o in $support.Outbound) { [void]$changes.Add(@{ Op = 'Add'; Section = 'system.webServer/rewrite/outboundRules'; Child = ''; Index = -1; Item = $o }) }
    }
    return @{ Conflict = ''; Changes = $changes.ToArray(); AddVariable = $addVariable; OutboundDigest = $outboundDigest }
}

function Write-CheckPage {
    # The day's check page, where IIS's error page points. Whether IIS's
    # worker processes can read it is checked every time (not only when the
    # folder is new) and put right when it can be: $true when they can.
    param($Agent, [string]$Token)
    $dir = $Agent.Config.page_dir
    $path = Join-Path $dir 'check.html'
    if (Test-ReparsePoint $dir) { Write-AgentLog "$dir is a link to elsewhere: no check page written"; return $false }
    $page = Get-CheckPage $Token
    if (-not ((Test-Path -LiteralPath $path) -and ([IO.File]::ReadAllText($path) -ceq $page))) { Write-TextFile $path $page }
    if (Test-PageReadable (Get-PageReaders $path)) { return $true }
    if ($env:windir) {
        $icacls = Join-Path $env:windir 'System32\icacls.exe'
        foreach ($target in @(@($dir, '*S-1-5-32-568:(OI)(CI)RX', '*S-1-5-17:(OI)(CI)RX'), @($path, '*S-1-5-32-568:R', '*S-1-5-17:R'))) {
            $r = Invoke-External $icacls @($target[0], '/grant', $target[1], '/grant', $target[2])
            if ($r.Code -ne 0) { Write-AgentLog "could not let IIS read $($target[0]): $($r.Err)" }
        }
    }
    return (Test-PageReadable (Get-PageReaders $path))
}

function Test-ReparsePoint {
    # Whether a path that exists is a junction or symbolic link.
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $false }
    try { return ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 } catch { return $true }
}

function Get-PageReaders {
    # The SIDs a file's ACL lets read it, and those it denies: @{ Allow; Deny },
    # or $null where there is no Windows ACL to read.
    param([string]$Path)
    if (-not $env:windir) { return $null }
    try { $acl = Get-Acl -LiteralPath $Path } catch { return @{ Allow = @(); Deny = @() } }
    $allow = New-Object System.Collections.ArrayList
    $deny = New-Object System.Collections.ArrayList
    foreach ($rule in $acl.Access) {
        $rights = [long][int]$rule.FileSystemRights
        # ReadData (1), or GENERIC_READ / GENERIC_ALL.
        if (($rights -band 1) -eq 0 -and ($rights -band 0x80000000) -eq 0 -and ($rights -band 0x10000000) -eq 0) { continue }
        try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { continue }
        if ([string]$rule.AccessControlType -eq 'Deny') { [void]$deny.Add($sid) } else { [void]$allow.Add($sid) }
    }
    return @{ Allow = @($allow.ToArray()); Deny = @($deny.ToArray()) }
}

function Test-PageReadable {
    # IIS's worker processes (IIS_IUSRS) and anonymous visitors (IUSR) can read
    # it, directly or through Users, Authenticated Users or Everyone, and none
    # of them is denied. With no ACL to read (not Windows): yes.
    param($Readers)
    if ($null -eq $Readers) { return (-not $env:windir) }
    $broad = @('S-1-5-32-545', 'S-1-5-11', 'S-1-1-0')
    foreach ($sid in @($Readers.Deny)) { if (@($broad + 'S-1-5-32-568', 'S-1-5-17') -contains $sid) { return $false } }
    $allow = @($Readers.Allow)
    foreach ($sid in $broad) { if ($allow -contains $sid) { return $true } }
    return ($allow -contains 'S-1-5-32-568' -and $allow -contains 'S-1-5-17')
}

function Update-IisCheck {
    # The browser check in IIS while the rules carry `challenge`: the page,
    # the error page entry and header rules, then the global rule for the
    # sites where the page is shown for sure. Taken out otherwise.
    param($Agent, [double]$Now)
    $cfg = $Agent.Config
    $p = $Agent.Plan
    $pagePath = Join-Path $cfg.page_dir 'check.html'
    $want = [bool]($cfg.iis_check -and $p -and $p.challenge)
    $snap = Get-IisSnapshot $cfg
    if ($snap.Installed -and -not $snap.Error) { $Agent.ProbeTargets = @(Get-ProbeTargets $snap $cfg.ports) }
    if (-not $want) {
        Write-AgentNote $Agent 'check' ''
        [void](Remove-IisCheck $Agent $snap $pagePath)
        $Agent.Running['iis-check'] = $false
        return
    }
    $why = ''
    if (-not $snap.Installed) { $why = "IIS isn't installed here: no browser check" }
    elseif ($snap.Error) { $why = "IIS's configuration can't be read ($($snap.Error)): no browser check" }
    elseif (@($snap.Modules) -notcontains 'RewriteModule') { $why = "IIS URL Rewrite isn't installed (https://www.iis.net/downloads/microsoft/url-rewrite): no browser check in IIS" }
    if ($why) { Write-AgentNote $Agent 'check' $why; $Agent.Running['iis-check'] = $false; return }
    $day = Get-UtcDay $Now
    $tokens = @((Get-ChallengeToken $cfg.secret $day), (Get-ChallengeToken $cfg.secret ($day - 1)))
    # The page already out keeps its pass until the rule takes the new one.
    $pageToken = $tokens[0]
    if ((Test-Path -LiteralPath $pagePath) -and $Agent.Iis.check_day -ge 0 -and $Agent.Iis.check_day -ne $day) {
        $pageToken = Get-ChallengeToken $cfg.secret $Agent.Iis.check_day
    }
    $readable = Write-CheckPage $Agent $pageToken
    if (-not $readable) {
        Write-AgentNote $Agent 'check' "IIS's worker processes can't read $pagePath (IIS_IUSRS and IUSR need read access): no browser check, or every checked visitor would get a bare 503"
        Remove-IisCheckRule $Agent $snap
        $Agent.Running['iis-check'] = $false
        return
    }
    $support = Get-IisCheckSupportChanges $Agent $snap $pagePath
    if ($support.Conflict) {
        Write-AgentNote $Agent 'check' $support.Conflict
        Remove-IisCheckRule $Agent $snap
        $Agent.Running['iis-check'] = $false
        return
    }
    if (@($support.Changes).Count -gt 0) {
        if (-not (Invoke-IisCommit $support.Changes $Agent)) {
            Write-AgentNote $Agent 'check' 'the browser check could not be set up in IIS (see above)'
            $Agent.Running['iis-check'] = $false
            return
        }
        if ($support.AddVariable) { $Agent.Iis.check_added_variable = $true }
        $Agent.Iis.check_outbound_digest = $support.OutboundDigest
        $Agent.Iis.check_page = $pagePath
        Save-AgentState $Agent
        $snap = Get-IisSnapshot $cfg
    }
    $sites = Get-CheckSites $snap $pagePath $cfg.check_substatus $cfg.ports
    $skippedNote = ''
    if (@($sites.Skipped).Count -gt 0) { $skippedNote = 'no browser check on ' + (@($sites.Skipped) -join '; ') }
    if (@($sites.Ids).Count -eq 0) {
        if (-not $skippedNote) { $skippedNote = 'no IIS site on the web ports to give the browser check' }
        Write-AgentNote $Agent 'check' $skippedNote
        Remove-IisCheckRule $Agent $snap
        $Agent.Running['iis-check'] = $false
        return
    }
    Write-AgentNote $Agent 'check' $skippedNote
    # Never the server's own addresses: its requests to itself (health
    # checks, warm-up, cron jobs calling its own pages) have no browser.
    $challenge = @{ skip = @($p.challenge.skip); exempt = @(Merge-IpRanges (@($p.challenge.exempt) + @($Agent.Own))) }
    $rule = Get-CheckRule $challenge $tokens $sites.Ids $cfg.check_substatus
    $digest = Get-Sha256Hex (ConvertTo-ConfigXml $rule)
    $index = [array]::IndexOf(@($snap.GlobalRules), $script:CheckRuleName)
    if ($index -ne 0 -or $Agent.Iis.check_rule_digest -cne $digest) {
        # First of the global rules, so no rule of the owner's stops before it.
        $changes = @()
        if ($index -ge 0) { $changes += @{ Op = 'Remove'; Section = 'system.webServer/rewrite/globalRules'; Child = ''; Key = @{ name = $script:CheckRuleName } } }
        $changes += @{ Op = 'Add'; Section = 'system.webServer/rewrite/globalRules'; Child = ''; Index = 0; Item = $rule }
        if (-not (Invoke-IisCommit $changes $Agent)) {
            Write-AgentNote $Agent 'check' 'the browser check rule could not be written to IIS (see above)'
            $Agent.Running['iis-check'] = ($index -ge 0 -and [bool]$Agent.Iis.check_rule_digest)
            return
        }
        $Agent.Iis.check_rule_digest = $digest
        Write-AgentLog ('browser check in IIS for {0} site(s), {1} skipped' -f @($sites.Ids).Count, @($sites.Skipped).Count)
    }
    # The rule takes today's and yesterday's pass first, then the page hands
    # out today's: a visitor never holds a pass the rule refuses.
    if (-not (Write-CheckPage $Agent $tokens[0])) {
        Write-AgentNote $Agent 'check' "IIS's worker processes can't read $pagePath`: no browser check"
        Remove-IisCheckRule $Agent $snap
        $Agent.Running['iis-check'] = $false
        return
    }
    $Agent.Iis.check_day = $day
    $Agent.Running['iis-check'] = $true
}

function Remove-IisCheckRule {
    # Only the global rule (the rest does nothing without it).
    param($Agent, $Snap)
    if (@($Snap.GlobalRules) -notcontains $script:CheckRuleName) { $Agent.Iis.check_rule_digest = ''; return }
    if (Invoke-IisCommit @(@{ Op = 'Remove'; Section = 'system.webServer/rewrite/globalRules'; Child = ''; Key = @{ name = $script:CheckRuleName } }) $Agent) {
        $Agent.Iis.check_rule_digest = ''
    }
}

function Remove-IisCheck {
    # Everything of the browser check out of IIS, then the page. The page goes
    # only once nothing in IIS can point a visitor at it: a rule left behind
    # with no page would be a bare 503. $true when all of it is gone.
    param($Agent, $Snap, [string]$PagePath)
    $gone = -not $Snap.Installed
    if ($Snap.Installed -and -not $Snap.Error) {
        $changes = @(Get-IisCheckRemoval $Agent $Snap $PagePath)
        if ($changes.Count -eq 0) { $gone = $true }
        elseif (Invoke-IisCommit $changes $Agent) {
            $gone = $true
            $Agent.Iis.check_rule_digest = ''; $Agent.Iis.check_outbound_digest = ''; $Agent.Iis.check_added_variable = $false
            Write-AgentLog 'browser check taken out of IIS'
        }
    }
    if ($gone -and (Test-Path -LiteralPath $PagePath)) { Remove-Item -LiteralPath $PagePath -Force -ErrorAction SilentlyContinue }
    return $gone
}

function Update-LogSources {
    # Which IIS log folders are read, and whether the page limit runs.
    param($Agent)
    $cfg = $Agent.Config
    $p = $Agent.Plan
    $need = [bool]($p -and $p.enabled -and ($p.flood -or $p.challenge -or $p.origin -or -not $p.block))
    $dirs = @()
    if ($need) {
        if (@($cfg.iis_log_dirs).Count -gt 0) { $dirs = @($cfg.iis_log_dirs) }
        elseif ($Agent.LastSnap -and @($Agent.LastSnap.LogDirs).Count -gt 0) { $dirs = @($Agent.LastSnap.LogDirs) }
        else {
            $drive = $env:SystemDrive
            if (-not $drive) { $drive = 'C:' }
            $root = Join-Path $drive 'inetpub\logs\LogFiles'
            $dirs = @(Get-ChildItem -LiteralPath $root -Directory -Filter 'W3SVC*' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        }
        $dirs = @($dirs | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 200)
    }
    foreach ($d in @($Agent.Tails.Keys)) { if ($dirs -notcontains $d) { $Agent.Tails.Remove($d) } }
    foreach ($d in $dirs) { if (-not $Agent.Tails.ContainsKey($d)) { $Agent.Tails[$d] = New-LogTail $d } }
    # A log counts as read once its #Fields line, with c-ip, has been.
    $read = @($Agent.Tails.Values | Where-Object { $_.Fields -and $_.Fields.Valid }).Count -gt 0
    $pageLimit = [bool]($cfg.logs -and $p -and $p.flood -and $p.flood.req_rate)
    $why = ''
    if ($pageLimit -and $dirs.Count -eq 0) { $why = 'no IIS log folder found (set "iis_log_dirs" in the config): no page limit' }
    elseif ($pageLimit -and $p.block -and -not $Agent.FwUsable) { $why = "Windows Firewall can't ban here (see above): no page limit" }
    Write-AgentNote $Agent 'logs' $why
    $Agent.Running['logs'] = [bool]($pageLimit -and -not $why -and $read)
    if ($p -and $p.enabled -and -not $p.block) {
        # Monitor mode: nothing is blocked, and the lists and the origin lock
        # are watched in the logs instead (reported as monitor), as the Linux
        # agent's kernel layer counts without dropping.
        $Agent.Running['windows-firewall'] = [bool]($Agent.FwUsable -and $read)
        $Agent.Running['origin'] = [bool]($p.origin -and -not $Agent.OriginBlock -and $Agent.FwUsable -and $read)
    }
}

function Invoke-AgentStep {
    # One round: fetch, apply, find out what's in place. Seconds to wait.
    param($Agent, [double]$Now = 0)
    if ($Now -le 0) { $Now = Get-EpochNow }
    Invoke-RulesFetch $Agent
    if ($null -eq $Agent.Rules) { return $script:RetrySeconds }
    $before = ConvertTo-Json -InputObject @{ r = $Agent.Running; i = $Agent.Iis; e = $Agent.ETag } -Depth 6 -Compress
    Set-AgentPlan $Agent
    Update-OriginConflicts $Agent $Now
    [void](Update-Firewall $Agent $Now)
    $Agent.BansApplied = (@(Get-EnforcedBanKeys $Agent $Now) -join ',')
    Update-IisLimits $Agent
    Update-IisBans $Agent $Now
    $Agent.IisBansApplied = $Agent.BansApplied
    Update-IisCheck $Agent $Now
    Update-LogSources $Agent
    $after = ConvertTo-Json -InputObject @{ r = $Agent.Running; i = $Agent.Iis; e = $Agent.ETag } -Depth 6 -Compress
    if ($after -cne $before) { Save-AgentState $Agent }
    $sync = Get-WholeNumber (Get-Prop $Agent.Rules 'sync') 1 86400
    if ($null -eq $sync) { $sync = $script:RetrySeconds }
    return [math]::Max($script:MinSync, $sync)
}

function Invoke-AgentTick {
    # Every few seconds: IIS's logs, the bans, the day's pass, the reports.
    param($Agent, [double]$Now = 0)
    if ($Now -le 0) { $Now = Get-EpochNow }
    $p = $Agent.Plan
    if ($null -eq $p) { return }
    if ($Agent.Tails.Count -gt 0) {
        if ($Agent.Config.flush_log_buffer -and $env:windir) {
            [void](Invoke-External (Join-Path $env:windir 'System32\netsh.exe') @('http', 'flush', 'logbuffer') 10)
        }
        foreach ($tail in @($Agent.Tails.Values)) {
            foreach ($entry in @(Read-LogTail $tail)) { Invoke-LogEntry $Agent $entry $Now }
        }
    }
    if ($p.flood -and $p.flood.req_rate -and $Now -ge $Agent.PrunedAt) {
        Limit-Buckets $Agent.Buckets $Now ([double]$p.flood.req_rate) ([double]$p.flood.req_burst + 1) $script:BucketsMax
        $Agent.PrunedAt = $Now + 30
    }
    Get-DueBans $Agent $Now
    $keys = @(Get-EnforcedBanKeys $Agent $Now) -join ','
    if ($keys -cne $Agent.BansApplied) {
        if (Update-Firewall $Agent $Now -BansOnly) { $Agent.BansApplied = $keys }
    }
    if ($keys -cne $Agent.IisBansApplied -and $Now -ge $Agent.IisBansAt + $script:IisBansEvery) {
        Update-IisBans $Agent $Now
        $Agent.IisBansApplied = $keys
    }
    Save-AgentBans $Agent
    if ($Agent.Challenged.Count -gt 0 -and $Now -ge $Agent.ChallengedAt) {
        $busiest = @($Agent.Challenged.GetEnumerator() | Sort-Object -Property @{ Expression = { $_.Value }; Descending = $true }, @{ Expression = { $_.Key } } |
                Select-Object -First $script:ChallengeMaxRows)
        foreach ($e in $busiest) { Add-AgentEvent $Agent $e.Key 'challenge' 'block' '' '' '' $e.Value $Now }
        $Agent.Challenged = New-Object System.Collections.Hashtable
        $Agent.ChallengedAt = $Now + $script:ChallengeReportEvery
    }
    if ($Agent.Running['iis-check'] -and (Get-UtcDay $Now) -ne $Agent.Iis.check_day -and $Now -ge $Agent.CheckRetryAt) {
        # A new day: a new pass. Once a minute at most if writing it fails.
        $Agent.CheckRetryAt = $Now + $script:CheckRetryEvery
        Update-IisCheck $Agent $Now
    }
    Send-AgentEvents $Agent
}

function Invoke-AgentClear {
    # Everything the agent put in place, taken away. 0 when all of it is
    # gone; 1 when anything is left, and then the state (the owner's IIS
    # values) and the check page stay, so a later clear can finish.
    param($Agent)
    $ok = $true
    $current = Get-FirewallRules
    if ($null -ne $current) {
        $ops = @(@($current) | ForEach-Object { @{ Op = 'Remove'; Name = $_.Name } })
        if ($ops.Count -gt 0) {
            foreach ($r in @(Invoke-FirewallBatch $ops)) { if (-not $r.Ok) { $ok = $false; Write-AgentLog "could not remove $($r.Name): $($r.Error)" } }
        }
    } else {
        $ok = $false
        Write-AgentLog "Windows Firewall can't be read: remove the rules of the group $($script:FwGroup) by hand"
    }
    $pagePath = Join-Path $Agent.Config.page_dir 'check.html'
    $snap = Get-IisSnapshot $Agent.Config
    if ($snap.Installed -and $snap.Error) {
        $ok = $false
        Write-AgentLog "IIS's configuration can't be read ($($snap.Error)): nothing taken out of IIS"
    } elseif ($snap.Installed) {
        $changes = @(Get-IisCheckRemoval $Agent $snap $pagePath)
        if ($snap.Dipr) { $changes += @(Get-IisLimitsRestore $Agent $snap) }
        $bans = Get-IisBanChanges @{ Bans = @{}; Iis = $Agent.Iis } $snap 0
        $changes += @($bans.Changes)
        if ($changes.Count -gt 0) {
            if (Invoke-IisCommit $changes $Agent) {
                $Agent.Iis.check_rule_digest = ''; $Agent.Iis.dipr_ours = $false; $Agent.Iis.allow_added = @(); $Agent.Iis.deny_added = @()
            } else {
                $ok = $false
                Write-AgentLog 'IIS configuration not restored (see above)'
            }
        }
    }
    if (-not $ok) {
        Save-AgentState $Agent
        Write-AgentLog 'clear did not finish: the state and the check page are kept; run clear again once the problem above is fixed'
        return 1
    }
    if (Test-Path -LiteralPath $pagePath) { Remove-Item -LiteralPath $pagePath -Force -ErrorAction SilentlyContinue }
    foreach ($f in $Agent.StateFile, $Agent.BansFile) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
    Write-AgentLog 'cleared: nothing is blocked'
    return 0
}

function Get-FallbackConfig {
    # For `clear` with no usable config: the default folders next to where the
    # config should be, so what the agent wrote (named its own way) can still
    # be found and taken out. Never used to fetch anything.
    param([string]$Path)
    $c = @{}
    foreach ($k in $script:DefaultConfig.Keys) { $c[$k] = $script:DefaultConfig[$k] }
    $dir = Split-Path -Parent $Path
    $c.state_dir = Join-Path $dir 'state'
    $c.page_dir = Join-Path $dir 'www'
    $c.config_path = $Path
    # A broken file may still say which sub-status the page used.
    try {
        $m = [regex]::Match([IO.File]::ReadAllText($Path), '"check_substatus"\s*:\s*([0-9]{1,3})')
        if ($m.Success) { $c.check_substatus = [int]$m.Groups[1].Value }
    } catch { }
    return $c
}

function Show-AgentStatus {
    param($Agent)
    $p = $null
    if ($Agent.Rules) { $p = Get-AgentPlan $Agent.Rules }
    $state = 'none yet'
    if ($p) { if ($p.block) { $state = 'blocking' } elseif ($p.enabled) { $state = 'monitoring' } else { $state = 'off' } }
    Write-Host ('analytics-agent-windows ' + $script:AgentVersion)
    Write-Host ('rules: ' + $state)
    if ($p) {
        foreach ($n in 'allow', 'deny', 'ban', 'list', 'shared') { Write-Host ('  {0}: {1}' -f $n, @($p[$n]).Count) }
        if ($p.flood) { Write-Host ('  flood: {0} pages/s (burst {1}), {2} open, ban {3} s' -f $p.flood.req_rate, $p.flood.req_burst, $p.flood.conn_max, $p.flood.ban) } else { Write-Host '  flood: off' }
        if ($p.origin) { Write-Host ('  origin: {0} ranges' -f @($p.origin.only).Count) } else { Write-Host '  origin: off' }
        if ($p.challenge) { Write-Host ('  browser check: on, {0} paths skipped' -f @($p.challenge.skip).Count) } else { Write-Host '  browser check: off' }
    }
    $layers = (Get-AgentLayers $Agent) -join ' '
    if (-not $layers) { $layers = 'none' }
    Write-Host ('layers: ' + $layers)
    Write-Host ('banned now: {0}' -f $Agent.Bans.Count)
    $bc = Get-BackupConfig $Agent.Config
    if (-not $bc) { Write-Host 'backups: off' }
    else {
        $last = (Read-BackupState $bc).last
        if ($last) { Write-Host ('backups: last {0} {1} {2}' -f $last.run, $last.state, $last.error) } else { Write-Host ('backups: on, nightly at ' + $bc.at + ', none yet') }
    }
    foreach ($k in @($Agent.Notes.Keys)) { if ($Agent.Notes[$k]) { Write-Host ('note: ' + $Agent.Notes[$k]) } }
}

function Invoke-AgentMain {
    param([string]$Command, [string]$ConfigPath, [string[]]$Rest = @(), [string]$Into = '', [bool]$Yes = $false)
    if (-not $ConfigPath) { $ConfigPath = Get-DefaultConfigPath }
    $backupCommands = @('backup-setup', 'backup', 'backups', 'restore', 'export', 'backup-worker')
    if (@('run', 'once', 'status', 'clear', 'version', 'services') + $backupCommands -notcontains $Command) {
        Write-Host 'analytics-agent.ps1 run | once | status | clear | services | version | backup-setup | backup | backups | restore | export'
        return 2
    }
    if ($Command -eq 'version') { Write-Host $script:AgentVersion; return 0 }
    # Windows PowerShell 5.1 can write an array as {"value":[...],"Count":n}
    # when System.Array carries extended type data; the reports must be plain lists.
    Remove-TypeData -TypeName System.Array -ErrorAction SilentlyContinue
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $config = $null
    try { $config = Read-AgentConfig $ConfigPath } catch {
        Write-AgentLog $_.Exception.Message
        if ($Command -ne 'clear') { return 1 }
        # Clear still takes out what carries the agent's own names.
        Write-AgentLog 'clearing with the default folders instead'
        $config = Get-FallbackConfig $ConfigPath
    }
    $script:LogFile = Join-Path (Split-Path -Parent $ConfigPath) 'agent.log'
    if ($backupCommands -contains $Command) {
        try { return (Invoke-BackupCommand $config $Command $Rest $Into $Yes) } catch { Write-Host $_.Exception.Message; return 1 }
    }
    $agent = New-Agent $config
    if ($Command -eq 'status') { Show-AgentStatus $agent; return 0 }
    if ($Command -eq 'services') {
        # Checks them now, prints them and reports them; runs beside the loop.
        $checks = Invoke-ServicesRound $agent 0 -Force
        if ($null -eq $checks) { Write-Host 'no services report (see above)'; return 1 }
        foreach ($c in @($checks)) {
            $use = ''
            if ($c.Contains('mem_mb')) { $use = ' {0} MB' -f $c['mem_mb'] }
            if ($c.Contains('cpu_pct')) { $use += ' {0}% CPU' -f $c['cpu_pct'] }
            $state = 'up'
            if (-not $c.ok) { $state = 'DOWN ' + $c.detail }
            Write-Host ('{0}: {1}{2}' -f $c.name, $state, $use)
        }
        return 0
    }
    # One agent at a time: once and clear next to a running loop would
    # undo each other.
    $mutex = New-Object System.Threading.Mutex($false, 'Global\AnalyticsAgentWindows')
    $owned = $false
    try { $owned = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
    if (-not $owned) {
        $mutex.Dispose()
        if ($Command -eq 'run') { Write-AgentLog 'already running'; return 0 }
        Write-AgentLog "the agent is running (the AnalyticsAgent task): stop it first (Stop-ScheduledTask AnalyticsAgent), then $Command"
        return 1
    }
    if ($Command -ne 'run') {
        try {
            if ($Command -eq 'clear') { return (Invoke-AgentClear $agent) }
            [void](Invoke-AgentStep $agent)
            Invoke-AgentTick $agent
            try { [void](Invoke-ServicesRound $agent) } catch { Write-AgentLog "services round failed: $($_.Exception.Message)" }
            if ($null -eq $agent.Rules) { Write-AgentLog 'no rules from the collector yet (see above)'; return 1 }
            Write-AgentLog ('layers in place: ' + ((Get-AgentLayers $agent) -join ' '))
            return 0
        } finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
    }
    Write-AgentLog ('analytics-agent-windows {0} started' -f $script:AgentVersion)
    $next = 0.0
    while ($true) {
        $now = Get-EpochNow
        if ($now -ge $next) {
            $wait = $script:RetrySeconds
            # Keep going: the rules in place stay in place.
            try { $wait = Invoke-AgentStep $agent $now } catch { Write-AgentLog "round failed: $($_.Exception.Message)" }
            $next = $now + $wait
        }
        try { Invoke-AgentTick $agent } catch { Write-AgentLog "flood round failed: $($_.Exception.Message)" }
        try { [void](Invoke-ServicesRound $agent) } catch { Write-AgentLog "services round failed: $($_.Exception.Message)" }
        try { Start-BackupWorker $config $ConfigPath } catch { Write-AgentLog "backups worker didn't start: $($_.Exception.Message)" }
        Start-Sleep -Seconds $script:TickSeconds
    }
}

if ($Command -ne 'lib') {
    $code = @(Invoke-AgentMain $Command $ConfigPath $Rest $Into $Yes.IsPresent)
    exit ([int]$code[$code.Count - 1])
}
