# Installs the analytics server agent for Windows Server (IIS): Windows
# Firewall rules, IIS's request limits, the browser check in IIS and the page
# limit from IIS's logs. In an elevated PowerShell:
#
#   [Net.ServicePointManager]::SecurityProtocol = 'Tls12'; Invoke-WebRequest COLLECTOR/downloads/agent/windows/install.ps1 -UseBasicParsing -OutFile $env:TEMP\agent-install.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\agent-install.ps1 -Endpoint COLLECTOR -SiteId SITE
#
# Asks for the site secret (or reads ANALYTICS_SITE_SECRET); -Endpoint and
# -SiteId can come from ANALYTICS_ENDPOINT and ANALYTICS_SITE_ID too. Puts the
# agent in %ProgramFiles%\AnalyticsAgent, its config (SYSTEM and
# Administrators only) in %ProgramData%\AnalyticsAgent\config.json, runs it
# once, then registers the scheduled task AnalyticsAgent: at startup, as
# SYSTEM, started again within 5 minutes if it ever stops.
#
#   install.ps1 -Uninstall      takes every rule away, then removes the task and the files
#                               (keeps %ProgramData%\AnalyticsAgent\state\iis-backups; keeps
#                               everything if the rules could not all be taken away)
param(
    [string]$Endpoint = $env:ANALYTICS_ENDPOINT,
    [string]$SiteId = $env:ANALYTICS_SITE_ID,
    [string]$Sha256 = $env:ANALYTICS_AGENT_SHA256,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 can write an array as {"value":[...],"Count":n} in the config otherwise.
Remove-TypeData -TypeName System.Array -ErrorAction SilentlyContinue
$TaskName = 'AnalyticsAgent'
$ProgramDir = Join-Path $env:ProgramFiles 'AnalyticsAgent'
$DataDir = Join-Path $env:ProgramData 'AnalyticsAgent'
$AgentFile = Join-Path $ProgramDir 'analytics-agent.ps1'
$ConfigFile = Join-Path $DataDir 'config.json'
$WindowsPowerShell = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Stop-Install([string]$Message) {
    Write-Host ('analytics-agent: ' + $Message) -ForegroundColor Red
    exit 1
}

function Invoke-Agent([string]$Command) {
    # Under Windows PowerShell, as the task runs it, whatever this runs under.
    & $WindowsPowerShell -NoProfile -ExecutionPolicy Bypass -File $AgentFile $Command
    return $LASTEXITCODE
}

function Test-Reparse([string]$Path) {
    return ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
}

function Set-PrivateAcl([string]$Path) {
    # Owned by Administrators, open to SYSTEM and Administrators only, nothing
    # inherited or left over. %ProgramData% lets every user create folders, so
    # a folder someone else made first would otherwise stay theirs (an owner
    # can always rewrite the ACL), and the config holds the site secret.
    $icacls = Join-Path $env:windir 'System32\icacls.exe'
    if (Test-Reparse $Path) { Stop-Install "$Path is a junction or link: remove it, then run this again" }
    $links = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue)
    if ($links.Count -gt 0) { Stop-Install "$Path holds a junction or link ($($links[0].FullName)): remove it, then run this again" }
    & $icacls $Path '/setowner' '*S-1-5-32-544' '/T' '/C' | Out-Null
    if ($LASTEXITCODE -ne 0) { Stop-Install "could not make Administrators the owner of $Path" }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule ((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    # What is already inside goes back to inheriting only that (the agent
    # grants IIS read access to its www folder again itself).
    if (@(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0) {
        & $icacls (Join-Path $Path '*') '/reset' '/T' '/C' | Out-Null
        if ($LASTEXITCODE -ne 0) { Stop-Install "could not reset access to what is inside $Path" }
    }
}

$principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Stop-Install 'run it in an elevated PowerShell (Run as administrator)' }
if (-not (Test-Path -LiteralPath $WindowsPowerShell)) { Stop-Install 'Windows PowerShell 5.1 is needed' }
if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) { Stop-Install 'the ScheduledTasks module is needed (Windows Server 2012 or later)' }

if ($Uninstall) {
    # The task first, or the running agent would put the rules back.
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    $cleared = -not (Test-Path -LiteralPath $DataDir)
    if (Test-Path -LiteralPath $AgentFile) {
        Write-Host 'Taking the rules away...'
        $cleared = (Invoke-Agent 'clear') -eq 0
    }
    if (-not $cleared) {
        # The state holds the owner's own IIS settings and the check page is
        # what IIS may still point at: nothing more goes until clear finishes.
        Write-Host ('analytics-agent: not everything could be taken away (see above), so nothing else was removed: ' +
            "the agent stays in $ProgramDir and its state, check page and IIS backups in $DataDir. Fix the problem, then run install.ps1 -Uninstall again.") -ForegroundColor Red
        exit 1
    }
    if (Test-Path -LiteralPath $ProgramDir) { Remove-Item -LiteralPath $ProgramDir -Recurse -Force }
    $backups = Join-Path $DataDir 'state\iis-backups'
    if (Test-Path -LiteralPath $DataDir) {
        # Everything but the copies of IIS's configuration (the one from before
        # the agent's first change among them): the secret, the state, the page.
        Get-ChildItem -LiteralPath $DataDir -Force | Where-Object { $_.Name -ne 'state' } | Remove-Item -Recurse -Force
        $state = Join-Path $DataDir 'state'
        if (Test-Path -LiteralPath $state) { Get-ChildItem -LiteralPath $state -Force | Where-Object { $_.Name -ne 'iis-backups' } | Remove-Item -Recurse -Force }
    }
    Write-Host 'Removed: nothing is blocked, and the agent is gone.'
    if (Test-Path -LiteralPath $backups) { Write-Host "IIS configuration backups kept in $backups (applicationHost-before-agent.config is IIS's configuration before the agent's first change); delete the folder when you no longer need them." }
    exit 0
}

if (-not $Endpoint) { Stop-Install "give -Endpoint (the collector's URL) or set ANALYTICS_ENDPOINT" }
if (-not $SiteId) { Stop-Install 'give -SiteId or set ANALYTICS_SITE_ID' }
$Endpoint = $Endpoint.TrimEnd('/')
# The agent is fetched from this address and run as SYSTEM, so the address has
# to be one that can't be tampered with on the way: https. ANALYTICS_INSECURE=1
# is for trying it against a collector on your own machine.
if ($Endpoint -match '^http://') {
    if ($env:ANALYTICS_INSECURE -ne '1') { Stop-Install 'the endpoint must be https:// (the agent runs as SYSTEM from it). For a local collector: ANALYTICS_INSECURE=1' }
    Write-Host 'analytics-agent: WARNING: installing over plain http, as asked. Anyone on the network can replace the agent.' -ForegroundColor Yellow
} elseif ($Endpoint -notmatch '^https://[^\s/]+') {
    Stop-Install 'the endpoint must start with https://'
}
if ($SiteId -notmatch '^[a-fA-F0-9]{24}$') { Stop-Install "the site ID is the 24-character ID from the dashboard, not '$SiteId'" }

$secret = $env:ANALYTICS_SITE_SECRET
if (-not $secret) {
    $secure = Read-Host -AsSecureString 'Site secret (Site settings in your dashboard)'
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $secret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}
if (-not $secret) { Stop-Install 'no site secret' }
# A paste can carry invisible characters, and the prompt hides them. The
# collector then answers 400 to every request, for as long as the agent runs.
if ($secret -cnotmatch '^[A-Za-z0-9]+$') { Stop-Install 'the site secret has more than letters and digits in it, so nothing was installed: copy it again' }

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Write-Host 'Downloading the agent...'
$tmp = Join-Path $env:TEMP ('analytics-agent-' + [guid]::NewGuid().ToString('N') + '.ps1')
try {
    Invoke-WebRequest -Uri ($Endpoint + '/downloads/agent/windows/analytics-agent.ps1') -OutFile $tmp -UseBasicParsing -TimeoutSec 60
} catch { Stop-Install "download failed: $($_.Exception.Message)" }
$first = (Get-Content -LiteralPath $tmp -TotalCount 2) -join ' '
if ($first -notmatch 'analytics-agent-windows') { Remove-Item -LiteralPath $tmp -Force; Stop-Install "the download isn't the agent" }
# Pin the exact agent if you want to: take the sum from the dashboard (or a
# copy you already trust) and pass -Sha256. Without it, https is what stands
# between this file and the network.
if ($Sha256) {
    $got = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -ne $Sha256.ToLowerInvariant()) { Remove-Item -LiteralPath $tmp -Force; Stop-Install "the agent's checksum is $got, not the $Sha256 you asked for; nothing installed" }
    Write-Host 'Checksum matches.'
}

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }
if (-not (Test-Path -LiteralPath $ProgramDir)) { New-Item -ItemType Directory -Path $ProgramDir -Force | Out-Null }
Move-Item -LiteralPath $tmp -Destination $AgentFile -Force
Unblock-File -LiteralPath $AgentFile -ErrorAction SilentlyContinue

if (-not (Test-Path -LiteralPath $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
Set-PrivateAcl $DataDir
$icacls = Join-Path $env:windir 'System32\icacls.exe'
# An earlier config keeps its own settings; the site, secret and endpoint are these.
$config = [ordered]@{}
if (Test-Path -LiteralPath $ConfigFile) {
    try {
        $old = ConvertFrom-Json ([IO.File]::ReadAllText($ConfigFile))
        # The folders are always the defaults inside this one (the agent refuses others).
        foreach ($p in $old.PSObject.Properties) { if (@('state_dir', 'page_dir') -notcontains $p.Name) { $config[$p.Name] = $p.Value } }
    } catch { Write-Host 'The old config is not valid JSON: writing a new one.' }
}
$config['site_id'] = $SiteId.ToLowerInvariant()
$config['secret'] = $secret
$config['endpoint'] = $Endpoint
[IO.File]::WriteAllText($ConfigFile, (ConvertTo-Json -InputObject $config -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
& $icacls $ConfigFile '/setowner' '*S-1-5-32-544' | Out-Null
if ($LASTEXITCODE -ne 0) { Stop-Install "could not make Administrators the owner of $ConfigFile" }

Write-Host 'Fetching the rules once...'
if ((Invoke-Agent 'once') -ne 0) { Stop-Install 'the first run failed (see above); nothing was started' }

$action = New-ScheduledTaskAction -Execute $WindowsPowerShell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" run' -f $AgentFile)
# At startup, and every 5 minutes as a watchdog: a run already going is left
# alone (IgnoreNew, and the agent's own lock), one that stopped starts again.
$triggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650))
)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $taskPrincipal -Settings $settings `
    -Description 'Analytics server agent: Windows Firewall rules, IIS request limits and browser check from the site firewall rules.' -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host 'Done: the AnalyticsAgent task is running.'
[void](Invoke-Agent 'status')
Write-Host ''
Write-Host "Status: powershell -ExecutionPolicy Bypass -File `"$AgentFile`" status"
Write-Host "Log: $DataDir\agent.log"
Write-Host 'Remove every rule and the agent: install.ps1 -Uninstall (a clear on its own is undone by the running task)'
