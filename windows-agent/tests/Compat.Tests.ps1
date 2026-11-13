# Windows PowerShell 5.1 is what Windows Server has. These tests run on
# PowerShell 7, so they look for what 7 accepts and 5.1 doesn't.
BeforeDiscovery {
    $script:Files = @('analytics-agent.ps1', 'install.ps1') | ForEach-Object { @{ Name = $_ } }
}

Describe 'Windows PowerShell 5.1 compatibility of <Name>' -ForEach $script:Files {
    BeforeAll {
        $script:Path = Join-Path (Join-Path $PSScriptRoot '..') $Name
        $tokens = $null; $errors = $null
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Path, [ref]$tokens, [ref]$errors)
        $script:Tokens = $tokens
        $script:Errors = $errors
        $script:Text = [IO.File]::ReadAllText($script:Path)
        function Find-Ast([scriptblock]$Predicate) { return @($script:Ast.FindAll($Predicate, $true)) }
    }
    It 'parses' {
        @($script:Errors).Count | Should -Be 0
    }
    It 'is plain ASCII (5.1 reads a file without a byte order mark as the ANSI code page)' {
        $bytes = [IO.File]::ReadAllBytes($script:Path)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
    It 'has no ternary, ??, ??=, ?. or ?[ , && or ||' {
        $kinds = @('TernaryExpressionAst', 'PipelineChainAst')
        @(Find-Ast { param($n) $kinds -contains $n.GetType().Name }).Count | Should -Be 0
        @($script:Tokens | Where-Object { @('QuestionQuestion', 'QuestionQuestionEquals', 'QuestionDot', 'QuestionLBracket', 'AndAnd', 'OrOr') -contains [string]$_.Kind }).Count | Should -Be 0
    }
    It 'has no ForEach-Object -Parallel, -AsHashtable, ConvertFrom-Json -Depth or other 6+ parameters' {
        $bad = @(Find-Ast { param($n) $n -is [System.Management.Automation.Language.CommandAst] } | ForEach-Object {
                $cmd = $_.GetCommandName()
                foreach ($e in $_.CommandElements) {
                    if ($e -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
                    $p = $e.ParameterName.ToLowerInvariant()
                    if ($p -in @('parallel', 'ashashtable', 'asbytestream', 'asarray', 'escapehandling', 'skipcertificatecheck', 'skiphttperrorcheck',
                            'statuscodevariable', 'responseheaderstvariable', 'noproxy', 'sslprotocol', 'additionalchildpath', 'throttlelimit')) { "$cmd -$p" }
                    if ($cmd -eq 'ConvertFrom-Json' -and $p -eq 'depth') { "$cmd -$p" }
                }
            })
        $bad | Should -BeNullOrEmpty
    }
    It 'gives Join-Path two paths at most (5.1 has no -AdditionalChildPath)' {
        $bad = @(Find-Ast { param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Join-Path' } |
                Where-Object { @($_.CommandElements | Select-Object -Skip 1 | Where-Object { $_ -isnot [System.Management.Automation.Language.CommandParameterAst] }).Count -gt 2 } |
                ForEach-Object { $_.Extent.Text })
        $bad | Should -BeNullOrEmpty
    }
    It 'uses no command or variable that 5.1 lacks' {
        $commands = @('Test-Json', 'Get-Error', 'Start-ThreadJob', 'ConvertFrom-Markdown', 'Join-String', 'Get-Uptime', 'Remove-Alias', 'Clear-RecycleBin')
        @(Find-Ast { param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $commands -contains $n.GetCommandName() }).Count | Should -Be 0
        $vars = @('IsWindows', 'IsLinux', 'IsMacOS', 'IsCoreCLR', 'PSStyle')
        @(Find-Ast { param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $vars -contains $n.VariablePath.UserPath }).Count | Should -Be 0
    }
    It 'uses no .NET API that .NET Framework 4.x lacks' {
        $patterns = @('ToUnixTime', 'FromUnixTime', '::HashData', 'ToHexString', 'FromHexString', 'Math\]::Clamp', 'GetRelativePath', 'File\]::[A-Za-z]+Async',
            '::IsAsciiHexDigit', 'Random\]::Shared', 'utf8NoBOM', 'NumberHandling', 'System\.Text\.Json', 'RandomNumberGenerator\]::GetBytes', 'Enumerable\]::Chunk',
            'IPNetwork', '\.ReplaceLineEndings', 'TryFormat', 'Convert\]::TryFrom', '\[System\.Range\]', '\[System\.Index\]', 'Path\]::Join')
        foreach ($p in $patterns) { $script:Text | Should -Not -Match $p -Because $p }
        # Overloads only .NET Core has: a string to Split, a char to StartsWith/EndsWith/Contains, a comparison to Replace/Contains.
        $script:Text | Should -Not -Match "\.Split\('[^']{2,}'"
        $script:Text | Should -Not -Match '\.Split\("(?!`[a-z0]")[^"]{2,}"' 
        $script:Text | Should -Not -Match "\.(StartsWith|EndsWith|Contains)\([^)]*\[char\]"
        $script:Text | Should -Not -Match "\.Replace\([^)]*StringComparison"
        $script:Text | Should -Not -Match "\.Contains\([^)]*StringComparison"
    }
    It 'needs no module beyond what Windows Server has' {
        @(Find-Ast { param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Import-Module', 'Install-Module', 'Install-PackageProvider') }).Count | Should -Be 0
        @(Find-Ast { param($n) $n -is [System.Management.Automation.Language.UsingStatementAst] }).Count | Should -Be 0
        @($script:Ast.ScriptRequirements | Where-Object { $_ } | ForEach-Object { $_.RequiredModules }).Count | Should -Be 0
    }
}
