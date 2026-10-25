[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),
    [switch]$ListFiles
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath($RepositoryRoot)
Push-Location $projectRoot
try {
    $isRepositoryRoot = $false
    try {
        $gitRoot = @(& git -c core.excludesfile= rev-parse --show-toplevel 2>$null)
        $isRepositoryRoot = $LASTEXITCODE -eq 0 -and $gitRoot.Count -eq 1 -and
            [IO.Path]::GetFullPath($gitRoot[0]).TrimEnd('\','/') -eq $projectRoot.TrimEnd('\','/')
    } catch { $isRepositoryRoot = $false }
    if ($isRepositoryRoot) {
        $files = @(& git -c core.excludesfile= -c core.quotepath=false ls-files --cached --others --exclude-standard | Sort-Object -Unique)
        if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect release files.' }
        $stagedFiles = @(& git -c core.excludesfile= -c core.quotepath=false ls-files --cached)
        if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect staged release files.' }
    } else {
        # Source archives must build without Git and must never inspect a parent
        # repository's index. Skip the same generated/private directory classes.
        function Get-ArchiveSources([string]$Directory) {
            foreach ($item in (Get-ChildItem -LiteralPath $Directory -Force)) {
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Source archives cannot contain reparse points.' }
                if ($item.PSIsContainer) {
                    if ($item.Name -notmatch '^(\.git|\.idea|\.vscode|\.tools|\.test-data|artifacts|target|node_modules|dist|private|results|__pycache__)$') {
                        Get-ArchiveSources $item.FullName
                    }
                } elseif ($item.Name -notmatch '(?i)\.(exe|dll|so|dylib|zip|dpapi|blob|pfx|p12|pem|log|csv|pyc)$|^\.env(?:\..*)?$') {
                    $item.FullName.Substring($projectRoot.TrimEnd('\','/').Length + 1).Replace('\','/')
                }
            }
        }
        $files = @(Get-ArchiveSources $projectRoot | Sort-Object -Unique)
        $stagedFiles = @()
    }
    $findings = @()
    $rules = @{
        'private-key' = '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'
        'personal-home-path' = '(?i)[A-Z]:[\\/]+Users[\\/]+(?!Public\b|Default\b)[^\\/\s<>]+[\\/]'
        'access-key' = '\bAKIA[0-9A-Z]{16}\b'
        'push-url-token' = '(?i)https://api\.day\.app/(?!push(?:[/?#"''\s]|$)|your|example|<)[a-z0-9_-]{12,}'
    }
    foreach ($file in $files) {
        if ($file -match '(?i)(^|/)(private|results|\.tools|\.idea|\.vscode|node_modules|target)/|\.(exe|dll|zip|dpapi|blob|pfx|p12|pem|log|csv)$|(^|/)\.env(?:\..*)?$') {
            $findings += "$file : forbidden release file"
            continue
        }
        if ((Test-Path -LiteralPath $file) -and ((Get-Item -LiteralPath $file -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            $findings += "$file : unsafe source link"
            continue
        }
        if ($file -match '\.(png|ico|jpg|jpeg|woff2?)$') { continue }
        $versions = @()
        if (Test-Path -LiteralPath $file -PathType Leaf) {
            if ((Get-Item -LiteralPath $file -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                $findings += "$file : unsafe source link"
                continue
            }
            if ((Get-Item -LiteralPath $file).Length -gt 5MB) {
                $findings += "$file : oversized working source file"
            } else {
                $versions += @{ Origin = 'working'; Content = [IO.File]::ReadAllText((Join-Path $projectRoot $file)) }
            }
        }
        # The index can still contain a secret after its working file was changed
        # or deleted. Scan that blob independently without printing its contents.
        if ($stagedFiles -contains $file) {
            $size = & git -c core.excludesfile= cat-file -s ":$file" 2>$null
            if ($LASTEXITCODE -ne 0) { throw 'Cannot read a staged source blob.' }
            if ([long]$size -gt 5MB) {
                $findings += "$file : oversized staged source file"
            } else {
                $lines = @(& git -c core.excludesfile= cat-file blob ":$file" 2>$null)
                if ($LASTEXITCODE -ne 0) { throw 'Cannot read a staged source blob.' }
                $versions += @{ Origin = 'staged'; Content = ($lines -join "`n") }
            }
        }
        foreach ($version in $versions) {
            foreach ($rule in $rules.GetEnumerator()) {
                if ($version.Content -match $rule.Value) {
                    $findings += "$file : $($version.Origin) $($rule.Key)"
                }
            }
        }
    }
    if ($findings.Count) {
        $findings | Write-Output
        throw 'Release check failed. Values are intentionally redacted.'
    }
    if ($ListFiles) {
        $files | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    } else {
        $scope = if ($isRepositoryRoot) { 'working tree and Git index' } else { 'source archive' }
        Write-Output "Release privacy checks passed for $($files.Count) source paths ($scope). Review test fixtures and licenses before publishing."
    }
} finally { Pop-Location }
