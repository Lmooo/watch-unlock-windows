[CmdletBinding(SupportsShouldProcess)]
param(
    # Remotes that receive main and the release tag; a missing remote is skipped.
    [string[]]$Remotes = @('origin','gitee'),
    [string]$GitHubRepo = 'whyy1/watch-unlock-windows'
)

# Publishes the package that `Build.ps1 -Action package` left in dist/: tags the current commit,
# pushes main and the tag, and creates the GitHub release with the installer, its update
# signature, latest.json and SHA256SUMS. Gitee release attachments are uploaded on its web page.
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

function Invoke-Native([string]$Executable, [string[]]$Arguments) {
    # git and gh report progress on stderr, which Windows PowerShell turns into errors.
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Executable @Arguments 2>&1 | ForEach-Object { $_.ToString() } | Out-Host
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($exitCode -ne 0) { throw "$Executable $($Arguments -join ' ') failed (exit code $exitCode)" }
}

Push-Location $projectRoot
try {
    $version = ([IO.File]::ReadAllText((Join-Path $projectRoot 'apps/desktop/src-tauri/tauri.conf.json')) | ConvertFrom-Json).version
    $tag = "v$version"
    $name = "WatchUnlock_${version}_x64-setup.exe"
    $dist = Join-Path $projectRoot 'dist'
    $assets = @($name, "$name.sig", 'latest.json', 'SHA256SUMS.txt') | ForEach-Object { Join-Path $dist $_ }
    foreach ($asset in $assets) {
        if (-not (Test-Path -LiteralPath $asset -PathType Leaf)) { throw "Missing $asset; run Build.ps1 -Action package first." }
    }
    $manifest = [IO.File]::ReadAllText((Join-Path $dist 'latest.json')) | ConvertFrom-Json
    if ($manifest.version -ne $version) { throw "dist/latest.json is for $($manifest.version), not $version; rebuild the package." }

    if ((git branch --show-current) -ne 'main') { throw 'Publish from main.' }
    if (git status --porcelain) { throw 'The working tree has uncommitted changes; commit them first.' }
    $giteeManifest = Join-Path $projectRoot 'updates/latest-gitee.json'
    if ((Test-Path -LiteralPath $giteeManifest) -and
        ([IO.File]::ReadAllText($giteeManifest) | ConvertFrom-Json).version -ne $version) {
        throw 'updates/latest-gitee.json is stale; rebuild with -GiteeRepo and commit it.'
    }
    & (Join-Path $PSScriptRoot 'Check-Release.ps1')

    $notesFile = Join-Path ([IO.Path]::GetTempPath()) "watch-unlock-$tag-notes.md"
    [IO.File]::WriteAllText($notesFile, $manifest.notes, (New-Object Text.UTF8Encoding $false))
    try {
        if ($PSCmdlet.ShouldProcess($tag, 'tag, push and create the GitHub release')) {
            if (-not (git tag --list $tag)) { Invoke-Native 'git' @('tag', '-a', $tag, '-m', "Watch Unlock Windows $version") }
            $known = @(git remote)
            foreach ($remote in $Remotes) {
                if ($known -notcontains $remote) { Write-Warning "Remote '$remote' not configured; skipped."; continue }
                Invoke-Native 'git' @('push', $remote, 'main', $tag)
            }
            Invoke-Native 'gh' (@('release', 'create', $tag, '--repo', $GitHubRepo, '--title', "Watch Unlock $version",
                '--notes-file', $notesFile, '--verify-tag') + $assets)
            Write-Output "Published $tag. On Gitee, create release $tag and attach dist/$name."
        }
    } finally { Remove-Item -LiteralPath $notesFile -ErrorAction SilentlyContinue }
} finally { Pop-Location }
