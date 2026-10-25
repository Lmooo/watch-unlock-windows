[CmdletBinding()]
param(
    [string]$RustToolsRoot = $env:WATCH_UNLOCK_TOOL_ROOT,
    [string]$RustToolchain = $env:WATCH_UNLOCK_RUST_TOOLCHAIN
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputRoot = Join-Path $projectRoot 'licenses'
$scratchRoot = Join-Path $projectRoot 'artifacts/licenses'
$utf8 = New-Object Text.UTF8Encoding($false)
$savedEnvironment = @{}
foreach ($name in @('PATH', 'CARGO_HOME', 'RUSTUP_HOME')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$dependencies = @{}
$texts = @{}
$overrides = @{}
$gaps = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)

function Get-OverrideFiles {
    param($Package, [string]$Directory)
    $key = "cargo:$($Package.name)@$($Package.version)"
    $result = @{}
    if (-not $overrides.ContainsKey($key)) { return $result }
    $record = $overrides[$key]
    $vcsFile = Join-Path $Directory '.cargo_vcs_info.json'
    if (-not (Test-Path -LiteralPath $vcsFile -PathType Leaf)) {
        [void]$gaps.Add("$key : upstream supplemental license has no package VCS evidence")
        return $result
    }
    $vcs = Get-Content -LiteralPath $vcsFile -Raw | ConvertFrom-Json
    if ($record.repository.TrimEnd('/') -ne ([string]$Package.repository).TrimEnd('/') -or
        $record.commit -cne $vcs.git.sha1 -or $record.path -cne $vcs.path_in_vcs) {
        [void]$gaps.Add("$key : supplemental license provenance does not match package repository and VCS commit")
        return $result
    }
    $overrideRoot = [IO.Path]::GetFullPath((Join-Path $outputRoot 'third-party-overrides'))
    foreach ($licenseFile in $record.license_files) {
        $expectedSource = "$($licenseFile.repository)/blob/$($licenseFile.commit)/$($licenseFile.path)"
        if ($licenseFile.repository -notmatch '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
            $licenseFile.commit -notmatch '^[a-f0-9]{40}$' -or $licenseFile.source_url -cne $expectedSource -or
            $licenseFile.file -match '(^|[/\\])\.\.([/\\]|$)' -or [IO.Path]::IsPathRooted($licenseFile.file)) {
            [void]$gaps.Add("$key : invalid supplemental license provenance")
            continue
        }
        $path = [IO.Path]::GetFullPath((Join-Path $overrideRoot $licenseFile.file))
        if (-not $path.StartsWith($overrideRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $licenseFile.sha256) {
            [void]$gaps.Add("$key : supplemental license file missing or checksum mismatch")
            continue
        }
        if ($licenseFile.notice_prefix_from) {
            $source = Join-Path $Directory $licenseFile.notice_prefix_from
            $notice = [IO.File]::ReadAllText($path).Replace("`r`n", "`n")
            if (-not (Test-Path -LiteralPath $source -PathType Leaf) -or
                -not [IO.File]::ReadAllText($source).Replace("`r`n", "`n").StartsWith($notice)) {
                [void]$gaps.Add("$key : supplemental notice differs from original package header")
                continue
            }
        }
        if ($licenseFile.referenced_license_url) {
            $source = Join-Path $Directory $licenseFile.referenced_by
            if ($licenseFile.referenced_license_url -cne 'https://mozilla.org/MPL/2.0/' -or $Package.license -cne 'MPL-2.0' -or
                -not (Test-Path -LiteralPath $source -PathType Leaf) -or
                -not [IO.File]::ReadAllText($source).Contains($licenseFile.referenced_license_url)) {
                [void]$gaps.Add("$key : supplemental license is not referenced by the original package")
                continue
            }
        } elseif ($licenseFile.repository -cne $record.repository -or $licenseFile.commit -cne $record.commit) {
            [void]$gaps.Add("$key : supplemental license has an unrelated repository or commit")
            continue
        }
        $result[$path] = "upstream supplement $($licenseFile.file) ($($licenseFile.source_url))"
    }
    return $result
}

function Get-PublicSource {
    param($Package, [string]$Ecosystem)
    if ($Ecosystem -eq 'npm') {
        return "https://www.npmjs.com/package/$($Package.name)/v/$($Package.version)"
    }
    if ($Package.source -like 'registry+*') {
        return "https://crates.io/crates/$($Package.name)/$($Package.version)"
    }
    $candidate = if ($Package.source -like 'git+*') {
        ($Package.source -replace '^git\+', '') -replace '#.*$', ''
    } else { [string]$Package.repository }
    $uri = $null
    if ([Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$uri) -and
        $uri.Scheme -eq 'https' -and -not $uri.UserInfo -and -not $uri.Query) {
        return $uri.GetLeftPart([UriPartial]::Path)
    }
    return $null
}

function Add-Package {
    param($Package, [string]$Directory, [string]$Ecosystem)
    $key = "$Ecosystem`:$($Package.name)@$($Package.version)"
    if ($dependencies.ContainsKey($key)) { return }
    $license = [string]$Package.license
    $publicSource = Get-PublicSource $Package $Ecosystem
    $dependencies[$key] = [ordered]@{
        name = [string]$Package.name
        version = [string]$Package.version
        license = if ($license) { $license } else { $null }
        publicsource = $publicSource
    }
    if (-not $license) { [void]$gaps.Add("$key : missing license expression") }
    if (-not $publicSource) { [void]$gaps.Add("$key : missing public source URL") }
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        [void]$gaps.Add("$key : installed package directory unavailable")
        return
    }

    $files = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $Directory -File)) {
        if ($file.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE)($|[._-])') {
            $files[$file.FullName] = $file.Name
        }
    }
    if ($Package.license_file) {
        $licensePath = [string]$Package.license_file
        $candidate = if ([IO.Path]::IsPathRooted($licensePath)) { [IO.Path]::GetFullPath($licensePath) }
            else { [IO.Path]::GetFullPath((Join-Path $Directory $licensePath)) }
        $prefix = [IO.Path]::GetFullPath($Directory).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if ($candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -and
            (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $files[$candidate] = $candidate.Substring($prefix.Length).Replace('\', '/')
        } else { [void]$gaps.Add("$key : declared license_file unavailable inside package") }
    }
    if ($Ecosystem -eq 'cargo') {
        $supplements = Get-OverrideFiles $Package $Directory
        foreach ($path in $supplements.Keys) { $files[$path] = $supplements[$path] }
    }

    $found = 0
    foreach ($path in $files.Keys) {
        $file = Get-Item -LiteralPath $path
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $file.Length -gt 4MB) {
            [void]$gaps.Add("$key : license file $($files[$path]) is a link or exceeds 4 MiB")
            continue
        }
        $content = [IO.File]::ReadAllText($path).Replace("`r`n", "`n").Replace("`r", "`n")
        if ([string]::IsNullOrWhiteSpace($content) -or $content.Contains([string][char]0)) {
            [void]$gaps.Add("$key : license file $($files[$path]) is empty or not plain text")
            continue
        }
        if (-not $content.EndsWith("`n")) { $content += "`n" }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $digest = ([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($content)))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
        if (-not $texts.ContainsKey($digest)) {
            $texts[$digest] = @{ Content = $content; References = (New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)) }
        }
        [void]$texts[$digest].References.Add("$key / $($files[$path])")
        $found++
    }
    if ($found -eq 0) { [void]$gaps.Add("$key : no complete license text found in package license files") }
}

function Add-RustWorkspace {
    param([string]$Workspace, [string[]]$Features = @())
    $manifest = Join-Path $projectRoot "$Workspace/Cargo.toml"
    $arguments = @($toolchainArguments) + @('metadata', '--format-version', '1', '--offline', '--locked',
        '--filter-platform', 'x86_64-pc-windows-gnu', '--manifest-path', $manifest)
    if ($Features.Count) { $arguments += @('--features', ($Features -join ',')) }
    $errorFile = Join-Path $scratchRoot (($Workspace.Replace('/', '-')) + '-metadata.stderr.log')
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $json = @(& $cargoCommand @arguments 2> $errorFile)
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $oldPreference }
    if ($exitCode -ne 0) {
        throw "Offline locked cargo metadata failed for $Workspace (exit $exitCode). Diagnostics are in ignored artifacts/licenses."
    }
    $metadata = ($json -join "`n") | ConvertFrom-Json
    Remove-Item -LiteralPath $errorFile -ErrorAction SilentlyContinue
    if (-not $metadata.resolve) { throw "Cargo did not return a resolved dependency graph for $Workspace." }
    $nodes = @{}
    $packages = @{}
    foreach ($node in $metadata.resolve.nodes) { $nodes[$node.id] = $node }
    foreach ($package in $metadata.packages) { $packages[$package.id] = $package }
    $members = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $visited = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $pending = New-Object 'Collections.Generic.Queue[string]'
    foreach ($member in $metadata.workspace_members) { [void]$members.Add($member); $pending.Enqueue($member) }
    while ($pending.Count) {
        $id = $pending.Dequeue()
        if (-not $visited.Add($id)) { continue }
        if (-not $nodes.ContainsKey($id) -or -not $packages.ContainsKey($id)) {
            throw "Incomplete cargo dependency graph for $Workspace."
        }
        if (-not $members.Contains($id)) {
            $package = $packages[$id]
            Add-Package $package ([IO.Path]::GetDirectoryName($package.manifest_path)) 'cargo'
        }
        foreach ($dependency in $nodes[$id].deps) { $pending.Enqueue($dependency.pkg) }
    }
}

function Add-NpmProductionPackages {
    $desktop = Join-Path $projectRoot 'apps/desktop'
    # Windows PowerShell cannot represent the npm root package's empty JSON key.
    $lockText = Get-Content -LiteralPath (Join-Path $desktop 'package-lock.json') -Raw
    $lock = ($lockText -replace '("packages"\s*:\s*\{\s*)""\s*:', '$1"__workspace_root__":') | ConvertFrom-Json
    if (-not $lock.packages) { throw 'The frontend requires a current npm package-lock.json.' }
    foreach ($property in $lock.packages.PSObject.Properties) {
        $relative = $property.Name
        $entry = $property.Value
        if (-not $relative -or $relative -eq '__workspace_root__' -or $entry.dev -or $entry.link) { continue }
        if (-not $relative.StartsWith('node_modules/') -or ($relative -split '/') -contains '..') {
            throw 'Unsafe production package path in npm lockfile.'
        }
        $directory = Join-Path $desktop $relative
        $manifest = Join-Path $directory 'package.json'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
            throw 'A locked frontend production dependency is not installed. Run npm ci before exporting notices.'
        }
        $package = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        if ($package.version -ne $entry.version) { throw 'An installed frontend production dependency differs from package-lock.json. Run npm ci.' }
        Add-Package $package $directory 'npm'
    }
}

try {
    New-Item -ItemType Directory -Path $scratchRoot -Force | Out-Null
    if (-not $RustToolsRoot -and (Test-Path -LiteralPath (Join-Path $projectRoot '.tools/cargo/bin/cargo.exe'))) {
        $RustToolsRoot = Join-Path $projectRoot '.tools'
    }
    $cargoCommand = 'cargo'
    $toolchainArguments = @()
    if ($RustToolsRoot) {
        $resolvedTools = (Resolve-Path -LiteralPath $RustToolsRoot).Path
        $env:CARGO_HOME = Join-Path $resolvedTools 'cargo'
        $env:RUSTUP_HOME = Join-Path $resolvedTools 'rustup'
        $cargoCommand = Join-Path $env:CARGO_HOME 'bin/cargo.exe'
        $env:PATH = "$(Join-Path $env:CARGO_HOME 'bin');$env:PATH"
        if (-not $RustToolchain) { $RustToolchain = '1.90.0-x86_64-pc-windows-gnu' }
    }
    if ($RustToolchain) { $toolchainArguments = @("+$RustToolchain") }
    if (-not (Get-Command $cargoCommand -ErrorAction SilentlyContinue)) {
        throw 'Cargo is unavailable. Supply RustToolsRoot or configure Cargo on PATH.'
    }
    $provenance = Join-Path $outputRoot 'third-party-overrides/provenance.json'
    if (Test-Path -LiteralPath $provenance -PathType Leaf) {
        $records = Get-Content -LiteralPath $provenance -Raw | ConvertFrom-Json
        foreach ($record in $records) {
            $key = "cargo:$($record.name)@$($record.version)"
            if ($overrides.ContainsKey($key)) { throw 'Duplicate supplemental license package record.' }
            $overrides[$key] = $record
        }
    }
    Add-RustWorkspace 'backend'
    Add-RustWorkspace 'apps/desktop/src-tauri' @('custom-protocol')
    Add-NpmProductionPackages

    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
    $keys = [string[]]@($dependencies.Keys)
    [Array]::Sort($keys, [StringComparer]::Ordinal)
    $orderedDependencies = @($keys | ForEach-Object { $dependencies[$_] })
    $dependencyJson = ConvertTo-Json -InputObject $orderedDependencies -Depth 5 -Compress
    [IO.File]::WriteAllText((Join-Path $outputRoot 'dependencies.json'), ($dependencyJson.Replace("`r`n", "`n") + "`n"), $utf8)

    $document = New-Object Text.StringBuilder
    [void]$document.Append("WATCH UNLOCK - THIRD-PARTY LICENSE TEXTS`n`n")
    [void]$document.Append("Generated from locked offline Cargo metadata for x86_64-pc-windows-gnu and installed locked npm production packages.`n")
    [void]$document.Append("The Cargo graph conservatively includes reachable build and development dependencies. Desktop custom-protocol is enabled.`n")
    [void]$document.Append("Repository workspace members are governed separately by the repository license and are omitted here.`n")
    [void]$document.Append("Original package license expressions are listed without selecting one branch of a dual license.`n")
    [void]$document.Append("License files are reproduced with original notices and copyright statements. Only line endings are normalized.`n")
    [void]$document.Append("Identical complete texts are printed once with every package/file reference retained. This inventory is not a legal sufficiency assessment.`n`n")
    [void]$document.Append("Supplemental upstream texts are pinned to package VCS commits in third-party-overrides/provenance.json; checksums and source notices are checked offline.`n`n")
    [void]$document.Append("DEPENDENCIES`n============`n")
    foreach ($key in $keys) {
        $dependency = $dependencies[$key]
        [void]$document.Append("$key`nLicense: $($dependency.license)`nSource: $($dependency.publicsource)`n`n")
    }
    $digests = [string[]]@($texts.Keys)
    [Array]::Sort($digests, [StringComparer]::Ordinal)
    foreach ($digest in $digests) {
        $text = $texts[$digest]
        $references = [string[]]@($text.References)
        [Array]::Sort($references, [StringComparer]::Ordinal)
        [void]$document.Append("LICENSE TEXT $digest`n")
        [void]$document.Append((($references | ForEach-Object { "Applies to: $_" }) -join "`n") + "`n`n")
        [void]$document.Append($text.Content)
        [void]$document.Append("`nEND LICENSE TEXT $digest`n`n")
    }
    [IO.File]::WriteAllText((Join-Path $outputRoot 'THIRD-PARTY-NOTICES.txt'), $document.ToString(), $utf8)
    $gapItems = [string[]]@($gaps)
    [Array]::Sort($gapItems, [StringComparer]::Ordinal)
    $gapFile = Join-Path $outputRoot 'UNRESOLVED.txt'
    if ($gapItems.Count) {
        [IO.File]::WriteAllText($gapFile, (($gapItems -join "`n") + "`n"), $utf8)
    } elseif (Test-Path -LiteralPath $gapFile -PathType Leaf) {
        Remove-Item -LiteralPath $gapFile
    }
    Write-Output "Third-party inventory: $($keys.Count) packages, $($digests.Count) distinct license texts, $($gapItems.Count) unresolved items."
    if ($gapItems.Count) {
        foreach ($gap in $gapItems) { Write-Warning $gap }
        throw 'Third-party license inventory is incomplete. See licenses/UNRESOLVED.txt before distribution.'
    }
} finally {
    foreach ($name in $savedEnvironment.Keys) {
        if ($null -eq $savedEnvironment[$name]) { Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
    }
}
