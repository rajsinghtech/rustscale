$ErrorActionPreference = 'Stop'

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$TempRoot = Join-Path ([IO.Path]::GetTempPath()) "rustscale-packaging-$([guid]::NewGuid())"
$Version = 'v0.1.1'
$ReleaseDir = Join-Path $TempRoot "releases\download\$Version"
$InstallRoot = Join-Path $TempRoot 'localappdata'
$OldGhToken = $env:GH_TOKEN
$OldGithubToken = $env:GITHUB_TOKEN

try {
    Remove-Item Env:GH_TOKEN, Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $ReleaseDir, $InstallRoot | Out-Null
    $Stage = Join-Path $TempRoot 'stage'
    New-Item -ItemType Directory -Force -Path $Stage | Out-Null
    Set-Content -Path (Join-Path $Stage 'rustscale.exe') -Value 'rustscale-test'
    Set-Content -Path (Join-Path $Stage 'rustscaled.exe') -Value 'rustscaled-test'
    Copy-Item (Join-Path $Root 'LICENSE') $Stage

    $Archive = 'rustscale-x86_64-pc-windows-msvc.zip'
    $ArchivePath = Join-Path $ReleaseDir $Archive
    Compress-Archive -Path (Join-Path $Stage '*') -DestinationPath $ArchivePath
    $Hash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -Path (Join-Path $ReleaseDir 'SHA256SUMS') -Value "$Hash  $Archive"

    $env:LOCALAPPDATA = $InstallRoot
    $env:RUSTSCALE_RELEASE_BASE = ([Uri](Join-Path $TempRoot 'releases')).AbsoluteUri.TrimEnd('/')
    & (Join-Path $Root 'scripts\install.ps1') -Version '0.1.1' `
        -TailscaleCompatible -NoPath

    $Installed = Join-Path $InstallRoot 'rustscale'
    foreach ($Name in @('rustscale.exe', 'rustscaled.exe', 'tailscale.exe', 'tailscaled.exe')) {
        if (-not (Test-Path (Join-Path $Installed $Name))) {
            throw "missing installed file: $Name"
        }
    }

    & (Join-Path $Root 'scripts\install.ps1') -Uninstall -NoPath
    if (Test-Path $Installed) { throw 'uninstall left the install directory behind' }

    # The Windows path must also fail closed before installation when an asset
    # no longer matches the published SHA256SUMS entry.
    Add-Content -Path $ArchivePath -Value 'tamper'
    $Pwsh = (Get-Process -Id $PID).Path
    & $Pwsh -NoLogo -NoProfile -File (Join-Path $Root 'scripts\install.ps1') `
        -Version '0.1.1' -NoPath *> $null
    if ($LASTEXITCODE -eq 0) { throw 'tampered Windows archive unexpectedly installed' }
    if (Test-Path $Installed) { throw 'failed Windows install left files behind' }

    Write-Host 'Windows packaging installer tests: ok'
} finally {
    if ($null -ne $OldGhToken) { $env:GH_TOKEN = $OldGhToken }
    if ($null -ne $OldGithubToken) { $env:GITHUB_TOKEN = $OldGithubToken }
    Remove-Item $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
