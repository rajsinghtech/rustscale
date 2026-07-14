# rustscale binary installer for Windows — downloads prebuilt binaries from
# GitHub Releases and installs them. One-liner in PowerShell:
#
#   irm https://rajsinghtech.github.io/rustscale/install.ps1 | iex
#
# Installs rustscale.exe and rustscaled.exe to:
#   -User scope  : $env:LOCALAPPDATA\rustscale  (no admin needed, default)
#   -System scope: $env:ProgramFiles\rustscale  (requires admin)
#
# Adds the install directory to the user or system PATH if not already present.
#
# Parameters:
#   -Scope <User|System>   Install location (default: User)
#   -Version <tag>         Pin to a specific release tag (e.g. "v0.1.1")
#   -TailscaleCompatible   Also install tailscale.exe and tailscaled.exe aliases
#   -NoPath                Do not change the persistent PATH (portable installs)
#   -Uninstall             Remove installed files
#
# Examples:
#   irm https://rajsinghtech.github.io/rustscale/install.ps1 | iex
#   & ([scriptblock]::Create((irm https://rajsinghtech.github.io/rustscale/install.ps1))) -Scope System
#   & .\install.ps1 -Version v0.1.1

[CmdletBinding()]
param(
    [ValidateSet('User', 'System')]
    [string]$Scope = 'User',

    [string]$Version = '',

    [switch]$TailscaleCompatible,

    [switch]$NoPath,

    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$Repo = 'rajsinghtech/rustscale'
$Archive = 'rustscale-x86_64-pc-windows-msvc.zip'
$ReleaseBase = if ($env:RUSTSCALE_RELEASE_BASE) {
    $env:RUSTSCALE_RELEASE_BASE.TrimEnd('/')
} else {
    "https://github.com/$Repo/releases"
}

function Get-InstallDir {
    if ($Scope -eq 'System') {
        return Join-Path $env:ProgramFiles 'rustscale'
    }
    return Join-Path $env:LOCALAPPDATA 'rustscale'
}

function Get-ReleaseRoot {
    if ($Version) {
        if (-not $Version.StartsWith('v')) {
            $script:Version = "v$Version"
        }
        return "$ReleaseBase/download/$Version"
    }
    $script:Version = 'latest'
    return "$ReleaseBase/latest/download"
}

function Get-AssetUrl {
    param([string]$ReleaseRoot, [string]$Name)

    $token = if ($env:GH_TOKEN) { $env:GH_TOKEN } else { $env:GITHUB_TOKEN }
    if (-not $token) { return "$ReleaseRoot/$Name" }

    if (-not $script:PrivateRelease) {
        $releaseApi = if ($Version -eq 'latest') {
            "https://api.github.com/repos/$Repo/releases/latest"
        } else {
            "https://api.github.com/repos/$Repo/releases/tags/$Version"
        }
        $headers = @{
            Authorization = "Bearer $token"
            Accept = 'application/vnd.github+json'
            'X-GitHub-Api-Version' = '2022-11-28'
        }
        $script:PrivateRelease = Invoke-RestMethod -Uri $releaseApi -Headers $headers
    }
    $asset = $script:PrivateRelease.assets | Where-Object { $_.name -eq $Name } |
        Select-Object -First 1
    if (-not $asset) { throw "release API response is missing $Name" }
    return $asset.url
}

function Save-ReleaseFile {
    param([string]$Uri, [string]$OutFile)

    if ($Uri.StartsWith('file:')) {
        Copy-Item ([Uri]$Uri).LocalPath $OutFile -Force
        return
    }
    $token = if ($env:GH_TOKEN) { $env:GH_TOKEN } else { $env:GITHUB_TOKEN }
    $headers = if ($token) {
        @{ Authorization = "Bearer $token"; Accept = 'application/octet-stream' }
    } else { @{} }
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -Headers $headers `
        -UseBasicParsing -ErrorAction Stop
}

function Add-ToPath {
    param([string]$PathToAdd)

    if ($Scope -eq 'System') {
        $pathKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    } else {
        $pathKey = 'HKCU:\Environment'
    }

    $currentPath = (Get-ItemProperty -Path $pathKey -Name PATH -ErrorAction SilentlyContinue).PATH
    if (-not $currentPath) { $currentPath = '' }
    if ($currentPath -split ';' -contains $PathToAdd) {
        return
    }

    $newPath = if (-not $currentPath) {
        "$PathToAdd;"
    } elseif ($currentPath.EndsWith(';')) {
        "$currentPath$PathToAdd;"
    } else {
        "$currentPath;$PathToAdd;"
    }

    Set-ItemProperty -Path $pathKey -Name PATH -Value $newPath
    # Broadcast the change so new processes pick it up immediately.
    $signature = @'
[DllImport("user32.dll", SetLastError = true)]
public static extern IntPtr SendMessageTimeout(
    IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
    uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
    try {
        $type = Add-Type -MemberDefinition $signature -Name 'Win32SendMessage' -Namespace 'rustscale' -PassThru
        $HWND_BROADCAST = [IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x1a
        $result = [UIntPtr]::Zero
        $type::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result) | Out-Null
    } catch {
        # Non-fatal — the PATH change takes effect in new shell sessions regardless.
    }
}

function Remove-FromPath {
    param([string]$PathToRemove)

    if ($Scope -eq 'System') {
        $pathKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    } else {
        $pathKey = 'HKCU:\Environment'
    }

    $currentPath = (Get-ItemProperty -Path $pathKey -Name PATH -ErrorAction SilentlyContinue).PATH
    if (-not $currentPath) { return }
    $entries = $currentPath -split ';' | Where-Object { $_ -and $_ -ne $PathToRemove }
    $newPath = ($entries -join ';') + ';'
    Set-ItemProperty -Path $pathKey -Name PATH -Value $newPath
}

function Do-Install {
    $installDir = Get-InstallDir

    # Admin check for System scope.
    if ($Scope -eq 'System') {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Error "System scope requires administrator privileges. Re-run from an elevated PowerShell or use -Scope User."
        }
    }

    $releaseRoot = Get-ReleaseRoot
    $url = Get-AssetUrl -ReleaseRoot $releaseRoot -Name $Archive
    $checksumUrl = Get-AssetUrl -ReleaseRoot $releaseRoot -Name 'SHA256SUMS'
    Write-Host "rustscale: downloading $Archive from release $Version"

    $tempZip = Join-Path $env:TEMP "rustscale-install-$([guid]::NewGuid()).zip"
    $tempExtract = Join-Path $env:TEMP "rustscale-install-$([guid]::NewGuid())"
    $tempChecksums = Join-Path $env:TEMP "rustscale-install-$([guid]::NewGuid()).sha256"

    try {
        Save-ReleaseFile -Uri $url -OutFile $tempZip
        Save-ReleaseFile -Uri $checksumUrl -OutFile $tempChecksums

        $checksumLine = Get-Content $tempChecksums | Where-Object {
            $_ -match "^[0-9a-fA-F]{64}\s+\*?$([regex]::Escape($Archive))$"
        } | Select-Object -First 1
        if (-not $checksumLine) {
            throw "SHA256SUMS has no entry for $Archive"
        }
        $expected = ($checksumLine -split '\s+')[0].ToLowerInvariant()
        $actual = (Get-FileHash -Path $tempZip -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "checksum mismatch for $Archive (expected $expected, got $actual)"
        }
        Write-Host "rustscale: checksum verified"

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($tempZip)
        try {
            foreach ($entry in $zip.Entries) {
                if ([IO.Path]::IsPathRooted($entry.FullName) -or
                    ($entry.FullName -split '[/\\]' -contains '..')) {
                    throw "unsafe path in release archive: $($entry.FullName)"
                }
            }
        } finally {
            $zip.Dispose()
        }
        Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force

        foreach ($bin in @('rustscale.exe', 'rustscaled.exe')) {
            if (-not (Test-Path (Join-Path $tempExtract $bin))) {
                throw "release archive is missing required file '$bin'"
            }
        }

        if (-not (Test-Path $installDir)) {
            New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        }

        foreach ($bin in @('rustscale.exe', 'rustscaled.exe')) {
            $src = Join-Path $tempExtract $bin
            Copy-Item $src (Join-Path $installDir $bin) -Force
        }
        if ($TailscaleCompatible) {
            Copy-Item (Join-Path $tempExtract 'rustscale.exe') `
                (Join-Path $installDir 'tailscale.exe') -Force
            Copy-Item (Join-Path $tempExtract 'rustscaled.exe') `
                (Join-Path $installDir 'tailscaled.exe') -Force
        }

        if (-not $NoPath) { Add-ToPath $installDir }

        Write-Host ""
        Write-Host "rustscale: installed to $installDir"
        if (Test-Path (Join-Path $installDir 'rustscale.exe'))  { Write-Host "  $installDir\rustscale.exe" }
        if (Test-Path (Join-Path $installDir 'rustscaled.exe')) { Write-Host "  $installDir\rustscaled.exe" }
        if ($TailscaleCompatible) {
            Write-Host "  $installDir\tailscale.exe (compatibility alias)"
            Write-Host "  $installDir\tailscaled.exe (compatibility alias)"
        }
        Write-Host ""
        Write-Host "Open a new terminal, then get started:"
        Write-Host "  rustscaled run          # start the daemon"
        Write-Host "  rustscale up            # connect to a tailnet"
        Write-Host "  rustscale status        # check state"
    } catch {
        Write-Host "rustscale: installation failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "This can happen if:" -ForegroundColor Yellow
        Write-Host "  - the version '$Version' doesn't have an asset named '$Archive'"
        Write-Host "  - there's a network issue"
        Write-Host "  - the repository is private and GH_TOKEN was not set"
        Write-Host ""
        Write-Host "Download the archive manually from:"
        Write-Host "  https://github.com/$Repo/releases"
        Write-Host "and install manually, or build from source:"
        Write-Host "  git clone https://github.com/$Repo && sh rustscale/scripts/install-from-source.sh"
        exit 1
    } finally {
        Remove-Item $tempZip -ErrorAction SilentlyContinue
        Remove-Item $tempChecksums -ErrorAction SilentlyContinue
        Remove-Item $tempExtract -Recurse -ErrorAction SilentlyContinue
    }
}

function Do-Uninstall {
    $installDir = Get-InstallDir
    if (-not (Test-Path $installDir)) {
        Write-Host "rustscale: nothing found to remove at $installDir"
        return
    }

    Write-Host "rustscale: removing $installDir"
    Remove-Item $installDir -Recurse -Force
    if (-not $NoPath) { Remove-FromPath $installDir }
    Write-Host "rustscale: uninstalled"
}

if ($Uninstall) {
    Do-Uninstall
} else {
    Do-Install
}
