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
#   -Version <tag>         Pin to a specific release tag (e.g. "v0.1.0")
#   -Uninstall             Remove installed files
#
# Examples:
#   irm https://rajsinghtech.github.io/rustscale/install.ps1 | iex
#   irm https://rajsinghtech.github.io/rustscale/install.ps1 | iex -Scope System
#   & .\install.ps1 -Version v0.1.0

[CmdletBinding()]
param(
    [ValidateSet('User', 'System')]
    [string]$Scope = 'User',

    [string]$Version = '',

    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$Repo = 'rajsinghtech/rustscale'
$Archive = 'rustscale-x86_64-pc-windows-msvc.zip'
# Fallback version when the GitHub API is unreachable (private repos, rate
# limits, offline). Bump with each release.
$DefaultVersion = 'v0.1.0'

function Get-InstallDir {
    if ($Scope -eq 'System') {
        return Join-Path $env:ProgramFiles 'rustscale'
    }
    return Join-Path $env:LOCALAPPDATA 'rustscale'
}

function Get-DownloadUrl {
    if ($Version) {
        return "https://github.com/$Repo/releases/download/$Version/$Archive"
    }

    # Try the releases/latest redirect first (works for public repos without API).
    try {
        $resp = Invoke-WebRequest -Uri "https://github.com/$Repo/releases/latest" `
            -Method Head -MaximumRedirection 0 -ErrorAction Stop -UseBasicParsing
    } catch [System.Net.Http.HttpRequestException] {
        $resp = $_.Exception.Response
    }
    if ($resp -and $resp.Headers.Location) {
        $tag = ($resp.Headers.Location -split '/')[-1]
        if ($tag -match '^v') {
            $Version = $tag
            return "https://github.com/$Repo/releases/download/$Version/$Archive"
        }
    }

    # Try the GitHub API.
    try {
        $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
        $release = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
        if ($release.tag_name) {
            $Version = $release.tag_name
            return "https://github.com/$Repo/releases/download/$Version/$Archive"
        }
    } catch {
        # Fall through to default.
    }

    # Fallback to hardcoded default.
    $Version = $DefaultVersion
    return "https://github.com/$Repo/releases/download/$Version/$Archive"
}

function Add-ToPath {
    param([string]$PathToAdd)

    if ($Scope -eq 'System') {
        $pathKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    } else {
        $pathKey = 'HKCU:\Environment'
    }

    $currentPath = (Get-ItemProperty -Path $pathKey -Name PATH).PATH
    if ($currentPath -split ';' -contains $PathToAdd) {
        return
    }

    $newPath = if ($currentPath.EndsWith(';')) {
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

    $currentPath = (Get-ItemProperty -Path $pathKey -Name PATH).PATH
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

    $url = Get-DownloadUrl
    Write-Host "rustscale: downloading $Archive from release $Version"

    $tempZip = Join-Path $env:TEMP "rustscale-install-$([guid]::NewGuid()).zip"
    $tempExtract = Join-Path $env:TEMP "rustscale-install-$([guid]::NewGuid())"

    try {
        Invoke-WebRequest -Uri $url -OutFile $tempZip -UseBasicParsing -ErrorAction Stop
        Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force

        if (-not (Test-Path $installDir)) {
            New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        }

        foreach ($bin in @('rustscale.exe', 'rustscaled.exe')) {
            $src = Join-Path $tempExtract $bin
            if (Test-Path $src) {
                Copy-Item $src (Join-Path $installDir $bin) -Force
            }
        }

        Add-ToPath $installDir

        Write-Host ""
        Write-Host "rustscale: installed to $installDir"
        if (Test-Path (Join-Path $installDir 'rustscale.exe'))  { Write-Host "  $installDir\rustscale.exe" }
        if (Test-Path (Join-Path $installDir 'rustscaled.exe')) { Write-Host "  $installDir\rustscaled.exe" }
        Write-Host ""
        Write-Host "Open a new terminal, then get started:"
        Write-Host "  rustscaled run          # start the daemon"
        Write-Host "  rustscale up            # connect to a tailnet"
        Write-Host "  rustscale status        # check state"
    } catch {
        Write-Host "rustscale: download failed: $url" -ForegroundColor Red
        Write-Host ""
        Write-Host "This can happen if:" -ForegroundColor Yellow
        Write-Host "  - the repository is private (release assets require auth)"
        Write-Host "  - the version '$Version' doesn't have an asset named '$Archive'"
        Write-Host "  - there's a network issue"
        Write-Host ""
        Write-Host "If the repo is private, download the archive from:"
        Write-Host "  https://github.com/$Repo/releases"
        Write-Host "and install manually, or build from source:"
        Write-Host "  git clone https://github.com/$Repo && sh rustscale/scripts/install-from-source.sh"
        exit 1
    } finally {
        Remove-Item $tempZip -ErrorAction SilentlyContinue
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
    Remove-FromPath $installDir
    Write-Host "rustscale: uninstalled"
}

if ($Uninstall) {
    Do-Uninstall
} else {
    Do-Install
}
