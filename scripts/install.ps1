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
    $apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    $release = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
    $Version = $release.tag_name
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
        Invoke-WebRequest -Uri $url -OutFile $tempZip -UseBasicParsing
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
