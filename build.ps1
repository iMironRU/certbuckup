# Build the 32-bit binary. Locates the i686 MinGW toolchain and calls make.
#
# ASCII-only on purpose: Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI,
# which mangles Cyrillic and breaks the parser. Keep this file plain ASCII.
#
# Toolchain lookup, highest priority first:
#   1. env var MINGW32_BIN
#   2. extracted WinLibs at %LOCALAPPDATA%\mingw32\bin
#   3. i686-w64-mingw32-g++ already on PATH

$ErrorActionPreference = "Stop"

function Find-Toolchain {
    if ($env:MINGW32_BIN -and (Test-Path "$env:MINGW32_BIN\g++.exe")) {
        return "$env:MINGW32_BIN\g++.exe"
    }
    $local = Join-Path $env:LOCALAPPDATA "mingw32\bin\g++.exe"
    if (Test-Path $local) { return $local }
    $onPath = Get-Command i686-w64-mingw32-g++ -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    return $null
}

$gpp = Find-Toolchain
if (-not $gpp) {
    Write-Host "32-bit MinGW toolchain (i686, MSVCRT) not found."
    Write-Host "Download: https://github.com/brechtsanders/winlibs_mingw/releases"
    Write-Host "  file winlibs-i686-posix-dwarf-...-msvcrt-...zip"
    Write-Host "  extract into %LOCALAPPDATA% (gives ...\mingw32\bin\g++.exe)"
    Write-Host "  or set: `$env:MINGW32_BIN='...\mingw32\bin'"
    exit 1
}

$bin = Split-Path -Parent $gpp
Write-Host "Toolchain: $gpp"
$make = Join-Path $bin "mingw32-make.exe"
if (-not (Test-Path $make)) { $make = "mingw32-make" }

# Тулчейн в PATH, чтобы windres (иконка) и прочие утилиты находились.
$env:Path = "$bin;" + $env:Path
$windres = Join-Path $bin "windres.exe"

& $make CXX="$gpp" WINDRES="$windres" @args
exit $LASTEXITCODE
