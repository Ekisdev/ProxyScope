@echo off
REM windowsbuilder.bat - builds proxyscope.exe on Windows.
REM
REM Checks whether a Go toolchain is on PATH. If not, asks Y/N whether to
REM install one (via winget, falling back to a direct download from
REM go.dev if winget isn't available), then re-runs this same check/build
REM flow. Answering N just closes without doing anything else.

setlocal EnableDelayedExpansion
title proxyscope Windows builder
cd /d "%~dp0"

:checkgo
where go >nul 2>&1
if not errorlevel 1 goto :build

echo.
echo Go was not found on PATH.
choice /C YN /N /M "Do you want to install Go? (Y/N): "
if errorlevel 2 goto :declined
if errorlevel 1 goto :install
goto :declined

:install
echo.
set "INSTALLED="

where winget >nul 2>&1
if not errorlevel 1 (
    echo Installing Go via winget ...
    winget install --id GoLang.Go -e --source winget --accept-source-agreements --accept-package-agreements
    if not errorlevel 1 set "INSTALLED=1"
    if not defined INSTALLED echo winget install did not succeed, trying a direct download instead ...
)

if not defined INSTALLED (
    where curl >nul 2>&1
    if errorlevel 1 (
        echo Neither winget nor curl is available on this system.
        echo Install Go manually from https://go.dev/dl/ and run this script again.
        pause
        exit /b 1
    )

    echo Looking up the latest Go release ...
    set "GOVER="
    for /f "usebackq delims=" %%V in (`curl -fsSL "https://go.dev/VERSION?m=text"`) do (
        if not defined GOVER set "GOVER=%%V"
    )
    if not defined GOVER (
        echo Could not determine the latest Go version.
        echo Install Go manually from https://go.dev/dl/ and run this script again.
        pause
        exit /b 1
    )

    set "GOMSI=%TEMP%\!GOVER!.windows-amd64.msi"
    echo Downloading !GOVER! ...
    curl -fsSL -o "!GOMSI!" "https://go.dev/dl/!GOVER!.windows-amd64.msi"
    if errorlevel 1 (
        echo Download failed. Install Go manually from https://go.dev/dl/
        pause
        exit /b 1
    )

    echo Installing !GOVER! - you may be prompted for administrator permission ...
    msiexec /i "!GOMSI!" /quiet /norestart
    if errorlevel 1 (
        echo Go installation failed. Install it manually from https://go.dev/dl/ and run this script again.
        pause
        exit /b 1
    )
    del "!GOMSI!" >nul 2>&1
    set "INSTALLED=1"
)

echo.
echo Go installed. Refreshing PATH and running this script again ...
call :refreshpath
goto :checkgo

:refreshpath
for /f "tokens=2*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "SYS_PATH=%%B"
for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v Path 2^>nul') do set "USER_PATH=%%B"
set "PATH=%SYS_PATH%;%USER_PATH%"
exit /b 0

:declined
exit /b 0

:build
echo.
go version
echo.
REM Force a 64-bit build regardless of the installed Go toolchain's own
REM default GOARCH: -syscapture (WinDivert) only ships/documents a 64-bit
REM WinDivert.dll/WinDivert64.sys (see README's "Installing WinDivert"), and
REM a 32-bit proxyscope.exe can't load a 64-bit DLL. A cross-toolchain Go
REM build (e.g. a 386 host Go producing an amd64 binary) works fine here
REM since this project uses no CGO. This does not change go.exe's own
REM GOARCH, only this one build.
set "GOARCH=amd64"
set "GOOS=windows"
echo Building proxyscope.exe (GOARCH=%GOARCH%) ...
go build -o proxyscope.exe .\cmd\proxyscope
if errorlevel 1 (
    echo.
    echo Build failed.
    pause
    exit /b 1
)
echo.
echo Build succeeded: proxyscope.exe
pause
exit /b 0
