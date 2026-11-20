@echo off
setlocal enabledelayedexpansion

rem Builds NineNsFlt.sys, generates NineNsFlt.cat and test-signs both.
rem Requires: VS 2026 Build Tools (C++), Windows SDK/WDK 28000.

set "HERE=%~dp0"
set "OUT=%HERE%out"
set "KITS=C:\Program Files (x86)\Windows Kits\10"
set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"

rem Must run before vcvars: the VC environment breaks the PowerShell Cert: drive.
rem NINENS_SIGNING_THUMBPRINT can select an existing certificate without creating one.
echo === Test-signing certificate ===
if defined NINENS_SIGNING_THUMBPRINT (
    set "THUMB=%NINENS_SIGNING_THUMBPRINT%"
) else (
    for /f "usebackq tokens=*" %%i in (`pwsh -NoProfile -ExecutionPolicy Bypass -File "%HERE%test-sign.ps1"`) do set "THUMB=%%i"
)
if not defined THUMB (
    echo error: could not create or find test signing certificate
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (
    echo error: Visual Studio with C++ tools not found
    exit /b 1
)
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul

set "KITVER="
for /f "tokens=*" %%i in ('dir /b /ad /o-n "%KITS%\Include" ^| findstr /r "^10\."') do (
    if exist "%KITS%\lib\%%i\km\x64\ntoskrnl.lib" if not defined KITVER set "KITVER=%%i"
)
if not defined KITVER (
    echo error: WDK kernel libraries not found in "%KITS%"
    exit /b 1
)

set "GSLIB=BufferOverflowFastFailK.lib"
if not exist "%KITS%\lib\%KITVER%\km\x64\BufferOverflowFastFailK.lib" set "GSLIB=BufferOverflowK.lib"
set "INF2CAT=%KITS%\bin\%KITVER%\x86\Inf2Cat.exe"
set "SIGNTOOL=%KITS%\bin\%KITVER%\x64\signtool.exe"

if not exist "%OUT%" mkdir "%OUT%"

echo === Building NineNsFlt.sys (x64, kit %KITVER%) ===
cl /nologo /kernel /GS /W4 /O2 ^
    /D_AMD64_ /DAMD64 /D_WIN64 ^
    /I"%KITS%\Include\%KITVER%\km" ^
    /I"%KITS%\Include\%KITVER%\km\crt" ^
    /I"%KITS%\Include\%KITVER%\shared" ^
    /c /Fo"%OUT%\\" "%HERE%NineNsFlt.c"
if errorlevel 1 exit /b 1

link /nologo /DRIVER /ENTRY:GsDriverEntry /SUBSYSTEM:NATIVE /MACHINE:X64 ^
    /INTEGRITYCHECK /NODEFAULTLIB ^
    /OUT:"%OUT%\NineNsFlt.sys" "%OUT%\NineNsFlt.obj" ^
    /LIBPATH:"%KITS%\lib\%KITVER%\km\x64" ntoskrnl.lib fwpkclnt.lib %GSLIB%
if errorlevel 1 exit /b 1

echo === Generating NineNsFlt.cat ===
copy /y "%HERE%NineNsFlt.inf" "%OUT%\" >nul
"%INF2CAT%" /driver:"%OUT%" /os:10_X64 /verbose
if errorlevel 1 exit /b 1

echo === Test-signing ===
"%SIGNTOOL%" sign /fd SHA256 /sha1 %THUMB% "%OUT%\NineNsFlt.sys" "%OUT%\NineNsFlt.cat"
if errorlevel 1 exit /b 1

echo.
echo [SUCCESS] Driver package ready in "%OUT%":
echo   NineNsFlt.sys  NineNsFlt.cat  NineNsFlt.inf
echo.
echo To load on a test machine: enable testsigning ^(bcdedit /set testsigning on^),
echo trust the signing cert %THUMB% ^(Root + TrustedPublisher^), then install
echo the INF ^(right-click Install^) or run: sc create NineNsFlt type= kernel start= auto binPath= %%WinDir%%\System32\Drivers\NineNsFlt.sys
exit /b 0
