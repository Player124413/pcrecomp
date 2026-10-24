@echo off
rem Shrek 2 -- one-shot local build (Windows, Visual Studio 2022, x86).
rem
rem   set SHREK2_GAME=C:\Games\Shrek 2\System\game.exe
rem   build.bat
rem
rem Produces projects\shrek2\build\Release\shrek2.exe
setlocal EnableDelayedExpansion
cd /d "%~dp0\..\.."

if "%SHREK2_GAME%"=="" (
    if exist "%~dp0..\..\..\System\game.exe" set "SHREK2_GAME=%~dp0..\..\..\System\game.exe"
)
if "%SHREK2_GAME%"=="" (
    echo [build] set SHREK2_GAME to the install's System\game.exe first.
    echo [build]   set SHREK2_GAME=C:\Games\Shrek 2\System\game.exe
    exit /b 2
)
if not exist "%SHREK2_GAME%" (
    echo [build] no such file: %SHREK2_GAME%
    exit /b 2
)

echo [build] 1/3 installing the Python side
python -m pip install -q -r projects\shrek2\requirements.txt || exit /b 3

echo [build] 2/3 lifting %SHREK2_GAME%
python projects\shrek2\tools\build_lift.py --game "%SHREK2_GAME%" || exit /b 4

rem SHREK2_TRACE=ON builds the lift with RECOMP_TRACE: one call per lifted
rem function, and the SHREK2_CALLTRACE / _FIRSTHIT / _ARGTRACE knobs work.
rem Slower, so keep it out of a build you intend to play.
if "%SHREK2_TRACE%"=="" set "SHREK2_TRACE=OFF"

echo [build] 3/3 configuring and building Win32 (SHREK2_TRACE=%SHREK2_TRACE%)
cmake -S projects\shrek2 -B projects\shrek2\build -A Win32 -DSHREK2_TRACE=%SHREK2_TRACE% || exit /b 5
cmake --build projects\shrek2\build --config Release --parallel || exit /b 6

echo.
echo [build] done: projects\shrek2\build\Release\shrek2.exe
echo [build] next: copy it into the game's System folder, then follow
echo [build]       projects\shrek2\BRINGUP.md
echo [build] (it replaces game.exe in System\; the original stays in place).
endlocal
