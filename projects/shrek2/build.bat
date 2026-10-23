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

echo [build] 3/3 configuring and building Win32
cmake -S projects\shrek2 -B projects\shrek2\build -G "Visual Studio 17 2022" -A Win32 || exit /b 5
cmake --build projects\shrek2\build --config Release --parallel || exit /b 6

echo.
echo [build] done: projects\shrek2\build\Release\shrek2.exe
echo [build] copy it into the game's System folder and run it instead of game.exe.
endlocal
