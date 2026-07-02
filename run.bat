@echo off
REM Launch the interactive Bethesda Ghidra Scripts menu.
REM Double-click this file or run it from a terminal.
setlocal
cd /d "%~dp0"

REM Find a Python 3 interpreter: prefer the py launcher, fall back to python.
set "PYEXE="
py -3 --version >nul 2>&1 && set "PYEXE=py -3"
if not defined PYEXE (
    python --version >nul 2>&1 && set "PYEXE=python"
)

if not defined PYEXE (
    echo.
    echo Python 3.10+ was not found on your PATH.
    echo This tool requires Python -- install it from:
    echo     https://www.python.org/downloads/
    echo Tick "Add python.exe to PATH" during Python setup, then run this file again.
    echo.
    pause
    exit /b 1
)

%PYEXE% "%~dp0run.py" %*
if errorlevel 1 (
    echo.
    echo run.py exited with an error.
    pause
)
endlocal
