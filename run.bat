@echo off
REM Launch the interactive Bethesda Ghidra Scripts menu.
REM Double-click this file or run it from a terminal.
setlocal
cd /d "%~dp0"
python "%~dp0run.py" %*
if errorlevel 1 (
    echo.
    echo run.py exited with an error.
    pause
)
endlocal
