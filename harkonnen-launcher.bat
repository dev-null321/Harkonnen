@echo off
REM Harkonnen Antivirus Launcher for Windows
setlocal

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

echo Checking requirements...

REM Check if Python is available
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Python is required but not found
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check Python version - we need Python 3
python -c "import sys; sys.exit(0 if sys.version_info.major >= 3 else 1)" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Python 3 is required but Python 2 was found
    echo Please install Python 3 from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check if Tkinter is available
python -c "import tkinter" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Warning: Tkinter not found. Falling back to text-based interface.
    echo To install Tkinter for a graphical interface, reinstall Python with tcl/tk support.
    echo.
    echo Starting text-based interface...
    REM Fall back to TUI version
    python "%SCRIPT_DIR%\harkonnen_tui.py"
    exit /b 0
)

REM Check if harkonnen executable exists
if not exist "%SCRIPT_DIR%\harkonnen.exe" (
    echo Harkonnen executable not found. Attempting to build...
    
    REM Check if we have build tools
    where mingw32-make >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo Building with MinGW...
        mingw32-make
        if %ERRORLEVEL% NEQ 0 (
            echo Failed to build Harkonnen. Please check dependencies.
            pause
            exit /b 1
        )
    ) else (
        where nmake >nul 2>&1
        if %ERRORLEVEL% EQU 0 (
            echo Building with NMAKE...
            nmake /f Makefile.win
            if %ERRORLEVEL% NEQ 0 (
                echo Failed to build Harkonnen. Please check dependencies.
                pause
                exit /b 1
            )
        ) else (
            echo No compatible build tools found.
            echo Please install MinGW or Visual Studio Build Tools.
            echo You can download pre-built binaries from the project website.
            pause
            exit /b 1
        )
    )
)

REM Start the GUI
echo Starting Harkonnen Antivirus...
python "%SCRIPT_DIR%\harkonnen_gui.py"

endlocal