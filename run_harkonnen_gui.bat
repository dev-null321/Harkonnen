@echo off
REM Harkonnen CNN GUI Launcher for Windows
REM This script sets up the environment and launches the Harkonnen CNN GUI

echo =================================================
echo        HARKONNEN CNN GUI LAUNCHER
echo =================================================
echo This script will set up the environment and launch the GUI
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in your PATH
    echo Please install Python and try again
    pause
    exit /b 1
)

REM Create virtual environment if it doesn't exist
if not exist harkonnen_env (
    echo Setting up virtual environment...
    python -m venv harkonnen_env
    if %errorlevel% neq 0 (
        echo Failed to create virtual environment. 
        echo Please install venv with: pip install virtualenv
        pause
        exit /b 1
    )
    echo Virtual environment created successfully
)

REM Activate virtual environment
echo Activating virtual environment...
call harkonnen_env\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo Failed to activate virtual environment
    pause
    exit /b 1
)

REM Install required packages
echo Installing required packages...
pip install pillow torch torchvision tqdm colorama numpy
if %errorlevel% neq 0 (
    echo Failed to install required packages
    call deactivate
    pause
    exit /b 1
)

REM Launch the GUI
echo Launching Harkonnen CNN GUI...
python harkonnen_gui.py

REM Deactivate virtual environment when the GUI closes
call deactivate

echo Harkonnen CNN GUI session ended
pause