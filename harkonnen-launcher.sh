#!/bin/bash
# Harkonnen Antivirus Launcher Script

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

# Detect OS
OS="$(uname)"

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not found"
    exit 1
fi

# Check if Tkinter is available
if ! python3 -c "import tkinter" &> /dev/null; then
    echo "Warning: Tkinter not found. Falling back to text-based interface."
    echo "To install Tkinter for a graphical interface:"
    case "$OS" in
        "Linux")
            echo "  For Ubuntu/Debian: sudo apt-get install python3-tk"
            echo "  For Fedora: sudo dnf install python3-tkinter"
            echo "  For Arch: sudo pacman -S tk"
            ;;
        "Darwin")
            echo "  For macOS: brew install python-tk"
            ;;
        *)
            echo "  Please install Python Tkinter for your system"
            ;;
    esac
    echo ""
    echo "Starting text-based interface..."
    # Fall back to the TUI version
    python3 "$SCRIPT_DIR/harkonnen_tui.py"
    
    # If TUI failed or was interrupted, show command-line help
    if [ $? -ne 0 ]; then
        echo ""
        echo "Text UI failed or was interrupted."
        echo "You can still use the command-line interface:"
        echo ""
        "$SCRIPT_DIR/harkonnen" --help
    fi
    
    exit 0
fi

# Check if harkonnen executable exists, if not, try to build it
if [ ! -f "./harkonnen" ]; then
    echo "Harkonnen executable not found. Attempting to build..."
    make || { echo "Failed to build Harkonnen. Please check dependencies."; exit 1; }
fi

# Start the GUI
echo "Starting Harkonnen Antivirus..."
python3 harkonnen_gui.py