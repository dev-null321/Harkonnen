#!/bin/bash

# Harkonnen CNN GUI Launcher
# This script sets up the environment and launches the Harkonnen CNN GUI

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}        HARKONNEN CNN GUI LAUNCHER               ${NC}"
echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}This script will set up the environment and launch the GUI${NC}"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed or not in your PATH${NC}"
    echo -e "Please install Python 3 and try again"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "harkonnen_env" ]; then
    echo -e "${YELLOW}Setting up virtual environment...${NC}"
    python3 -m venv harkonnen_env || {
        echo -e "${RED}Failed to create virtual environment. Please install venv:${NC}"
        echo "    pip3 install virtualenv"
        exit 1
    }
    echo -e "${GREEN}Virtual environment created successfully${NC}"
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source harkonnen_env/bin/activate || {
    echo -e "${RED}Failed to activate virtual environment${NC}"
    exit 1
}

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
pip install pillow torch torchvision tqdm colorama numpy || {
    echo -e "${RED}Failed to install required packages${NC}"
    deactivate
    exit 1
}

# Launch the GUI
echo -e "${GREEN}Launching Harkonnen CNN GUI...${NC}"
python3 harkonnen_gui.py

# Deactivate virtual environment when the GUI closes
deactivate

echo -e "${BLUE}Harkonnen CNN GUI session ended${NC}"