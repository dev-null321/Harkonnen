# Harkonnen Advanced Malware Detection (Beta 0.1)

## ⚠️ EXPERIMENTAL SOFTWARE - BETA VERSION 0.1 ⚠️

**IMPORTANT NOTICE**: This software is in early beta stage (v0.1) and is provided for **EXPERIMENTAL AND EDUCATIONAL PURPOSES ONLY**. It should not be relied upon as your primary or sole antimalware solution. False positives and false negatives may occur.

Harkonnen Advanced Malware Detection combines ResNet-based deep learning with advanced file analysis to identify potentially malicious files across all major platforms.

## Features

- **Advanced ResNet Neural Network**: Uses ResNet-18 architecture trained on malware samples
- **Confidence-Based Classification**: Three-tier classification system:
  - High confidence malware (≥80% confidence)
  - Undetermined files (20-80% confidence)
  - Benign files (≤20% confidence)
- **Cross-platform GUI Interface**: Works on Windows, macOS, and Linux
- **File Management**: Quarantine or remove detected threats
- **Detailed File Analysis**: Provides comprehensive information about detected threats
- **Dark-themed Interface**: Sleek dark pink and blue theme inspired by House Harkonnen

## Installation

### Prerequisites

- Python 3.8 or newer
- pip (Python package manager)
- PyTorch compatible system

### Using Virtual Environment (Recommended)

We strongly recommend using a virtual environment to isolate dependencies:

```bash
# Create virtual environment
python3 -m venv harkonnen_env

# Activate environment (Windows)
harkonnen_env\Scripts\activate

# Activate environment (macOS/Linux)
source harkonnen_env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Installation Steps

1. **Clone or download this repository**
   ```
   git clone https://github.com/yourusername/Harkonnen.git
   cd Harkonnen
   ```

2. **Create and activate the virtual environment** (see above)

3. **Install dependencies**:
   ```
   pip install -r requirements.txt
   ```

4. **Download model files** 
   
   Make sure you have `best_model.pth` or `latest_model.pth` in the root directory.

5. **Run the application**:
   
   ```
   # Windows
   python harkonnen_gui.py
   
   # macOS/Linux
   python3 harkonnen_gui.py
   ```
   
   Or use the provided launch scripts:
   
   ```
   # Windows
   run_harkonnen_gui.bat
   
   # macOS/Linux (make executable first)
   chmod +x run_harkonnen_gui.sh
   ./run_harkonnen_gui.sh
   ```

## Usage

### Basic Usage

1. **Launch the application** using the appropriate method for your platform.

2. **Select a model** by clicking the "Browse" button next to "Model File (.pth)". 
   Use the provided `best_model.pth` or `latest_model.pth`.

3. **Select a target** by clicking the "Browse" button next to "Scan Location". 
   You can scan either a single file or an entire directory.

4. **Start the scan** by clicking the "Start Scan" button.

5. **View and analyze results** in the tabbed interface.

6. **Take action** on detected threats using the "Remove" or "Quarantine" buttons.

### Understanding Results

The system uses a three-tier classification approach:

1. **Malware (Red, ≥80% confidence)**
   - Files with high confidence of being malicious
   - Recommended action: Remove or quarantine immediately

2. **Undetermined (Orange/Yellow, 20-80% confidence)**
   - Files with moderate likelihood of being malicious
   - Recommended action: Further analysis, quarantine if suspicious

3. **Benign (Green, ≤20% confidence)**
   - Files with low likelihood of being malicious
   - Recommended action: No action needed

### Important Notes

- **False Positives**: Some benign files may be incorrectly flagged. Always use caution before removing files.
- **False Negatives**: Some malware may not be detected. This tool should supplement, not replace, other security measures.
- **Performance**: Scanning large directories may take time; GPU acceleration is recommended for faster processing.
- **This is Beta Software**: Expect occasional bugs and imperfect detection rates.

## Files Included

- **Core Files**:
  - `harkonnen_gui.py` - Main graphical user interface
  - `resnet_inference.py` - ResNet neural network inference engine
  - `best_model.pth` - Pre-trained PyTorch model
  - `requirements.txt` - Python dependencies
  
- **Launch Scripts**:
  - `run_harkonnen_gui.sh` - Launch script for macOS/Linux
  - `run_harkonnen_gui.bat` - Launch script for Windows

## System Requirements

- Windows 10/11, macOS 10.15+, or Linux (modern distribution)
- Python 3.8 or newer
- 4GB RAM (8GB recommended for large scans)
- CUDA-capable GPU recommended for faster scanning

## Limitations

- The model is still in early beta (v0.1) and detection accuracy will improve in future versions
- Large files may take significant time to process
- Not all types of malware can be detected using this approach
- This tool focuses on file-based malware and cannot detect network-based threats

## License

This project is provided for educational and research purposes only. See the LICENSE file for details.

## Acknowledgments

- PyTorch for neural network capabilities
- ResNet architecture for image classification
- Python's tkinter for cross-platform GUI
