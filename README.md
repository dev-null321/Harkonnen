# Harkonnen Advanced Malware Detection System

## 🛡️ Complete Malware Defense with Neural Network Analysis

**Version: 0.1 - Beta**

Harkonnen is a comprehensive antimalware solution that combines traditional signature-based detection with cutting-edge ResNet deep learning, heuristic analysis, YARA rules, and advanced file scanning techniques to identify potentially malicious files across all major platforms.

**IMPORTANT NOTICE**: This software is provided for **EXPERIMENTAL AND EDUCATIONAL PURPOSES ONLY**. It should not be relied upon as your primary or sole antimalware solution. False positives and false negatives may occur.

## 🔍 Core Components

Harkonnen consists of three main components that work together to provide comprehensive malware detection:

1. **Core C Engine** - Performs signature matching, heuristic analysis, and YARA rule scanning
2. **CNN Neural Network** - Uses ResNet-18 architecture for pattern-based malware detection
3. **GUI Interface** - Provides a user-friendly cross-platform interface for scanning

## ✨ Features

### Comprehensive Detection Methods
- **Signature-Based Detection**: Uses hash database to quickly identify known malware
- **ResNet Neural Network**: Deep learning model trained on millions of malware samples
- **Heuristic Analysis**: Detects suspicious behaviors and code patterns
- **YARA Rule Scanning**: Custom rules for identifying specific malware families
- **Static Analysis**: Examines executables without running them
- **API Monitoring**: (Optional) Monitors for suspicious API calls

### Performance and Usability
- **Multi-Threaded Processing**: Parallel scanning for high performance
- **Cross-Platform Support**: Works on Windows, macOS, and Linux
- **Command-Line Interface**: For power users and automation
- **Graphical User Interface**: User-friendly dark-themed interface
- **Batch Processing**: Scan and manage multiple files at once

### Malware Management
- **Quarantine System**: Safely isolate suspicious files
- **Detailed Reporting**: Generate comprehensive HTML or text reports
- **Confidence-Based Classification**: Three-tier detection system

## 🖥️ System Requirements

- **Operating Systems**:
  - Windows 10/11
  - macOS 10.15+ (Catalina or newer)
  - Linux (modern distributions)
- **Hardware**:
  - 4GB RAM (8GB recommended)
  - 500MB free disk space
  - CUDA-capable GPU recommended for faster neural network scanning
- **Software Dependencies**:
  - Python 3.8 or newer
  - PyTorch 2.0+ (with CUDA support recommended)
  - C Compiler (for core engine)

## ⚙️ Installation

### Prerequisites

1. **Install Python 3.8+**
   - Download from [python.org](https://www.python.org/downloads/)
   - Ensure pip is included in the installation

2. **Install C Compiler** (if building from source)
   - **Windows**: Visual Studio with C/C++ tools
   - **macOS**: Xcode Command Line Tools (`xcode-select --install`)
   - **Linux**: GCC (`sudo apt install build-essential` or equivalent)

### Installation Steps

#### 1. Clone or Download Repository

```bash
git clone https://github.com/yourusername/Harkonnen.git
cd Harkonnen
```

#### 2. Create and Activate Virtual Environment

We strongly recommend using a virtual environment to isolate dependencies:

**Windows**:
```bash
python -m venv harkonnen_env
harkonnen_env\Scripts\activate
```

**macOS/Linux**:
```bash
python3 -m venv harkonnen_env
source harkonnen_env/bin/activate
```

#### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

#### 4. Download Model Files

Ensure you have the neural network model files in the root directory:
- `best_model.pth` - Primary model with highest accuracy
- `latest_model.pth` - Most recent model (may include newer detections)

#### 5. Compile Core Engine (if building from source)

**Linux/macOS**:
```bash
make
```

**Windows**:
```bash
nmake -f Makefile.win
```

## 🚀 Usage

### GUI Mode (Recommended)

1. **Start the GUI Application**:

   **Windows**:
   ```bash
   run_harkonnen_gui.bat
   ```

   **macOS/Linux**:
   ```bash
   chmod +x run_harkonnen_gui.sh
   ./run_harkonnen_gui.sh
   ```

   Or directly:
   ```bash
   python harkonnen_gui.py
   ```

2. **Using the GUI**:
   - Select the model file by clicking "Browse" next to "Model File (.pth)"
   - Choose a file or directory to scan with "Browse" next to "Scan Location"
   - Toggle options like "Deep Scan" as needed
   - Click "Start Scan" to begin

3. **Understanding Results**:
   - **Malware (Red, ≥80% confidence)**: High probability of being malicious
   - **Undetermined (Orange, 20-80% confidence)**: May be malicious, requires review
   - **Benign (Green, ≤20% confidence)**: Low probability of being malicious

### Command-Line Mode (Advanced)

The `harkonnen` command-line tool provides powerful scanning options:

```bash
# Basic scan of a file
./harkonnen file.exe

# Deep scan with neural network analysis
./harkonnen -d -n file.exe

# Scan a directory with multiple threads and YARA rules
./harkonnen -p -y -t 8 /path/to/directory

# Generate HTML report after scanning
./harkonnen -d -r html -O /path/to/directory

# Update malware signature database
./harkonnen -u
```

**Available Command-Line Options**:

```
-h, --help               Display help message
-v, --version            Display version information
-s, --scan               Basic scan (default)
-d, --deep               Deep scan with heuristics and PE analysis
-n, --neural             Use neural network analysis
-y, --yara               Enable YARA rule scanning
-p, --parallel           Enable multi-threaded scanning
-t, --threads=NUM        Set specific thread count
-r, --report=FORMAT      Generate report (text, html, or both)
-O, --open-report        Open report in browser when complete
-u, --update             Update signature database
```

### Python Module Integration

You can also use the Harkonnen neural network scanner as a Python module in your own applications:

```python
from resnet_inference import scan_file, load_model, get_device

# Initialize the model
device = get_device()  # Gets best available device (CUDA, MPS, or CPU)
model = load_model("best_model.pth", device)

# Scan a file
is_malware, confidence, status = scan_file("suspicious_file.exe", model, device)

if status == "malware":
    print(f"MALWARE DETECTED! Confidence: {confidence*100:.2f}%")
elif status == "undetermined":
    print(f"SUSPICIOUS FILE! Confidence: {confidence*100:.2f}%")
else:
    print(f"File appears benign. Confidence: {confidence*100:.2f}%")
```

## 🔄 Updating

### Signature Database Updates

Keep your signature database up to date for the best detection rates:

```bash
# Using the command-line tool
./harkonnen -u

# Or from the GUI
# Click on "File" -> "Update Signatures"
```

### Neural Network Model Updates

Newer model versions may be available periodically with improved detection capabilities:

1. Download the latest model file from the repository
2. Replace your existing `best_model.pth` or use as `latest_model.pth`
3. Select the new model in the GUI or specify with `-m` on the command line

## 🔧 Advanced Configuration

### Custom YARA Rules

You can extend detection capabilities with custom YARA rules:

1. Create or download YARA rule files (`.yar` extension)
2. Place them in the `rules/` directory
3. Enable YARA scanning with the `-y` option or GUI checkbox

### Batch Mode

For scanning large numbers of files or scheduled scans:

```bash
# Create a batch scan script
./harkonnen -p -d -r html -O /path/to/scan >> scan_results.log
```

### GPU Acceleration

To enable GPU acceleration for neural network scanning:

1. Install CUDA and cuDNN (for NVIDIA GPUs)
2. Install PyTorch with CUDA support:
   ```bash
   pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
   ```
3. The system will automatically use the GPU when available

## 🛠️ Troubleshooting

### Common Issues

1. **"Model file not found" error**:
   - Ensure `best_model.pth` is in the root directory
   - Check file path contains no special characters

2. **Slow scanning performance**:
   - Enable parallel mode with `-p` or GUI option
   - For neural network scanning, use a CUDA-capable GPU
   - Reduce scan scope to specific directories

3. **False positives**:
   - Try using the latest model
   - Use quarantine instead of delete for suspicious files
   - Report false positives to improve future models

4. **Dependencies issues**:
   - Ensure you're using the virtual environment
   - Update dependencies: `pip install -r requirements.txt --upgrade`

## 📊 Understanding Detection Confidence

The neural network generates a confidence score between 0-100% for each file:

- **High Confidence (≥80%)**: Strong indication of malware
- **Medium Confidence (20-80%)**: Suspicious but not conclusive
- **Low Confidence (≤20%)**: Likely benign

These thresholds are conservative to minimize false positives. You can adjust the threshold sensitivity in advanced settings for specific use cases.

## 📝 License

This project is licensed under the terms of the [MIT License](LICENSE).

## 🙏 Acknowledgments

- The ResNet architecture 
- PyTorch for neural network capabilities
- The YARA project for pattern matching
- Python's tkinter for cross-platform GUI
- All contributors to the open-source security community

## 📢 Disclaimer

Harkonnen Advanced Malware Detection System is provided AS IS without warranty of any kind. The creators are not responsible for any damage or data loss that may occur from its use. This tool should be used as part of a comprehensive security strategy, not as a sole security solution. Freely available under the MIT License. 
