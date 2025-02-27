# Harkonnen Antivirus System


Harkonnen is a comprehensive, educational antivirus system designed for security research and learning. This project showcases various security techniques including signature-based detection, heuristic analysis, behavioral monitoring, and machine learning approaches to malware identification.

## 🔍 Key Features

### Core Detection Capabilities
- **Signature-based detection**: Compares file hashes against a database of known malicious signatures
- **Heuristic analysis**: Identifies suspicious patterns and behaviors in executable files
- **Entropy analysis**: Detects potentially packed or obfuscated malware using statistical analysis
- **PE file analysis**: Special handling and structure examination for Windows Portable Executable files
- **Dynamic API monitoring**: Detects suspicious API calls during runtime
- **Neural network detection**: Uses machine learning to identify previously unknown malware

### New Features (v2.5.0)
- **YARA rule support**: Custom pattern-based malware detection system
- **Multi-threaded scanning**: Parallel processing for significantly faster scans
- **Malware isolation**: Ability to safely remove detected threats from the system
- **HTML & text reporting**: Detailed scan reports with threat visualization
- **Threat intelligence**: Queries Malware Bazaar for real-time threat information
- **Malware information database**: Provides concise descriptions of detected threats
- **Automatic signature updates**: Adds newly identified threats to local database for future scans

### User Interface Options
- **Command-line interface**: Full-featured scanner with multiple detection options
- **Text-based UI**: Interactive terminal interface for streamlined operation
- **Graphical UI**: Cross-platform GUI with visualization capabilities
- **macOS App Bundle**: Native macOS application experience

## 🛠️ Technical Architecture

Harkonnen employs a modular design with the following components:

### Core Components
1. **Static Analysis Engine**
   - Hash calculation and lookup
   - File format verification
   - Entropy analysis
   - String extraction and pattern matching
   
2. **Heuristic Engine**
   - Code flow analysis
   - API call patterns
   - Suspicious instruction sequences
   - Common malware techniques detection
   
3. **PE Parser**
   - Header and section analysis
   - Import/export table examination
   - Resource analysis
   - Anomaly detection
   
4. **Sandbox Environment**
   - API call monitoring
   - File system access tracking
   - Network activity analysis
   - System modification detection
   
5. **Neural Network**
   - Feature extraction from binaries
   - Pattern recognition for zero-day threats
   - Confidence scoring
   - Continuous learning capability

### New Components in v2.5.0

6. **YARA Rule Engine**
   - Custom pattern-based detection
   - Rule management system
   - Severity classification
   - Metadata extraction

7. **Parallel Processing Framework**
   - Multi-threaded file scanning
   - Worker thread pool
   - Optimal CPU core utilization
   - Thread-safe result collection

8. **Reporting System**
   - HTML report generation with visualizations
   - Text-based report generation
   - Threat statistics and summaries
   - Browser integration

9. **Dynamic Signature Management**
   - Online updates from Malware Bazaar
   - Local signature database
   - Import/export functionality
   - Automatic updates

## 🔧 Building from Source

### Prerequisites

- **Core Requirements**:
  - C compiler (gcc/clang)
  - Python 3.6+ with Tkinter (for GUI)
  - make

- **Optional Components**:
  - libcurl (for online threat intelligence)
  - cJSON (for JSON parsing)
  - pthreads (for multi-threading support)
  - PyTorch (for neural network functionality)
  - seccomp (on Linux for sandboxing)

### Platform-Specific Requirements

#### macOS
- Xcode Command Line Tools
- Python 3 (preferably via Homebrew)

#### Linux
- Build essentials package
- Python3-tk package
- Development headers for curl and json-c

#### Windows
- MinGW or Visual Studio Build Tools
- Python with Tkinter (standard installation)
- Windows SDK (if using Visual Studio)

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/dev-null321/Harkonnen.git
cd Harkonnen

# Build the command-line version
make
```

## 🚀 Usage Guide

### Command Line Interface

```
Usage: ./harkonnen [OPTIONS] <filename or directory>

Scanning Options:
  -h, --help                 Display this help message
  -v, --version              Display version information
  -s, --scan                 Scan files without additional actions
  -q, --quick                Quick scan (hash check only)
  -d, --deep                 Deep scan (includes heuristics and PE analysis)
  -b, --sandbox              Run suspicious files in sandbox
  -m, --monitor              Enable API monitoring
  -n, --neural               Use neural network for additional detection
  -k, --kill                 Terminate malicious processes automatically
  -o, --output=FILE          Write results to FILE

Signature Management:
  -u, --update               Update signature database from Malware Bazaar
  -i, --import=FILE          Import signatures from a local file

Performance Options:
  -t, --threads=NUM          Use specified number of threads for scanning
  -p, --parallel             Enable multi-threaded scanning (auto-configure)

YARA Rules:
  -y, --yara                 Enable YARA rule scanning
  -Y, --yara-rules=DIR       Specify YARA rules directory
  -L, --list-rules           List all loaded YARA rules

Reporting:
  -r, --report=FORMAT        Generate scan report (text, html, or both)
  -O, --open-report          Open report in browser when scan completes
```

### Common Usage Examples

#### Basic scan of a file:
```bash
./harkonnen suspicious_file.exe
```

#### Deep scan with neural network analysis:
```bash
./harkonnen -d -n malware_sample.exe
```

#### Parallel scan with YARA rules:
```bash
./harkonnen -p -y large_directory
```

#### Generate HTML report for a scan:
```bash
./harkonnen -d -r html -O suspicious_files/
```

#### Update signature database:
```bash
./harkonnen -u
```

#### List loaded YARA rules:
```bash
./harkonnen -L
```

## 🛡️ YARA Rule Support

YARA rules provide powerful pattern-based detection capabilities. Harkonnen includes a built-in YARA rule engine that can:

1. **Load custom rules** from a designated directory (default: `./rules/`)
2. **Apply rules** to scanned files for pattern matching
3. **Classify threats** based on rule metadata (severity, tags, etc.)
4. **Provide context** about detected patterns

### Creating Custom YARA Rules

YARA rules use a simple syntax to define patterns. Here's an example:

```
rule Suspicious_PowerShell {
    meta:
        description = "Detects obfuscated PowerShell scripts"
        severity = "medium"
        tags = "powershell,obfuscation"
    strings:
        $s1 = "FromBase64String" nocase
        $s2 = "Invoke-Expression" nocase
        $s3 = "IEX" nocase
        $s4 = "-enc" nocase
    condition:
        2 of them
}
```

Save custom rules as `.yar` files in the `rules/` directory, and they'll be automatically loaded when using the `-y` option.

## 📊 Multi-threaded Scanning

Harkonnen v2.5.0 introduces parallel scanning capabilities to dramatically improve performance on multi-core systems:

1. **Automatic thread allocation** based on available CPU cores
2. **Workload distribution** across threads for optimal performance
3. **Thread-safe result collection** and reporting
4. **Progress tracking** during scanning

Enable parallel scanning with:
```bash
./harkonnen -p directory_to_scan
```

Or specify the exact number of threads:
```bash
./harkonnen -t 8 directory_to_scan
```

## 📋 Reporting System

### HTML Reports

HTML reports provide rich visualizations and detailed information about scan results:

- **Threat summary** with statistics and charts
- **File details** for all scanned items
- **Detection information** including threat names, descriptions, and severity
- **System information** including hardware, OS, and scan configuration

Generate an HTML report:
```bash
./harkonnen -r html -O directory_to_scan
```

The `-O` flag automatically opens the report in your default browser.

### Text Reports

Text reports provide a concise summary in plain text format:

- **Scan overview**
- **Detection details**
- **System information**

Generate a text report:
```bash
./harkonnen -r text directory_to_scan
```

Or generate both formats:
```bash
./harkonnen -r both directory_to_scan
```

## 🔄 Signature Management

### Online Updates

Harkonnen can automatically update its signature database from Malware Bazaar:

```bash
./harkonnen -u
```

This fetches the latest malware signatures and adds them to the local database.

### Custom Signatures

You can import custom signatures from a file:

```bash
./harkonnen -i my_signatures.txt
```

The signature format is simple:
```
SHA256_HASH:Malware_Name
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow the existing code style
- Add tests for new functionality
- Update documentation to reflect changes
- Ensure cross-platform compatibility where possible

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This software is provided for educational and research purposes only. It is not intended for production use or to provide complete protection against all types of malware. The authors are not responsible for any damage that may occur from using this software or from the misuse of information contained within.

Harkonnen should never be used to analyze malware on production systems or critical infrastructure. Always use isolated, sandboxed environments for malware analysis.
