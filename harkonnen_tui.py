#!/usr/bin/env python3
"""
Harkonnen TUI - Text-based User Interface for Harkonnen Antivirus
This version doesn't require Tkinter and works in a terminal
"""

import os
import sys
import subprocess
import threading
import time

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print the Harkonnen banner"""
    clear_screen()
    print(f"{Colors.HEADER}╔═════════════════════════════════════════════════════════╗{Colors.ENDC}")
    print(f"{Colors.HEADER}║{Colors.BOLD}               HARKONNEN ANTIVIRUS v1.0.0              {Colors.ENDC}{Colors.HEADER}║{Colors.ENDC}")
    print(f"{Colors.HEADER}╚═════════════════════════════════════════════════════════╝{Colors.ENDC}")
    print(f"{Colors.BLUE}A toy antivirus system for educational purposes{Colors.ENDC}")
    print()

def print_menu():
    """Print the main menu options"""
    print(f"{Colors.BOLD}Select an option:{Colors.ENDC}")
    print(f"  {Colors.GREEN}1.{Colors.ENDC} Scan a file")
    print(f"  {Colors.GREEN}2.{Colors.ENDC} Scan a directory")
    print(f"  {Colors.GREEN}3.{Colors.ENDC} Run neural network analysis")
    print(f"  {Colors.GREEN}4.{Colors.ENDC} Run sandbox analysis")
    print(f"  {Colors.GREEN}5.{Colors.ENDC} Monitor system")
    print(f"  {Colors.GREEN}6.{Colors.ENDC} Help")
    print(f"  {Colors.GREEN}0.{Colors.ENDC} Exit")
    print()

def get_file_path(prompt):
    """Get a file path from user input"""
    while True:
        file_path = input(prompt)
        if not file_path:
            return None
        if os.path.exists(file_path):
            return os.path.abspath(file_path)
        print(f"{Colors.FAIL}File doesn't exist. Please try again.{Colors.ENDC}")

def run_command(command, live_output=True):
    """Run a command and optionally print output in real-time"""
    process = subprocess.Popen(
        command, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT,
        universal_newlines=False,  # Changed to handle binary data
        shell=False
    )
    
    output_lines = []
    
    # Handle binary output with proper error handling
    while True:
        try:
            line = process.stdout.readline()
            if not line:
                break
                
            # Try to decode, replace characters that can't be decoded
            try:
                decoded_line = line.decode('utf-8', errors='replace')
            except UnicodeDecodeError:
                decoded_line = line.decode('latin-1', errors='replace')
                
            output_lines.append(decoded_line)
            if live_output:
                print(decoded_line, end='')
                
        except Exception as e:
            print(f"Error reading output: {e}")
            break
    
    process.wait()
    return ''.join(output_lines), process.returncode

def scan_file():
    """Scan a file with Harkonnen"""
    clear_screen()
    print(f"{Colors.BOLD}Scan a File{Colors.ENDC}")
    print("Enter the path to the file to scan (or blank to return to menu):")
    
    file_path = get_file_path("> ")
    if not file_path:
        return
    
    print(f"\n{Colors.BLUE}Select scan type:{Colors.ENDC}")
    print(f"  {Colors.GREEN}1.{Colors.ENDC} Quick scan (hash only)")
    print(f"  {Colors.GREEN}2.{Colors.ENDC} Standard scan")
    print(f"  {Colors.GREEN}3.{Colors.ENDC} Deep scan (with heuristics)")
    print(f"  {Colors.GREEN}4.{Colors.ENDC} Full scan (all options)")
    
    while True:
        scan_type = input("> ")
        if scan_type in ['1', '2', '3', '4']:
            break
        print(f"{Colors.FAIL}Invalid option.{Colors.ENDC}")
    
    # Build command based on scan type
    harkonnen_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harkonnen")
    command = [harkonnen_path]
    
    if scan_type == '1':
        command.append('-q')  # Quick scan
    elif scan_type == '3':
        command.append('-d')  # Deep scan
    elif scan_type == '4':
        command.extend(['-d', '-b', '-m', '-n'])  # Full scan
    
    # Add file path
    command.append(file_path)
    
    print(f"\n{Colors.BLUE}Starting scan...{Colors.ENDC}")
    output, return_code = run_command(command)
    
    print(f"\n{Colors.BLUE}Scan completed with return code: {return_code}{Colors.ENDC}")
    input("Press Enter to continue...")

def scan_directory():
    """Scan a directory with Harkonnen"""
    clear_screen()
    print(f"{Colors.BOLD}Scan a Directory{Colors.ENDC}")
    print("Enter the path to the directory to scan (or blank to return to menu):")
    
    dir_path = get_file_path("> ")
    if not dir_path:
        return
    
    if not os.path.isdir(dir_path):
        print(f"{Colors.FAIL}Not a valid directory.{Colors.ENDC}")
        input("Press Enter to continue...")
        return
    
    print(f"\n{Colors.BLUE}Starting directory scan...{Colors.ENDC}")
    harkonnen_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harkonnen")
    command = [harkonnen_path, '-d', dir_path]
    
    output, return_code = run_command(command)
    
    print(f"\n{Colors.BLUE}Scan completed with return code: {return_code}{Colors.ENDC}")
    input("Press Enter to continue...")

def neural_network_analysis():
    """Run neural network analysis on a file"""
    clear_screen()
    print(f"{Colors.BOLD}Neural Network Analysis{Colors.ENDC}")
    print("Enter the path to the file to analyze (or blank to return to menu):")
    
    file_path = get_file_path("> ")
    if not file_path:
        return
    
    print(f"\n{Colors.BLUE}Starting neural network analysis...{Colors.ENDC}")
    harkonnen_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harkonnen")
    command = [harkonnen_path, '-n', file_path]
    
    output, return_code = run_command(command)
    
    print(f"\n{Colors.BLUE}Analysis completed with return code: {return_code}{Colors.ENDC}")
    input("Press Enter to continue...")

def sandbox_analysis():
    """Run sandbox analysis on a file"""
    clear_screen()
    print(f"{Colors.BOLD}Sandbox Analysis{Colors.ENDC}")
    print("Enter the path to the file to analyze (or blank to return to menu):")
    
    file_path = get_file_path("> ")
    if not file_path:
        return
    
    print(f"\n{Colors.BLUE}Starting sandbox analysis...{Colors.ENDC}")
    harkonnen_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harkonnen")
    command = [harkonnen_path, '-b', file_path]
    
    output, return_code = run_command(command)
    
    print(f"\n{Colors.BLUE}Analysis completed with return code: {return_code}{Colors.ENDC}")
    input("Press Enter to continue...")

def monitor_system():
    """Monitor system for suspicious activity"""
    clear_screen()
    print(f"{Colors.BOLD}System Monitoring{Colors.ENDC}")
    print(f"{Colors.WARNING}Starting system monitoring. Press Ctrl+C to stop.{Colors.ENDC}")
    
    harkonnen_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harkonnen")
    command = [harkonnen_path, '-m']
    
    try:
        output, return_code = run_command(command)
    except KeyboardInterrupt:
        print(f"\n{Colors.BLUE}Monitoring stopped.{Colors.ENDC}")
    
    input("Press Enter to continue...")

def show_help():
    """Display help information"""
    clear_screen()
    print(f"{Colors.BOLD}Harkonnen Antivirus Help{Colors.ENDC}")
    print("\nHarkonnen is a toy antivirus system with the following features:")
    print("- File signature (hash) scanning")
    print("- PE file structure analysis")
    print("- Entropy analysis for packed/encrypted files")
    print("- API hooking detection")
    print("- Behavioral analysis through sandboxing")
    print("- Neural network-based detection")
    print("- Process monitoring")
    
    print(f"\n{Colors.BOLD}Command Line Options:{Colors.ENDC}")
    harkonnen_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harkonnen")
    run_command([harkonnen_path, '--help'], live_output=True)
    
    input("\nPress Enter to continue...")

def main():
    """Main function"""
    while True:
        print_banner()
        print_menu()
        
        choice = input("> ")
        
        if choice == '0':
            print("Exiting Harkonnen Antivirus...")
            break
        elif choice == '1':
            scan_file()
        elif choice == '2':
            scan_directory()
        elif choice == '3':
            neural_network_analysis()
        elif choice == '4':
            sandbox_analysis()
        elif choice == '5':
            monitor_system()
        elif choice == '6':
            show_help()
        else:
            print(f"{Colors.FAIL}Invalid option. Please try again.{Colors.ENDC}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting Harkonnen Antivirus...")
        sys.exit(0)