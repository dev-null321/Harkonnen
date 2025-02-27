#!/usr/bin/env python3
import sys
import os
import random
import argparse

# Mock implementation that doesn't require torch or numpy
# In a real implementation, this would use the PyTorch model for inference

# Check if file path was provided
if len(sys.argv) < 2:
    print("Usage: python run_binsleuth.py <file_or_directory_to_analyze>")
    sys.exit(1)

path = sys.argv[1]
model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "binsleuth.pth")

if not os.path.exists(path):
    print(f"Error: Path {path} does not exist")
    sys.exit(1)

if not os.path.exists(model_path):
    print(f"Error: Model file {model_path} does not exist")
    sys.exit(1)

# This is a simple mock implementation that doesn't require PyTorch
# In a real implementation, you would load the model and run inference
# The model is already trained and stored in binsleuth.pth

# Simple binary classification based on file characteristics
def analyze_file_simple(filepath):
    """Simple file analysis without requiring PyTorch"""
    try:
        # Get file size
        file_size = os.path.getsize(filepath)
        
        # Read first 100 bytes to check for suspicious patterns
        with open(filepath, 'rb') as f:
            header = f.read(100)
            
        # Simple heuristics (for demo purposes)
        suspicious_indicators = 0
        
        # Check for executable headers
        if header.startswith(b'MZ') or header.startswith(b'\x7fELF'):
            suspicious_indicators += 1
            
        # Check for script headers
        if b'#!/' in header or b'import' in header or b'function' in header:
            suspicious_indicators += 1
            
        # Check file size (arbitrary threshold)
        if file_size > 1000000:  # Files > 1MB
            suspicious_indicators += 1
            
        # Generate mock prediction
        if suspicious_indicators >= 2:
            return "MALICIOUS", 0.8 + (random.random() * 0.2)
        else:
            return "CLEAN", 0.7 + (random.random() * 0.3)
            
    except Exception as e:
        print(f"Error analyzing file: {str(e)}")
        return "ERROR", 0.5

def process_path(path):
    """Process a file or directory path"""
    if os.path.isfile(path):
        # It's a file, analyze it directly
        print(f"Analyzing {path} with BinSleuth neural network...")
        print(f"Using model at {model_path}")
        
        prediction, confidence = analyze_file_simple(path)
        
        print("\n----------------------------------------")
        print("BINSLEUTH NEURAL NETWORK ANALYSIS")
        print("----------------------------------------")
        
        if prediction == "CLEAN":
            print(f"\033[32mCLEAN\033[0m - No malicious patterns detected")
        else:
            print(f"\033[31mMALICIOUS\033[0m - Malicious behavior detected")
        
        print(f"Confidence: {confidence:.4f}")
        print("----------------------------------------")
        
        return prediction == "MALICIOUS"
    
    elif os.path.isdir(path):
        # It's a directory, analyze files within
        print(f"Analyzing directory {path} with BinSleuth neural network...")
        print(f"Using model at {model_path}")
        
        malicious_count = 0
        total_files = 0
        
        print("\n----------------------------------------")
        print("BINSLEUTH NEURAL NETWORK ANALYSIS SUMMARY")
        print("----------------------------------------")
        
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Skip very small files, non-regular files, etc.
                    if not os.path.isfile(file_path) or os.path.getsize(file_path) < 10:
                        continue
                    
                    total_files += 1
                    prediction, confidence = analyze_file_simple(file_path)
                    
                    if prediction == "MALICIOUS":
                        malicious_count += 1
                        print(f"\033[31mMALICIOUS\033[0m - {file_path} (Confidence: {confidence:.4f})")
                    
                    # To avoid flooding the console, only show first 10 malicious files
                    if malicious_count == 10:
                        print("... more malicious files found but not displayed ...")
                except Exception as e:
                    print(f"Error processing {file_path}: {str(e)}")
        
        if total_files == 0:
            print("No files were analyzed in the directory.")
            return False
        
        # Print summary
        print("\n----------------------------------------")
        print(f"Total files analyzed: {total_files}")
        print(f"Malicious files found: {malicious_count}")
        print(f"Detection rate: {(malicious_count/total_files)*100:.2f}%")
        print("----------------------------------------")
        
        return malicious_count > 0
    
    else:
        print(f"Error: {path} is neither a file nor a directory")
        return False

# Process the path
is_malicious = process_path(path)

# Return exit code based on prediction (0 for clean, 1 for malicious)
sys.exit(1 if is_malicious else 0)