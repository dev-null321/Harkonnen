#!/usr/bin/env python3
import os
import sys
import argparse
import torch
import torch.nn as nn
import numpy as np
import shutil
from torchvision import transforms, models
from PIL import Image
import time
from tqdm import tqdm
import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init(autoreset=True)

# ASCII Art banner
BANNER = r'''
 ██╗  ██╗ █████╗ ██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███╗   ██╗███████╗███╗   ██╗
 ██║  ██║██╔══██╗██╔══██╗██║ ██╔╝██╔═══██╗████╗  ██║████╗  ██║██╔════╝████╗  ██║
 ███████║███████║██████╔╝█████╔╝ ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██╔██╗ ██║
 ██╔══██║██╔══██║██╔══██╗██╔═██╗ ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║╚██╗██║
 ██║  ██║██║  ██║██║  ██║██║  ██╗╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║ ╚████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝
                                                                                 
 █████╗ ███╗   ██╗████████╗██╗███╗   ███╗ █████╗ ██╗     ██╗    ██╗ █████╗ ██████╗ ███████╗
██╔══██╗████╗  ██║╚══██╔══╝██║████╗ ████║██╔══██╗██║     ██║    ██║██╔══██╗██╔══██╗██╔════╝
███████║██╔██╗ ██║   ██║   ██║██╔████╔██║███████║██║     ██║ █╗ ██║███████║██████╔╝█████╗  
██╔══██║██║╚██╗██║   ██║   ██║██║╚██╔╝██║██╔══██║██║     ██║███╗██║██╔══██║██╔══██╗██╔══╝  
██║  ██║██║ ╚████║   ██║   ██║██║ ╚═╝ ██║██║  ██║███████╗╚███╔███╔╝██║  ██║██║  ██║███████╗
╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                                                                                            
 RESNET-18 DEEP LEARNING MALWARE DETECTION ENGINE
 ---------------------------------------------
'''

# Constants
IMAGE_SIZE = 256  # 256x256 grayscale image for ResNet-18

class GrayscaleResNetModel(nn.Module):
    """
    ResNet-18 modified to accept 1-channel (grayscale) input and perform binary classification.
    """
    def __init__(self, num_classes=2):
        super(GrayscaleResNetModel, self).__init__()
        # Use weights=None instead of pretrained=False (which is deprecated)
        self.model = models.resnet18(weights=None)
        # Change first conv layer to accept 1 channel
        self.model.conv1 = nn.Conv2d(1, 64, kernel_size=7, stride=2, padding=3, bias=False)
        num_features = self.model.fc.in_features
        self.model.fc = nn.Linear(num_features, num_classes)
        
    def forward(self, x):
        return self.model(x)

def get_device():
    """Get the best available device for PyTorch"""
    if torch.cuda.is_available():
        return torch.device("cuda")
    elif torch.backends.mps.is_available():
        return torch.device("mps")
    else:
        return torch.device("cpu")

def binary_to_grayscale_image(binary_data):
    """
    Convert binary data to a 256x256 grayscale image.
    Each byte of the binary is treated as a pixel value (0-255).
    """
    # Determine how many bytes we need for a 256x256 image
    required_size = IMAGE_SIZE * IMAGE_SIZE
    
    # Pad or truncate the binary data
    if len(binary_data) < required_size:
        # Pad with zeros if the file is smaller than needed
        binary_data = binary_data + b'\x00' * (required_size - len(binary_data))
    elif len(binary_data) > required_size:
        # Use the first portion if the file is larger
        binary_data = binary_data[:required_size]
    
    # Convert to numpy array and reshape to 256x256
    image_array = np.frombuffer(binary_data, dtype=np.uint8).reshape((IMAGE_SIZE, IMAGE_SIZE))
    
    # Convert to PIL Image
    image = Image.fromarray(image_array, mode='L')  # 'L' mode for grayscale
    
    return image

def find_model_file():
    """Find the model file in the current directory or models subdirectory"""
    # Look in current directory first
    pth_files = [f for f in os.listdir('.') if f.endswith('.pth')]
    
    # If not found, look in models subdirectory
    if not pth_files and os.path.exists('./models'):
        pth_files = [os.path.join('./models', f) for f in os.listdir('./models') if f.endswith('.pth')]
    
    # Prioritize 'latest_model.pth' if it exists
    for model_name in ['latest_model.pth', 'best_model.pth', 'final_model.pth']:
        if model_name in pth_files:
            return model_name
        if os.path.join('./models', model_name) in pth_files:
            return os.path.join('./models', model_name)
    
    # Otherwise return the first .pth file
    if pth_files:
        return pth_files[0]
    
    # If no model found, raise an error
    raise FileNotFoundError("No .pth model files found in current directory or models/ subdirectory")

def load_model(model_path, device):
    """Load the pre-trained ResNet model"""
    model = GrayscaleResNetModel().to(device)
    
    # Load state dict
    print(f"Loading model from: {model_path}")
    checkpoint = torch.load(model_path, map_location=device)
    
    # Handle both full checkpoint dict and state_dict only formats
    if 'model_state_dict' in checkpoint:
        model.load_state_dict(checkpoint['model_state_dict'])
    else:
        model.load_state_dict(checkpoint)
    
    model.eval()
    return model

def scan_file(file_path, model, device, threshold=0.5):
    """
    Scan a single file and predict whether it's malware or benign
    
    Returns:
    - is_malware: True/False/None (None indicates error or undetermined)
    - malware_prob: Confidence value between 0-1 (or error message string)
    - status: String indicating "malware", "benign", "undetermined", or "error"
    """
    try:
        # Skip very small files
        if os.path.getsize(file_path) < 512:
            return None, "File too small (< 512 bytes)", "error"
        
        # Read and preprocess the file
        with open(file_path, 'rb') as f:
            byte_data = f.read()
        
        # Convert to image
        image = binary_to_grayscale_image(byte_data)
        
        # Apply transform
        transform = transforms.Compose([
            transforms.ToTensor(),
            transforms.Normalize((0.5,), (0.5,))
        ])
        
        image_tensor = transform(image).unsqueeze(0).to(device)
        
        # Predict
        with torch.no_grad():
            outputs = model(image_tensor)
            probabilities = torch.nn.functional.softmax(outputs, dim=1)
            
        # Get probabilities
        malware_prob = probabilities[0][1].item()
        
        # Categorize based on confidence levels
        if malware_prob >= 0.8:  # High confidence malware (80%+)
            return True, malware_prob, "malware"
        elif malware_prob <= 0.2:  # High confidence benign (20% or less)
            return False, malware_prob, "benign"
        else:  # Uncertain prediction
            return None, malware_prob, "undetermined"
    
    except Exception as e:
        return None, f"Error processing file: {str(e)}", "error"

def scan_directory(directory, model, device, threshold=0.5, recursive=True):
    """Scan all files in a directory and predict whether they're malware or benign"""
    results = []
    
    # Get all files in the directory
    files = []
    if recursive:
        for root, _, filenames in os.walk(directory):
            for filename in filenames:
                if not filename.startswith('.'):  # Skip hidden files
                    files.append(os.path.join(root, filename))
    else:
        files = [os.path.join(directory, f) for f in os.listdir(directory) 
                if os.path.isfile(os.path.join(directory, f)) and not f.startswith('.')]
    
    # Process each file
    if not files:
        print(f"No files found in {directory}")
        return results
    
    for file_path in tqdm(files, desc="Scanning files", unit="file"):
        is_malware, malware_prob, status = scan_file(file_path, model, device, threshold)
        
        results.append({
            'file_path': file_path,
            'is_malware': is_malware,
            'malware_probability': malware_prob,
            'status': status
        })
    
    return results

def print_results(results, verbose=False):
    """Print the results of the scan"""
    # Count by category
    malware_count = sum(1 for r in results if r['status'] == 'malware')
    benign_count = sum(1 for r in results if r['status'] == 'benign')
    undetermined_count = sum(1 for r in results if r['status'] == 'undetermined')
    error_count = sum(1 for r in results if r['status'] == 'error')
    
    print("\n" + "=" * 60)
    print(f"{Fore.CYAN}📊 SCAN RESULTS SUMMARY{Style.RESET_ALL}")
    print("=" * 60)
    print(f"{Fore.BLUE}🔎 Total files scanned:{Style.RESET_ALL} {len(results)}")
    print(f"{Fore.RED}🚨 Malware detected:{Style.RESET_ALL} {malware_count}")
    print(f"{Fore.GREEN}✅ Benign files:{Style.RESET_ALL} {benign_count}")
    print(f"{Fore.YELLOW}❓ Undetermined files:{Style.RESET_ALL} {undetermined_count}")
    if error_count > 0:
        print(f"{Fore.YELLOW}⚠️  Files with errors:{Style.RESET_ALL} {error_count}")
    
    if verbose:
        print("\n" + "-" * 60)
        print(f"{Fore.CYAN}📋 DETAILED SCAN RESULTS{Style.RESET_ALL}")
        print("-" * 60)
        
        # First show malware
        if malware_count > 0:
            print(f"\n{Fore.RED}🚨 MALWARE FILES (CONFIDENCE ≥ 80%):{Style.RESET_ALL}")
            for result in [r for r in results if r['status'] == 'malware']:
                prob_percent = result['malware_probability'] * 100
                print(f"{Fore.RED}🚨 {result['file_path']} (Confidence: {prob_percent:.2f}%){Style.RESET_ALL}")
        
        # Then show undetermined
        if undetermined_count > 0:
            print(f"\n{Fore.YELLOW}❓ UNDETERMINED FILES (20% < CONFIDENCE < 80%):{Style.RESET_ALL}")
            for result in [r for r in results if r['status'] == 'undetermined']:
                prob_percent = result['malware_probability'] * 100
                print(f"{Fore.YELLOW}❓ {result['file_path']} (Confidence: {prob_percent:.2f}%){Style.RESET_ALL}")
        
        # Then show benign
        if benign_count > 0 and verbose:
            print(f"\n{Fore.GREEN}✅ BENIGN FILES (CONFIDENCE ≤ 20%):{Style.RESET_ALL}")
            for result in [r for r in results if r['status'] == 'benign']:
                prob_percent = result['malware_probability'] * 100
                print(f"{Fore.GREEN}✅ {result['file_path']} (Confidence: {prob_percent:.2f}%){Style.RESET_ALL}")
        
        # Finally show errors
        if error_count > 0:
            print(f"\n{Fore.YELLOW}⚠️  FILES WITH ERRORS:{Style.RESET_ALL}")
            for result in [r for r in results if r['status'] == 'error']:
                print(f"{Fore.YELLOW}⚠️  {result['file_path']}: {result['malware_probability']}{Style.RESET_ALL}")
    
    # Always print high confidence malware
    if malware_count > 0:
        print("\n" + "!" * 60)
        print(f"{Fore.RED}❗ HIGH CONFIDENCE MALWARE DETECTIONS ❗{Style.RESET_ALL}")
        print("!" * 60)
        for i, result in enumerate([r for r in results if r['status'] == 'malware']):
            prob_percent = result['malware_probability'] * 100
            print(f"{Fore.RED}{i+1}. {result['file_path']} (Confidence: {prob_percent:.2f}%){Style.RESET_ALL}")
    
    # Return both malware and undetermined 
    malware_results = [r for r in results if r['status'] == 'malware']
    undetermined_results = [r for r in results if r['status'] == 'undetermined']
    
    return malware_results, undetermined_results

def remove_malware_files(malware_files):
    """Remove or quarantine malware files after user confirmation"""
    if not malware_files:
        print(f"{Fore.YELLOW}No malware files to remove.{Style.RESET_ALL}")
        return False
    
    print(f"\n{Fore.YELLOW}The following files were detected as malware:{Style.RESET_ALL}")
    for i, file_info in enumerate(malware_files):
        prob_percent = file_info['malware_probability'] * 100
        print(f"{Fore.RED}{i+1}. {file_info['file_path']} (Confidence: {prob_percent:.2f}%){Style.RESET_ALL}")
    
    action = input(f"\n{Fore.YELLOW}Choose an action: (Q)uarantine, (D)elete, or (I)gnore? [Q/d/i]: {Style.RESET_ALL}").lower()
    
    if action == 'i' or not action:
        print(f"{Fore.GREEN}No action taken.{Style.RESET_ALL}")
        return False
    
    # Create a quarantine directory
    quarantine_dir = os.path.join(os.getcwd(), "binSleuth_quarantine")
    
    if action == 'q' or action == '':
        # Quarantine files
        os.makedirs(quarantine_dir, exist_ok=True)
        
        success_count = 0
        error_count = 0
        
        for file_info in tqdm(malware_files, desc="Quarantining files", unit="file"):
            file_path = file_info['file_path']
            try:
                # Move to quarantine
                quarantine_filename = os.path.basename(file_path) + ".quarantined"
                quarantine_path = os.path.join(quarantine_dir, quarantine_filename)
                shutil.move(file_path, quarantine_path)
                success_count += 1
            except Exception as e:
                print(f"{Fore.RED}Error quarantining {file_path}: {str(e)}{Style.RESET_ALL}")
                error_count += 1
        
        print(f"\n{Fore.GREEN}✅ {success_count} files moved to quarantine: {quarantine_dir}{Style.RESET_ALL}")
        if error_count > 0:
            print(f"{Fore.RED}⚠️  {error_count} files could not be quarantined{Style.RESET_ALL}")
        
    elif action == 'd':
        # Delete files
        confirm = input(f"{Fore.RED}⚠️  WARNING: Files will be permanently deleted! Confirm? (y/N): {Style.RESET_ALL}").lower()
        
        if confirm != 'y':
            print(f"{Fore.GREEN}Deletion cancelled.{Style.RESET_ALL}")
            return False
        
        success_count = 0
        error_count = 0
        
        for file_info in tqdm(malware_files, desc="Deleting files", unit="file"):
            file_path = file_info['file_path']
            try:
                os.remove(file_path)
                success_count += 1
            except Exception as e:
                print(f"{Fore.RED}Error deleting {file_path}: {str(e)}{Style.RESET_ALL}")
                error_count += 1
        
        print(f"\n{Fore.GREEN}✅ {success_count} files permanently deleted{Style.RESET_ALL}")
        if error_count > 0:
            print(f"{Fore.RED}⚠️  {error_count} files could not be deleted{Style.RESET_ALL}")
    
    return True

def main():
    # Display banner
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
    
    parser = argparse.ArgumentParser(description='Harkonnen Antimalware - Binary Malware Detection using ResNet-18')
    
    # Input arguments
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-f', '--file', help='Path to file to scan')
    input_group.add_argument('-d', '--directory', help='Path to directory to scan')
    
    # Model arguments
    parser.add_argument('-m', '--model', help='Path to model file (if not specified, will auto-detect)')
    
    # Output arguments
    parser.add_argument('-v', '--verbose', action='store_true', help='Print detailed results for all files')
    parser.add_argument('--no-recursive', action='store_true', help='Do not scan subdirectories')
    
    # Threshold argument
    parser.add_argument('-t', '--threshold', type=float, default=0.5, 
                       help='Base threshold for malware detection (we use 0.8 for high confidence, 0.2 for benign)')
    
    # Auto-remove argument
    parser.add_argument('--auto-remove', action='store_true', help='Automatically prompt to remove malware files after scan')
    
    args = parser.parse_args()
    
    # Get device
    device = get_device()
    print(f"{Fore.BLUE}🖥️  Using device:{Style.RESET_ALL} {device}")
    
    # Find and load model
    try:
        if args.model:
            model_path = args.model
        else:
            model_path = find_model_file()
        model = load_model(model_path, device)
    except Exception as e:
        print(f"{Fore.RED}Error loading model: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    
    start_time = time.time()
    
    # Scan file or directory
    if args.file:
        print(f"{Fore.BLUE}🔍 Scanning file:{Style.RESET_ALL} {args.file}")
        is_malware, malware_prob, status = scan_file(args.file, model, device, args.threshold)
        
        if status == "error":
            print(f"{Fore.RED}Error: {malware_prob}{Style.RESET_ALL}")
            return
        
        results = [{
            'file_path': args.file,
            'is_malware': is_malware,
            'malware_probability': malware_prob,
            'status': status
        }]
    else:
        print(f"{Fore.BLUE}🔍 Scanning directory:{Style.RESET_ALL} {args.directory}")
        results = scan_directory(
            args.directory, model, device, args.threshold,
            recursive=not args.no_recursive
        )
    
    # Print results
    elapsed_time = time.time() - start_time
    print(f"\n{Fore.BLUE}⏱️  Scan completed in {elapsed_time:.2f} seconds{Style.RESET_ALL}")
    malware_results, undetermined_results = print_results(results, verbose=args.verbose)
    
    # Handle malware files first
    if malware_results and (args.auto_remove or input(f"\n{Fore.RED}Would you like to handle the detected MALWARE files? (Y/n): {Style.RESET_ALL}").lower() != 'n'):
        remove_malware_files(malware_results)
    
    # Then handle undetermined files
    if undetermined_results and (args.auto_remove or input(f"\n{Fore.YELLOW}Would you like to handle the UNDETERMINED files? (y/N): {Style.RESET_ALL}").lower() == 'y'):
        print(f"{Fore.YELLOW}⚠️ These files have confidence between 20%-80% and might be malicious{Style.RESET_ALL}")
        remove_malware_files(undetermined_results)
    
    print(f"\n{Fore.CYAN}Thank you for using Harkonnen Antimalware!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()