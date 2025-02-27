#!/usr/bin/env python3
import os
import sys
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import queue
import platform
import shutil

class HarkonnenGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Harkonnen Antivirus")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Detect OS
        self.os_type = platform.system()
        
        # Set Harkonnen path based on OS
        if self.os_type == "Windows":
            self.harkonnen_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harkonnen.exe")
        else:
            self.harkonnen_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harkonnen")
        
        # Queue for handling output from subprocess
        self.output_queue = queue.Queue()
        
        # Create the main interface
        self.create_widgets()
        
        # Start queue processing
        self.process_queue()
        
    def create_widgets(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(title_frame, text="Harkonnen Antivirus", font=("Arial", 16, "bold")).pack(side=tk.LEFT)
        
        # System info
        system_info = f"Running on {self.os_type}"
        ttk.Label(title_frame, text=system_info, font=("Arial", 10)).pack(side=tk.RIGHT)
        
        # Create a notebook for different tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: Scan
        scan_frame = ttk.Frame(notebook, padding="10")
        notebook.add(scan_frame, text="Scan")
        self.create_scan_tab(scan_frame)
        
        # Tab 2: Monitor
        monitor_frame = ttk.Frame(notebook, padding="10")
        notebook.add(monitor_frame, text="Monitor")
        self.create_monitor_tab(monitor_frame)
        
        # Tab 3: Neural Network
        neural_frame = ttk.Frame(notebook, padding="10")
        notebook.add(neural_frame, text="Neural Network")
        self.create_neural_tab(neural_frame)
        
        # Tab 4: Settings
        settings_frame = ttk.Frame(notebook, padding="10")
        notebook.add(settings_frame, text="Settings")
        self.create_settings_tab(settings_frame)
        
        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)
        
        # Version info
        version_label = ttk.Label(status_frame, text="v1.0.0")
        version_label.pack(side=tk.RIGHT)
    
    def create_scan_tab(self, parent):
        # File selection frame
        file_frame = ttk.LabelFrame(parent, text="Target Selection", padding="10")
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.target_var = tk.StringVar()
        target_entry = ttk.Entry(file_frame, textvariable=self.target_var, width=60)
        target_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        browse_btn = ttk.Button(file_frame, text="Browse File", command=self.browse_file)
        browse_btn.pack(side=tk.LEFT, padx=5)
        
        browse_dir_btn = ttk.Button(file_frame, text="Browse Directory", command=self.browse_directory)
        browse_dir_btn.pack(side=tk.LEFT)
        
        # Scan options frame
        options_frame = ttk.LabelFrame(parent, text="Scan Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Left column of options
        left_options = ttk.Frame(options_frame)
        left_options.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.quick_var = tk.BooleanVar()
        ttk.Checkbutton(left_options, text="Quick Scan (hash only)", variable=self.quick_var).pack(anchor=tk.W)
        
        self.deep_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(left_options, text="Deep Scan (heuristics + PE analysis)", variable=self.deep_var).pack(anchor=tk.W)
        
        self.sandbox_var = tk.BooleanVar()
        ttk.Checkbutton(left_options, text="Run in Sandbox", variable=self.sandbox_var).pack(anchor=tk.W)
        
        # Right column of options
        right_options = ttk.Frame(options_frame)
        right_options.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.monitor_var = tk.BooleanVar()
        ttk.Checkbutton(right_options, text="API Monitoring", variable=self.monitor_var).pack(anchor=tk.W)
        
        self.neural_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(right_options, text="Neural Network Analysis", variable=self.neural_var).pack(anchor=tk.W)
        
        self.kill_var = tk.BooleanVar()
        ttk.Checkbutton(right_options, text="Kill Malicious Processes", variable=self.kill_var).pack(anchor=tk.W)
        
        # Action buttons
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, pady=10)
        
        scan_btn = ttk.Button(action_frame, text="Start Scan", command=self.start_scan)
        scan_btn.pack(side=tk.RIGHT, padx=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(parent, text="Scan Results", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=15)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
    
    def create_monitor_tab(self, parent):
        info_frame = ttk.Frame(parent, padding="10")
        info_frame.pack(fill=tk.X)
        
        ttk.Label(info_frame, text="System Monitoring", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        ttk.Separator(info_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        options_frame = ttk.Frame(parent)
        options_frame.pack(fill=tk.X, pady=10)
        
        self.api_hooking_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Detect API Hooking", variable=self.api_hooking_var).pack(anchor=tk.W)
        
        self.process_monitor_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Monitor Processes", variable=self.process_monitor_var).pack(anchor=tk.W)
        
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, pady=10)
        
        monitor_btn = ttk.Button(action_frame, text="Start Monitoring", command=self.start_monitoring)
        monitor_btn.pack(side=tk.RIGHT)
        
        # Output frame
        monitor_output_frame = ttk.LabelFrame(parent, text="Monitoring Results", padding="10")
        monitor_output_frame.pack(fill=tk.BOTH, expand=True)
        
        self.monitor_output = scrolledtext.ScrolledText(monitor_output_frame, wrap=tk.WORD, width=80, height=15)
        self.monitor_output.pack(fill=tk.BOTH, expand=True)
        self.monitor_output.config(state=tk.DISABLED)
    
    def create_neural_tab(self, parent):
        info_frame = ttk.Frame(parent, padding="10")
        info_frame.pack(fill=tk.X)
        
        ttk.Label(info_frame, text="BinSleuth Neural Network", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        ttk.Separator(info_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # File selection frame
        file_frame = ttk.Frame(parent)
        file_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(file_frame, text="Select file for neural network analysis:").pack(anchor=tk.W)
        
        selection_frame = ttk.Frame(file_frame)
        selection_frame.pack(fill=tk.X, pady=5)
        
        self.neural_file_var = tk.StringVar()
        neural_entry = ttk.Entry(selection_frame, textvariable=self.neural_file_var, width=60)
        neural_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        browse_nn_btn = ttk.Button(selection_frame, text="Browse", command=self.browse_neural_file)
        browse_nn_btn.pack(side=tk.LEFT)
        
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, pady=10)
        
        analyze_btn = ttk.Button(action_frame, text="Analyze with Neural Network", command=self.run_neural_analysis)
        analyze_btn.pack(side=tk.RIGHT)
        
        # Output frame
        neural_output_frame = ttk.LabelFrame(parent, text="Neural Network Results", padding="10")
        neural_output_frame.pack(fill=tk.BOTH, expand=True)
        
        self.neural_output = scrolledtext.ScrolledText(neural_output_frame, wrap=tk.WORD, width=80, height=15)
        self.neural_output.pack(fill=tk.BOTH, expand=True)
        self.neural_output.config(state=tk.DISABLED)
    
    def create_settings_tab(self, parent):
        info_frame = ttk.Frame(parent, padding="10")
        info_frame.pack(fill=tk.X)
        
        ttk.Label(info_frame, text="Harkonnen Settings", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        ttk.Separator(info_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Settings options
        options_frame = ttk.Frame(parent)
        options_frame.pack(fill=tk.X, pady=10)
        
        # Path settings
        path_frame = ttk.LabelFrame(options_frame, text="Harkonnen Path", padding="10")
        path_frame.pack(fill=tk.X, pady=5)
        
        self.harkonnen_path_var = tk.StringVar(value=self.harkonnen_path)
        path_entry = ttk.Entry(path_frame, textvariable=self.harkonnen_path_var, width=60)
        path_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        browse_path_btn = ttk.Button(path_frame, text="Browse", command=self.browse_harkonnen_path)
        browse_path_btn.pack(side=tk.LEFT)
        
        # Theme settings
        theme_frame = ttk.LabelFrame(options_frame, text="Interface Theme", padding="10")
        theme_frame.pack(fill=tk.X, pady=5)
        
        self.theme_var = tk.StringVar(value="System Default")
        themes = ["System Default", "Light", "Dark"]
        theme_combo = ttk.Combobox(theme_frame, textvariable=self.theme_var, values=themes, state="readonly")
        theme_combo.pack(fill=tk.X)
        
        # Action buttons
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, pady=10)
        
        save_btn = ttk.Button(action_frame, text="Save Settings", command=self.save_settings)
        save_btn.pack(side=tk.RIGHT, padx=5)
        
        build_btn = ttk.Button(action_frame, text="Build Harkonnen", command=self.build_harkonnen)
        build_btn.pack(side=tk.RIGHT)
        
        # About section
        about_frame = ttk.LabelFrame(parent, text="About", padding="10")
        about_frame.pack(fill=tk.X, expand=False, pady=20)
        
        about_text = """Harkonnen Antivirus v1.0.0
        
A toy antivirus system with multiple detection capabilities:
• File signature scanning
• PE file structure analysis
• Entropy analysis
• API hooking detection
• Behavioral analysis through sandboxing
• Neural network-based detection
• Process monitoring and termination

This is an educational project and should not be used as a primary security solution."""
        
        ttk.Label(about_frame, text=about_text, justify=tk.LEFT).pack(anchor=tk.W)
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select File to Scan",
            filetypes=[("All Files", "*.*"), ("Executables", "*.exe"), ("Libraries", "*.dll")]
        )
        if filename:
            self.target_var.set(filename)
    
    def browse_directory(self):
        dirname = filedialog.askdirectory(title="Select Directory to Scan")
        if dirname:
            self.target_var.set(dirname)
    
    def browse_neural_file(self):
        filename = filedialog.askopenfilename(
            title="Select File for Neural Analysis",
            filetypes=[("All Files", "*.*"), ("Executables", "*.exe"), ("Libraries", "*.dll")]
        )
        if filename:
            self.neural_file_var.set(filename)
    
    def browse_harkonnen_path(self):
        filename = filedialog.askopenfilename(
            title="Select Harkonnen Executable",
            filetypes=[("Executable", "*")]
        )
        if filename:
            self.harkonnen_path_var.set(filename)
            self.harkonnen_path = filename
    
    def save_settings(self):
        self.harkonnen_path = self.harkonnen_path_var.get()
        messagebox.showinfo("Settings", "Settings saved successfully!")
    
    def build_harkonnen(self):
        self.update_status("Building Harkonnen...")
        
        def run_build():
            try:
                if self.os_type == "Windows":
                    # Check for MinGW or Visual Studio (cl.exe)
                    if shutil.which("mingw32-make"):
                        cmd = ["mingw32-make", "-C", os.path.dirname(os.path.abspath(__file__))]
                    elif shutil.which("nmake"):
                        cmd = ["nmake", "/f", os.path.join(os.path.dirname(os.path.abspath(__file__)), "Makefile.win")]
                    elif shutil.which("msbuild"):
                        cmd = ["msbuild", os.path.join(os.path.dirname(os.path.abspath(__file__)), "Harkonnen.vcxproj")]
                    else:
                        self.output_queue.put(("error", "No compatible build tools found for Windows. Please install MinGW, Visual Studio or build tools."))
                        return
                else:
                    # Unix-based systems use regular make
                    cmd = ["make", "-C", os.path.dirname(os.path.abspath(__file__))]
                
                self.output_queue.put(("build", f"Running: {' '.join(cmd)}\n"))
                # On Windows, we need shell=True for some commands
                shell_needed = self.os_type == "Windows"
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                          universal_newlines=True, shell=shell_needed)
                
                for line in process.stdout:
                    self.output_queue.put(("build", line))
                
                process.wait()
                if process.returncode == 0:
                    self.output_queue.put(("status", "Build complete"))
                else:
                    self.output_queue.put(("error", f"Build failed with return code {process.returncode}"))
            except Exception as e:
                self.output_queue.put(("error", str(e)))
        
        threading.Thread(target=run_build, daemon=True).start()
    
    def start_scan(self):
        target = self.target_var.get()
        
        if not target:
            messagebox.showerror("Error", "Please select a file or directory to scan")
            return
        
        if not os.path.exists(self.harkonnen_path):
            msg = f"Harkonnen executable not found at {self.harkonnen_path}. Would you like to build it now?"
            if messagebox.askyesno("Build Required", msg):
                self.build_harkonnen()
                return
            else:
                return
        
        cmd = [self.harkonnen_path]
        
        # Add options
        if self.quick_var.get():
            cmd.append("-q")
        
        if self.deep_var.get():
            cmd.append("-d")
        
        if self.sandbox_var.get():
            cmd.append("-b")
        
        if self.monitor_var.get():
            cmd.append("-m")
        
        if self.neural_var.get():
            cmd.append("-n")
        
        if self.kill_var.get():
            cmd.append("-k")
        
        # Add target
        cmd.append(target)
        
        self.update_status(f"Scanning {target}...")
        self.clear_output()
        
        def run_scan():
            try:
                # On Windows, we need shell=True for some commands
                shell_needed = self.os_type == "Windows"
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                          universal_newlines=True, shell=shell_needed)
                
                for line in process.stdout:
                    self.output_queue.put(("scan", line))
                
                process.wait()
                self.output_queue.put(("status", "Scan complete"))
            except Exception as e:
                self.output_queue.put(("error", str(e)))
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def start_monitoring(self):
        if not os.path.exists(self.harkonnen_path):
            msg = f"Harkonnen executable not found at {self.harkonnen_path}. Would you like to build it now?"
            if messagebox.askyesno("Build Required", msg):
                self.build_harkonnen()
                return
            else:
                return
        
        cmd = [self.harkonnen_path, "-m"]
        
        if self.api_hooking_var.get():
            cmd.append("-d")  # Deep scan includes API hooking detection
        
        self.update_status("Monitoring system...")
        self.clear_monitor_output()
        
        def run_monitor():
            try:
                # On Windows, we need shell=True for some commands
                shell_needed = self.os_type == "Windows"
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                          universal_newlines=True, shell=shell_needed)
                
                for line in process.stdout:
                    self.output_queue.put(("monitor", line))
                
                process.wait()
                self.output_queue.put(("status", "Monitoring complete"))
            except Exception as e:
                self.output_queue.put(("error", str(e)))
        
        threading.Thread(target=run_monitor, daemon=True).start()
    
    def run_neural_analysis(self):
        target = self.neural_file_var.get()
        
        if not target:
            messagebox.showerror("Error", "Please select a file for neural analysis")
            return
        
        self.update_status(f"Analyzing {target} with neural network...")
        self.clear_neural_output()
        
        python_cmd = sys.executable
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_binsleuth.py")
        
        cmd = [python_cmd, script_path, target]
        
        def run_analysis():
            try:
                # On Windows, we need shell=True for some commands
                shell_needed = self.os_type == "Windows"
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                          universal_newlines=True, shell=shell_needed)
                
                for line in process.stdout:
                    self.output_queue.put(("neural", line))
                
                process.wait()
                if process.returncode == 0:
                    self.output_queue.put(("neural", "\nNeural network analysis: File appears to be clean\n"))
                else:
                    self.output_queue.put(("neural", "\nWARNING: Neural network detected malicious behavior!\n"))
                
                self.output_queue.put(("status", "Neural analysis complete"))
            except Exception as e:
                self.output_queue.put(("error", str(e)))
        
        threading.Thread(target=run_analysis, daemon=True).start()
    
    def update_status(self, message):
        self.status_var.set(message)
    
    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def clear_monitor_output(self):
        self.monitor_output.config(state=tk.NORMAL)
        self.monitor_output.delete(1.0, tk.END)
        self.monitor_output.config(state=tk.DISABLED)
    
    def clear_neural_output(self):
        self.neural_output.config(state=tk.NORMAL)
        self.neural_output.delete(1.0, tk.END)
        self.neural_output.config(state=tk.DISABLED)
    
    def add_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def add_monitor_output(self, text):
        self.monitor_output.config(state=tk.NORMAL)
        self.monitor_output.insert(tk.END, text)
        self.monitor_output.see(tk.END)
        self.monitor_output.config(state=tk.DISABLED)
    
    def add_neural_output(self, text):
        self.neural_output.config(state=tk.NORMAL)
        self.neural_output.insert(tk.END, text)
        self.neural_output.see(tk.END)
        self.neural_output.config(state=tk.DISABLED)
    
    def process_queue(self):
        try:
            while True:
                message_type, message = self.output_queue.get_nowait()
                
                if message_type == "scan":
                    self.add_output(message)
                elif message_type == "monitor":
                    self.add_monitor_output(message)
                elif message_type == "neural":
                    self.add_neural_output(message)
                elif message_type == "build":
                    self.add_output(message)
                elif message_type == "status":
                    self.update_status(message)
                elif message_type == "error":
                    messagebox.showerror("Error", message)
                    self.update_status("Ready")
                
                self.output_queue.task_done()
        except queue.Empty:
            # Re-run after 100ms
            self.root.after(100, self.process_queue)


if __name__ == "__main__":
    root = tk.Tk()
    app = HarkonnenGUI(root)
    root.mainloop()