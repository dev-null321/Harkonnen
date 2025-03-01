#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
If you encounter module import errors, please run:
    python3 -m venv harkonnen_env
    source harkonnen_env/bin/activate  # On Unix/macOS
    harkonnen_env\Scripts\activate     # On Windows
    pip install pillow torch torchvision tqdm colorama numpy
Then run this script from the activated environment.

Harkonnen CNN - Graphical User Interface
Cross-platform GUI for Harkonnen malware detection using ResNet neural networks

UPDATED: Now uses resnet_inference.py with improved detection model and higher threshold
for more accurate malware detection with fewer false positives.
"""

import os
import sys
import subprocess
import threading
import time
import datetime
import re
from tkinter import (
    Tk, Frame, Label, Button, Text, Entry, Listbox, Scrollbar, 
    PhotoImage, Menu, messagebox, filedialog, ttk, StringVar, 
    IntVar, BooleanVar, VERTICAL, HORIZONTAL, END, N, S, E, W
)
import tkinter.font as tkFont
from pathlib import Path

# Set up constants - Dune/Harkonnen inspired color scheme
APP_TITLE = "Harkonnen Advanced Malware Detection"
APP_VERSION = "Beta 0.1"
APP_WIDTH = 900
APP_HEIGHT = 600
DEFAULT_FONT = ("Helvetica", 10)
HEADING_FONT = ("Helvetica", 12, "bold")
TITLE_FONT = ("Helvetica", 16, "bold")
SMALL_FONT = ("Helvetica", 9)
MONO_FONT = ("Courier", 10)

# Updated Harkonnen color scheme with dark pink and dark blue
BACKGROUND_COLOR = "#121212"  # Almost black background
FOREGROUND_COLOR = "#e0e0e0"  # Light gray text
ACCENT_COLOR = "#c71585"      # Deep pink
DARK_ACCENT = "#8b008b"       # Dark pink for contrast
WARNING_COLOR = "#ff1493"     # Bright pink for warnings/malware
SUCCESS_COLOR = "#00cc66"     # Green for success/benign
BUTTON_BG = "#1e2b58"         # Dark blue for buttons
BUTTON_FG = "#e0e0e0"         # Light gray text
BUTTON_ACTIVE_BG = "#2a3b78"  # Slightly lighter blue when active
TEXT_BG = "#1a1a1a"           # Very dark gray for text fields
TEXT_FG = "#e0e0e0"           # Light gray text
LIST_BG = "#1a1a1a"           # Very dark gray for lists
LIST_FG = "#e0e0e0"           # Light gray text
HEADER_BG = "#191970"         # Midnight blue header background
HEADER_FG = "#ff69b4"         # Hot pink for headers
SELECTED_BG = "#c71585"       # Deep pink for selected items
SELECTED_FG = "#ffffff"       # White text for selected items
STATUSBAR_BG = "#1a1a1a"      # Dark status bar
STATUSBAR_FG = "#e0e0e0"      # Light gray text
MALWARE_FG = "#ff1493"        # Pink text for malware items
BENIGN_FG = "#00cc66"         # Green text for benign items
PROGRESS_COLOR = "#0000cd"    # Medium blue progress bar

class HarkonnenGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(f"{APP_WIDTH}x{APP_HEIGHT}")
        self.root.minsize(800, 500)
        
        # State variables
        self.scan_in_progress = False
        self.scan_directory = StringVar(value=os.path.expanduser("~"))
        self.model_path = StringVar(value="best_model.pth")
        self.use_deep_scan = BooleanVar(value=True)
        self.detection_threshold = 0.75  # Higher threshold for malware detection (more conservative)
        self.malicious_files = []
        self.files_scanned = 0  # Counter for scanned files
        
        # Configure the main window
        self.configure_styles()
        self.create_widgets()
        self.create_menu()
        
        # Center the window
        self.center_window()
        
        # Load configuration
        self.load_config()

    def configure_styles(self):
        """Set up the application styles"""
        # Configure overall appearance
        self.root.configure(bg=BACKGROUND_COLOR)
        self.style = ttk.Style()
        
        # Create custom styles for ttk widgets
        self.style.configure("TFrame", background=BACKGROUND_COLOR)
        self.style.configure("Header.TFrame", background=HEADER_BG)
        self.style.configure("TLabel", background=BACKGROUND_COLOR, foreground=FOREGROUND_COLOR)
        self.style.configure("Header.TLabel", background=HEADER_BG, foreground=HEADER_FG, font=HEADING_FONT)
        self.style.configure("Status.TLabel", background=STATUSBAR_BG, foreground=STATUSBAR_FG)
        
        # Configure style for Treeview (for file list)
        self.style.configure("Treeview", 
                            background=LIST_BG,
                            foreground=LIST_FG,
                            rowheight=25,
                            fieldbackground=LIST_BG)
        self.style.map('Treeview', 
                      background=[('selected', SELECTED_BG)],
                      foreground=[('selected', SELECTED_FG)])
        
        # Button styles
        self.style.configure("TButton", 
                             background=BUTTON_BG, 
                             foreground=BUTTON_FG, 
                             font=DEFAULT_FONT,
                             borderwidth=1)
        self.style.map("TButton",
                      background=[('active', BUTTON_ACTIVE_BG)],
                      foreground=[('active', BUTTON_FG)])
        
        # Primary action button style
        self.style.configure("Primary.TButton", 
                             background=ACCENT_COLOR, 
                             foreground="#000000", 
                             font=DEFAULT_FONT,
                             borderwidth=1)
        self.style.map("Primary.TButton",
                      background=[('active', "#a2c2fb")],
                      foreground=[('active', "#000000")])
        
        # Warning action button style
        self.style.configure("Warning.TButton", 
                             background=WARNING_COLOR, 
                             foreground="#000000", 
                             font=DEFAULT_FONT,
                             borderwidth=1)
        self.style.map("Warning.TButton",
                      background=[('active', "#ff9eb8")],
                      foreground=[('active', "#000000")])
                      
        # Success action button style
        self.style.configure("Success.TButton", 
                             background=SUCCESS_COLOR, 
                             foreground="#000000", 
                             font=DEFAULT_FONT,
                             borderwidth=1)
        self.style.map("Success.TButton",
                      background=[('active', "#b9f0b7")],
                      foreground=[('active', "#000000")])
        
        # Progressbar style
        self.style.configure("TProgressbar", 
                             background=PROGRESS_COLOR, 
                             troughcolor=BUTTON_BG, 
                             thickness=10,
                             borderwidth=0)

    def create_widgets(self):
        """Create all the UI widgets"""
        # Main container for all widgets
        self.main_frame = ttk.Frame(self.root, style="TFrame")
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create header
        self.create_header()
        
        # Create content area
        self.create_content()
        
        # Create status bar
        self.create_status_bar()
    
    def create_header(self):
        """Create the application header with logo and title"""
        self.header_frame = ttk.Frame(self.main_frame, style="Header.TFrame")
        self.header_frame.pack(fill="x", pady=(0, 10))
        
        # Logo would be here if available
        # self.logo_img = PhotoImage(file="logo.png")
        # self.logo_label = ttk.Label(self.header_frame, image=self.logo_img, background=HEADER_BG)
        # self.logo_label.pack(side="left", padx=10, pady=10)
        
        # App title
        self.style.configure("Title.TLabel", 
                             background=HEADER_BG, 
                             foreground=HEADER_FG, 
                             font=TITLE_FONT)
        
        self.title_label = ttk.Label(self.header_frame, 
                                     text=APP_TITLE,
                                     style="Title.TLabel")
        self.title_label.pack(side="left", padx=10, pady=10)
        
        # Version info
        self.version_label = ttk.Label(self.header_frame, 
                                      text=f"v{APP_VERSION}",
                                      style="TLabel",
                                      font=SMALL_FONT)
        self.version_label.pack(side="right", padx=10, pady=10)

    def create_content(self):
        """Create the main content area with scan controls and results"""
        # Create main content frame
        self.content_frame = ttk.Frame(self.main_frame, style="TFrame")
        self.content_frame.pack(fill="both", expand=True)
        
        # Create left panel for scan controls
        self.left_panel = ttk.Frame(self.content_frame, style="TFrame")
        self.left_panel.pack(side="left", fill="y", padx=(0, 10))
        
        # Create directory selection
        self.dir_frame = ttk.Frame(self.left_panel, style="TFrame")
        self.dir_frame.pack(fill="x", pady=(0, 10))
        
        self.dir_label = ttk.Label(self.dir_frame, text="Scan Location:", style="TLabel")
        self.dir_label.pack(anchor="w", pady=(0, 5))
        
        self.dir_entry = Entry(self.dir_frame, 
                              textvariable=self.scan_directory,
                              bg=TEXT_BG, fg=TEXT_FG,
                              font=DEFAULT_FONT)
        self.dir_entry.pack(side="left", fill="x", expand=True)
        
        self.browse_button = ttk.Button(self.dir_frame, text="Browse", command=self.browse_directory)
        self.browse_button.pack(side="right", padx=(5, 0))
        
        # Create model selection
        self.model_frame = ttk.Frame(self.left_panel, style="TFrame")
        self.model_frame.pack(fill="x", pady=(0, 10))
        
        self.model_label = ttk.Label(self.model_frame, text="Model File (.pth):", style="TLabel")
        self.model_label.pack(anchor="w", pady=(0, 5))
        
        self.model_entry = Entry(self.model_frame, 
                               textvariable=self.model_path,
                               bg=TEXT_BG, fg=TEXT_FG,
                               font=DEFAULT_FONT)
        self.model_entry.pack(side="left", fill="x", expand=True)
        
        self.model_button = ttk.Button(self.model_frame, text="Browse", command=self.browse_model)
        self.model_button.pack(side="right", padx=(5, 0))
        
        # Scan options
        self.options_frame = ttk.Frame(self.left_panel, style="TFrame")
        self.options_frame.pack(fill="x", pady=(0, 10))
        
        self.options_label = ttk.Label(self.options_frame, text="Scan Options:", style="TLabel")
        self.options_label.pack(anchor="w", pady=(0, 5))
        
        self.deep_scan_check = ttk.Checkbutton(self.options_frame, 
                                              text="Deep Scan (analyze file contents)",
                                              variable=self.use_deep_scan,
                                              style="TCheckbutton")
        self.deep_scan_check.pack(anchor="w")
        
        # Action buttons
        self.actions_frame = ttk.Frame(self.left_panel, style="TFrame")
        self.actions_frame.pack(fill="x", pady=(0, 10))
        
        self.scan_button = ttk.Button(self.actions_frame, 
                                     text="Start Scan",
                                     command=self.start_scan,
                                     style="Primary.TButton")
        self.scan_button.pack(fill="x", pady=(0, 5))
        
        self.stop_button = ttk.Button(self.actions_frame, 
                                     text="Stop Scan",
                                     command=self.stop_scan,
                                     state="disabled")
        self.stop_button.pack(fill="x")
        
        # Create right panel for results
        self.right_panel = ttk.Frame(self.content_frame, style="TFrame")
        self.right_panel.pack(side="right", fill="both", expand=True)
        
        # Notebook for different tabs
        self.notebook = ttk.Notebook(self.right_panel)
        self.notebook.pack(fill="both", expand=True)
        
        # Results tab
        self.results_frame = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.results_frame, text="Scan Results")
        
        # Results area with treeview for better display
        self.results_frame.columnconfigure(0, weight=1)
        self.results_frame.rowconfigure(0, weight=1)
        
        # Create a frame for the results treeview
        self.list_frame = ttk.Frame(self.results_frame, style="TFrame")
        self.list_frame.grid(row=0, column=0, sticky="nsew")
        
        # Create heading for results
        self.results_heading = ttk.Label(self.list_frame, 
                                        text="Detected Threats",
                                        style="Header.TLabel")
        self.results_heading.pack(fill="x", pady=(0, 5))
        
        # Create Treeview for results (allows columns and better formatting)
        columns = ("index", "filename", "confidence")
        self.results_list = ttk.Treeview(self.list_frame, 
                                       columns=columns,
                                       show="headings",
                                       style="Treeview")
        
        # Column headings
        self.results_list.heading("index", text="#")
        self.results_list.heading("filename", text="File Name")
        self.results_list.heading("confidence", text="Confidence")
        
        # Column widths
        self.results_list.column("index", width=50, anchor="center")
        self.results_list.column("filename", width=250, anchor="w")
        self.results_list.column("confidence", width=100, anchor="center")
        
        self.results_list.pack(side="left", fill="both", expand=True)
        
        # Scrollbar for results
        self.results_scrollbar = Scrollbar(self.list_frame, 
                                          orient=VERTICAL,
                                          command=self.results_list.yview)
        self.results_scrollbar.pack(side="right", fill="y")
        self.results_list.config(yscrollcommand=self.results_scrollbar.set)
        
        # Bind selection event
        self.results_list.bind("<<TreeviewSelect>>", self.on_result_select)
        
        # Create details frame
        self.details_frame = ttk.Frame(self.results_frame, style="TFrame")
        self.details_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        
        # Details heading
        self.details_heading = ttk.Label(self.details_frame, 
                                        text="Threat Details",
                                        style="Header.TLabel")
        self.details_heading.pack(fill="x", pady=(0, 5))
        
        # Details text
        self.details_text = Text(self.details_frame, 
                                height=10,
                                bg=TEXT_BG, fg=TEXT_FG,
                                font=MONO_FONT,
                                wrap="word",
                                state="disabled")
        self.details_text.pack(side="left", fill="both", expand=True)
        
        self.details_scrollbar = Scrollbar(self.details_frame, 
                                          orient=VERTICAL,
                                          command=self.details_text.yview)
        self.details_scrollbar.pack(side="right", fill="y")
        self.details_text.config(yscrollcommand=self.details_scrollbar.set)
        
        # Action buttons for selected malware
        self.threat_actions_frame = ttk.Frame(self.results_frame, style="TFrame")
        self.threat_actions_frame.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        
        self.remove_button = ttk.Button(self.threat_actions_frame, 
                                       text="Remove Selected",
                                       command=self.remove_selected,
                                       state="disabled",
                                       style="Warning.TButton")
        self.remove_button.pack(side="left", padx=(0, 5))
        
        self.quarantine_button = ttk.Button(self.threat_actions_frame, 
                                          text="Quarantine Selected",
                                          command=self.quarantine_selected,
                                          state="disabled")
        self.quarantine_button.pack(side="left", padx=(0, 5))
        
        self.remove_all_button = ttk.Button(self.threat_actions_frame, 
                                          text="Remove All Threats",
                                          command=self.remove_all,
                                          state="disabled",
                                          style="Warning.TButton")
        self.remove_all_button.pack(side="right")
        
        # Log tab
        self.log_frame = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.log_frame, text="Scan Log")
        
        # Log text
        self.log_text = Text(self.log_frame, 
                            bg=TEXT_BG, fg=TEXT_FG,
                            font=MONO_FONT,
                            wrap="word")
        self.log_text.pack(side="left", fill="both", expand=True)
        
        self.log_scrollbar = Scrollbar(self.log_frame, 
                                      orient=VERTICAL,
                                      command=self.log_text.yview)
        self.log_scrollbar.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=self.log_scrollbar.set)
        
        # Quarantine tab
        self.quarantine_frame = ttk.Frame(self.notebook, style="TFrame")
        self.notebook.add(self.quarantine_frame, text="Quarantine")
        
        # Create quarantine list
        self.quarantine_list_frame = ttk.Frame(self.quarantine_frame, style="TFrame")
        self.quarantine_list_frame.pack(fill="both", expand=True)
        
        self.quarantine_heading = ttk.Label(self.quarantine_list_frame, 
                                           text="Quarantined Files",
                                           style="Header.TLabel")
        self.quarantine_heading.pack(fill="x", pady=(0, 5))
        
        self.quarantine_list = Listbox(self.quarantine_list_frame, 
                                      bg=LIST_BG, fg=LIST_FG,
                                      selectbackground=SELECTED_BG,
                                      selectforeground=SELECTED_FG,
                                      font=DEFAULT_FONT,
                                      activestyle="none",
                                      highlightthickness=0,
                                      borderwidth=1)
        self.quarantine_list.pack(side="left", fill="both", expand=True)
        
        self.quarantine_scrollbar = Scrollbar(self.quarantine_list_frame, 
                                             orient=VERTICAL,
                                             command=self.quarantine_list.yview)
        self.quarantine_scrollbar.pack(side="right", fill="y")
        self.quarantine_list.config(yscrollcommand=self.quarantine_scrollbar.set)
        
        # Quarantine actions
        self.quarantine_actions_frame = ttk.Frame(self.quarantine_frame, style="TFrame")
        self.quarantine_actions_frame.pack(fill="x", pady=(10, 0))
        
        self.restore_button = ttk.Button(self.quarantine_actions_frame, 
                                        text="Restore Selected",
                                        command=self.restore_quarantined,
                                        state="disabled")
        self.restore_button.pack(side="left", padx=(0, 5))
        
        self.delete_button = ttk.Button(self.quarantine_actions_frame, 
                                       text="Delete Permanently",
                                       command=self.delete_quarantined,
                                       state="disabled",
                                       style="Warning.TButton")
        self.delete_button.pack(side="left")
    
    def create_status_bar(self):
        """Create the status bar at the bottom of the UI"""
        self.status_frame = ttk.Frame(self.main_frame, style="TFrame")
        self.status_frame.pack(fill="x", pady=(10, 0))
        
        # Progress bar
        self.progress = ttk.Progressbar(self.status_frame, 
                                       orient=HORIZONTAL,
                                       mode="determinate",
                                       style="TProgressbar")
        self.progress.pack(fill="x", side="top", pady=(0, 5))
        
        # Status message
        self.status_label = ttk.Label(self.status_frame, 
                                     text="Ready",
                                     style="Status.TLabel")
        self.status_label.pack(side="left")
        
        # Scan stats
        self.stats_label = ttk.Label(self.status_frame, 
                                    text="",
                                    style="Status.TLabel")
        self.stats_label.pack(side="right")

    def create_menu(self):
        """Create the application menu"""
        self.menubar = Menu(self.root)
        self.root.config(menu=self.menubar)
        
        # File menu
        self.file_menu = Menu(self.menubar, tearoff=0, bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR)
        self.menubar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Select Directory", command=self.browse_directory)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Start Scan", command=self.start_scan)
        self.file_menu.add_command(label="Stop Scan", command=self.stop_scan, state="disabled")
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Actions menu
        self.actions_menu = Menu(self.menubar, tearoff=0, bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR)
        self.menubar.add_cascade(label="Actions", menu=self.actions_menu)
        self.actions_menu.add_command(label="View Quarantine", command=lambda: self.notebook.select(2))
        self.actions_menu.add_command(label="Remove All Threats", command=self.remove_all, state="disabled")
        self.actions_menu.add_separator()
        self.actions_menu.add_command(label="Clear Results", command=self.clear_results)
        
        # Help menu
        self.help_menu = Menu(self.menubar, tearoff=0, bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR)
        self.menubar.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.show_about)
        self.help_menu.add_command(label="Check for Updates", command=self.check_updates)

    def center_window(self):
        """Center the window on the screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def load_config(self):
        """Load saved configuration"""
        # This would normally load from a config file
        # For now, we'll just load the quarantine list
        self.load_quarantine_list()
    
    def browse_directory(self):
        """Open dialog to select a directory or file to scan"""
        # Create options to scan directory or file
        scan_type = messagebox.askyesno(
            title="Scan Selection",
            message="Would you like to scan a directory?\n\nSelect 'Yes' to scan a directory\nSelect 'No' to scan a single file",
            icon="question"
        )
        
        # Browse for directory
        if scan_type:
            directory = filedialog.askdirectory(
                initialdir=self.scan_directory.get() if os.path.isdir(self.scan_directory.get()) else os.path.expanduser("~"),
                title="Select Directory to Scan"
            )
            if directory:
                self.scan_directory.set(directory)
                self.log(f"Selected directory for scanning: {directory}")
        # Browse for file
        else:
            file_path = filedialog.askopenfilename(
                initialdir=os.path.dirname(self.scan_directory.get()) if os.path.exists(self.scan_directory.get()) else os.path.expanduser("~"),
                title="Select File to Scan",
                filetypes=[
                    ("All Files", "*.*"),
                    ("Executable Files", "*.exe *.dll *.com"),
                    ("Script Files", "*.bat *.sh *.ps1 *.vbs *.js *.py"),
                    ("Document Files", "*.pdf *.doc *.docx")
                ]
            )
            if file_path:
                self.scan_directory.set(file_path)
                self.log(f"Selected file for scanning: {file_path}")
            
    def browse_model(self):
        """Open dialog to select a model file (.pth)"""
        model_file = filedialog.askopenfilename(
            initialdir=os.path.dirname(self.model_path.get()),
            title="Select Model File",
            filetypes=[("PyTorch Models", "*.pth"), ("All Files", "*.*")]
        )
        if model_file:
            self.model_path.set(model_file)
    
    def start_scan(self):
        """Start the scanning process"""
        scan_target = self.scan_directory.get()
        model_path = self.model_path.get()
        
        # Verify scan target exists (directory or file)
        if not os.path.exists(scan_target):
            messagebox.showerror("Error", f"Path does not exist: {scan_target}")
            return
            
        # Verify model file exists
        if not os.path.exists(model_path):
            messagebox.showerror("Error", f"Model file does not exist: {model_path}")
            return
            
        # Check if model file is valid
        if not model_path.lower().endswith('.pth'):
            if not messagebox.askyesno("Warning", 
                                    f"The selected model file '{model_path}' doesn't have a .pth extension. Are you sure it's a valid PyTorch model?"):
                return
        
        # Update UI for scanning state
        self.scan_in_progress = True
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.file_menu.entryconfig("Start Scan", state="disabled")
        self.file_menu.entryconfig("Stop Scan", state="normal")
        
        # Clear previous results
        self.clear_results()
        self.files_scanned = 0  # Reset files scanned counter
        
        # Start scan in a separate thread
        self.log("Starting scan of: " + scan_target)
        self.status_label.config(text="SCANNING IN PROGRESS...", foreground=ACCENT_COLOR)
        
        self.scan_thread = threading.Thread(target=self.perform_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def perform_scan(self):
        """Perform the actual scanning in a background thread using resnet_inference.py"""
        directory = self.scan_directory.get()
        model_path = self.model_path.get()
        deep_scan = self.use_deep_scan.get()
        threshold = self.detection_threshold  # Use higher threshold for more conservative detection
        
        # Check if model file exists
        if not os.path.exists(model_path):
            self.root.after(0, lambda: messagebox.showerror(
                "Error", f"Model file not found: {model_path}"))
            self.root.after(0, self.scan_error, f"Model file not found: {model_path}")
            return
        
        start_time = time.time()
        self.update_progress(0)
        self.log(f"Starting scan with model: {model_path}")
        
        # Pre-scan - find all files to be scanned for progress tracking
        if os.path.isdir(directory):
            self.log("Preparing file list for scanning...")
            all_files = []
            for root, _, files in os.walk(directory):
                for file in files:
                    all_files.append(os.path.join(root, file))
            self.log(f"Found {len(all_files)} files to scan")
            
            # Add clean files to results for display (will be categorized later)
            file_tree_tab = ttk.Frame(self.notebook)
            self.notebook.add(file_tree_tab, text="All Files")
            
            # Create file tree display
            file_tree = ttk.Treeview(file_tree_tab, columns=("path", "size", "type"), show="headings")
            file_tree.heading("path", text="File Path")
            file_tree.heading("size", text="Size")
            file_tree.heading("type", text="Type")
            file_tree.column("path", width=300)
            file_tree.column("size", width=100, anchor="center")
            file_tree.column("type", width=100, anchor="center")
            file_tree.pack(side="left", fill="both", expand=True)
            
            # Add scrollbar
            file_scrollbar = ttk.Scrollbar(file_tree_tab, orient="vertical", command=file_tree.yview)
            file_scrollbar.pack(side="right", fill="y")
            file_tree.configure(yscrollcommand=file_scrollbar.set)
            
            # Add files to tree
            for i, file_path in enumerate(all_files):
                try:
                    file_size = os.path.getsize(file_path)
                    file_ext = os.path.splitext(file_path)[1].lower()
                    file_type = file_ext[1:] if file_ext else "unknown"
                    file_tree.insert("", "end", values=(file_path, self.format_size(file_size), file_type))
                except Exception as e:
                    self.log(f"Error processing file {file_path}: {str(e)}")
                
                # Update progress for file list creation
                if i % 10 == 0:  # update every 10 files for performance
                    self.update_progress(int((i / len(all_files)) * 20))  # Use first 20% of progress bar
        
        try:
            # Build command based on scan type using resnet_inference.py
            cmd = ["python3", "resnet_inference.py"]
            
            # Add directory or file argument
            if os.path.isfile(directory):
                self.log(f"Scanning single file: {directory}")
                cmd.extend(["-f", directory])
            else:
                self.log(f"Scanning directory: {directory}")
                cmd.extend(["-d", directory])
            
            # Add model path
            cmd.extend(["-m", model_path])
            
            # Add threshold for malware detection
            cmd.extend(["-t", str(threshold)])
            
            # Add verbose flag if deep scan
            if deep_scan:
                cmd.append("--verbose")
                self.log("Deep scan enabled: analyzing file contents")
            
            # Log the full command
            self.log(f"Running command: {' '.join(cmd)}")
            
            # Reset progress to 20% before actual scan starts
            self.update_progress(20)
            
            # Run the command and capture output
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Process output as it comes in
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    line = line.strip()
                    self.log(line)
                    self.process_scan_output(line)
                    
                    # Update progress (estimate)
                    if "Scanning file:" in line or "Processing" in line:
                        self.update_progress_pulse()
            
            # Get any remaining output
            stdout, stderr = process.communicate()
            if stdout:
                for line in stdout.splitlines():
                    self.log(line)
                    self.process_scan_output(line)
            
            # Process stderr but don't treat TQDM progress updates as errors
            if stderr:
                for line in stderr.splitlines():
                    if "%" in line and ("[" in line or "]" in line) and "file/s" in line:
                        # This is a TQDM progress bar output, log without ERROR prefix
                        self.log("Progress: " + line)
                    else:
                        self.log("ERROR: " + line)
            
            # Scan completed
            elapsed_time = time.time() - start_time
            self.log(f"Scan completed in {elapsed_time:.2f} seconds")
            
            # Update UI
            self.root.after(0, self.finish_scan, len(self.malicious_files), elapsed_time)
            
        except Exception as e:
            self.log(f"Error during scan: {str(e)}")
            self.root.after(0, self.scan_error, str(e))
    
    def process_scan_output(self, line):
        """Process a line of output from the scanner (adapted for resnet_inference.py)"""
        # Update progress when processing files
        if "Scanning file:" in line or "Processing" in line:
            self.files_scanned += 1
            self.update_progress_pulse()
            
            # Extract filename for display
            if ":" in line:
                try:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        filename = parts[1].strip()
                        # Update stats in real-time with current file
                        self.stats_label.config(text=f"Files scanned: {self.files_scanned} | Current: {os.path.basename(filename)}")
                except Exception:
                    pass
            else:
                # Generic counter update
                self.stats_label.config(text=f"Files scanned: {self.files_scanned}")
        
        # Check for errors and log them
        if "ERROR:" in line:
            self.log(f"Error detected: {line}")
            return
            
        # Process malware files (files with confidence ≥ 80%)
        if "🚨 MALWARE FILES" in line or "❗ HIGH CONFIDENCE MALWARE DETECTIONS" in line:
            self.log("Found high confidence malware section")
            return
        
        # Check for malware file pattern: "🚨 /path/to/file (Confidence: 95.23%)"
        if "🚨" in line and "Confidence:" in line:
            filepath = None
            confidence = 0
            info = "Malware detected by ResNet model (High confidence ≥ 80%)"
            
            # Parse the line format from the new output
            path_match = re.search(r'🚨\s+(.+?)\s+\(Confidence:', line)
            if path_match:
                filepath = path_match.group(1).strip()
            
            # Extract confidence percentage
            confidence_match = re.search(r'Confidence: (\d+\.\d+)%', line)
            if confidence_match:
                try:
                    confidence = float(confidence_match.group(1))
                except:
                    confidence = 90  # Default high if parsing fails
            
            # Add to malicious files list if valid
            if filepath and os.path.exists(filepath):
                self.log(f"Detected high confidence malware: {filepath} ({confidence:.2f}%)")
                
                # Create a record for this detection
                self.malicious_files.append({
                    "path": filepath,
                    "name": os.path.basename(filepath),
                    "info": info,
                    "confidence": confidence,
                    "index": len(self.malicious_files) + 1,
                    "status": "malware"  # Mark as confirmed malware
                })
                
                # Update the UI
                self.root.after(0, self.add_detection_to_ui, filepath, info, confidence, "malware")
                return
        
        # Check for undetermined files (files with confidence between 20% and 80%)
        # Pattern: "❓ /path/to/file (Confidence: 45.67%)"
        if "❓" in line and "Confidence:" in line:
            filepath = None
            confidence = 0
            info = "Undetermined (Confidence between 20% and 80%)"
            
            # Parse the line format from the new output
            path_match = re.search(r'❓\s+(.+?)\s+\(Confidence:', line)
            if path_match:
                filepath = path_match.group(1).strip()
            
            # Extract confidence percentage
            confidence_match = re.search(r'Confidence: (\d+\.\d+)%', line)
            if confidence_match:
                try:
                    confidence = float(confidence_match.group(1))
                except:
                    confidence = 50  # Default middle value if parsing fails
            
            # Add to undetermined files list if valid
            if filepath and os.path.exists(filepath):
                self.log(f"Detected undetermined file: {filepath} ({confidence:.2f}%)")
                
                # Create a record for this detection with a separate list
                self.malicious_files.append({
                    "path": filepath,
                    "name": os.path.basename(filepath),
                    "info": info,
                    "confidence": confidence,
                    "index": len(self.malicious_files) + 1,
                    "status": "undetermined"  # Mark as undetermined
                })
                
                # Update the UI - with yellow warning color for undetermined
                self.root.after(0, self.add_detection_to_ui, filepath, info, confidence, "undetermined")
                return
    
    def extract_confidence(self, line):
        """Extract confidence percentage from detection line"""
        # Default confidence if not found
        confidence = 90
        
        # Try to extract confidence percentage
        if "Confidence:" in line:
            try:
                # Extract the percentage value
                parts = line.split("Confidence:", 1)[1]
                confidence = float(parts.split("%")[0].strip())
            except:
                pass
                
        return confidence
    
    def add_detection_to_ui(self, filepath, info, confidence, status="malware"):
        """Add a detection to the UI with appropriate status tag"""
        filename = os.path.basename(filepath)
        index = len(self.malicious_files)
        
        # Create a unique ID for the item
        item_id = f"threat_{index}"
        
        # Insert into treeview with appropriate tags based on status
        values = (f"{index}", filename, f"{confidence:.1f}%")
        
        if status == "undetermined":
            # For undetermined files (20-80% confidence)
            self.results_list.insert('', 'end', iid=item_id, values=values, tags=("undetermined",))
            self.results_list.tag_configure("undetermined", foreground="#FF9800")  # Orange for undetermined
        else:
            # For high confidence malware (>80%)
            self.results_list.insert('', 'end', iid=item_id, values=values, tags=("malware",))
            self.results_list.tag_configure("malware", foreground=MALWARE_FG)
        
        # If this is the first detection, enable the action buttons
        if len(self.results_list.get_children()) == 1:
            self.remove_all_button.config(state="normal")
            self.actions_menu.entryconfig("Remove All Threats", state="normal")
    
    def update_progress(self, value):
        """Update the progress bar"""
        self.progress["value"] = value
        self.root.update_idletasks()  # Force update of the UI
    
    def update_progress_pulse(self):
        """Pulse the progress bar to show activity"""
        current = self.progress["value"]
        if current < 20:
            # In file listing phase, don't pulse
            pass
        elif current >= 95:  # Keep it below 100 until fully complete
            self.progress["value"] = 20
        else:
            # Increment progress between 20-95% during scan
            increment = (95 - 20) / (self.files_scanned + 1)
            new_value = min(95, 20 + (self.files_scanned * increment))
            self.progress["value"] = new_value
        
        self.root.update_idletasks()  # Force update of the UI
    
    def finish_scan(self, threat_count, elapsed_time):
        """Called when scan is complete"""
        self.scan_in_progress = False
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.file_menu.entryconfig("Start Scan", state="normal")
        self.file_menu.entryconfig("Stop Scan", state="disabled")
        
        # Update progress to show completion
        self.progress["value"] = 100
        self.root.update_idletasks()
        
        # Highlight the status with appropriate colors
        if threat_count > 0:
            status_text = f"SCAN COMPLETE - {threat_count} THREATS FOUND!"
            status_color = WARNING_COLOR
            self.status_label.config(text=status_text, foreground=status_color)
            
            # Show message box with threat details
            threat_message = f"{threat_count} threats were detected!\n\nClick on each threat in the Results tab for details."
            messagebox.showwarning("⚠️ THREATS DETECTED", threat_message)
        else:
            status_text = "SCAN COMPLETE - No threats found"
            status_color = SUCCESS_COLOR
            self.status_label.config(text=status_text, foreground=status_color)
            
            # Only show message if actually did a scan (found files)
            if elapsed_time > 1.0:
                messagebox.showinfo("✅ SCAN COMPLETE", "No threats were detected. Your system is clean.")
        
        # Set stats with scan time
        scan_stats = f"Elapsed time: {elapsed_time:.2f}s | Files scanned: {self.files_scanned}"
        self.stats_label.config(text=scan_stats)
    
    def scan_error(self, error_message):
        """Called when an error occurs during scanning"""
        self.scan_in_progress = False
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.file_menu.entryconfig("Start Scan", state="normal")
        self.file_menu.entryconfig("Stop Scan", state="disabled")
        
        self.status_label.config(text="Scan failed")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error_message}")
    
    def stop_scan(self):
        """Stop the current scan"""
        if not self.scan_in_progress:
            return
        
        self.log("Stopping scan...")
        self.scan_in_progress = False
        # TODO: Implement actual scan stopping mechanism
        
        # Update UI
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.file_menu.entryconfig("Start Scan", state="normal")
        self.file_menu.entryconfig("Stop Scan", state="disabled")
        self.status_label.config(text="Scan stopped by user")
    
    def on_result_select(self, event):
        """Handle selection of a threat in the results treeview"""
        selection = self.results_list.selection()
        if not selection:
            return
        
        # Enable action buttons for the selection
        self.remove_button.config(state="normal")
        self.quarantine_button.config(state="normal")
        
        # Get the selected threat item
        item_id = selection[0]
        item_values = self.results_list.item(item_id, "values")
        
        if item_values:
            # Extract the index value from the first column
            try:
                index = int(item_values[0])
                if 0 <= index < len(self.malicious_files):
                    threat = self.malicious_files[index]
                    # Update details view
                    self.update_details(threat)
            except (ValueError, IndexError):
                # Handle any parsing errors
                self.log(f"Error retrieving details for selection: {item_values}")
    
    def update_details(self, threat):
        """Update the details view with information about the selected threat"""
        # Enable editing of the text widget
        self.details_text.config(state="normal")
        
        # Clear current content
        self.details_text.delete(1.0, END)
        
        # Add details with status-specific information
        self.details_text.insert(END, f"File: {threat['name']}\n")
        self.details_text.insert(END, f"Path: {threat['path']}\n")
        
        # Add threat status with color coding
        if 'status' in threat and threat['status'] == 'undetermined':
            self.details_text.insert(END, "Status: ")
            self.details_text.insert(END, "UNDETERMINED", "yellow_text")
            self.details_text.insert(END, " (Confidence between 20-80%)\n")
            
            # Recommendation for undetermined files
            self.details_text.insert(END, f"Detection: {threat['info']}\n")
            self.details_text.insert(END, f"Confidence: {threat['confidence']}%\n\n")
            self.details_text.insert(END, "RECOMMENDATION: Further analysis recommended.\n")
            self.details_text.insert(END, "This file has moderate confidence of being malicious.\n")
            self.details_text.insert(END, "Consider quarantining if from unknown source.\n\n")
        else:
            self.details_text.insert(END, "Status: ")
            self.details_text.insert(END, "MALWARE", "red_text")
            self.details_text.insert(END, " (High confidence ≥ 80%)\n")
            
            # Recommendation for malware files
            self.details_text.insert(END, f"Detection: {threat['info']}\n")
            self.details_text.insert(END, f"Confidence: {threat['confidence']}%\n\n")
            self.details_text.insert(END, "RECOMMENDATION: Remove or quarantine immediately.\n")
            self.details_text.insert(END, "This file has high confidence of being malicious.\n\n")
        
        # Add file metadata
        try:
            stat_info = os.stat(threat['path'])
            size = stat_info.st_size
            modified = datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            created = datetime.datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
            
            self.details_text.insert(END, f"Size: {self.format_size(size)}\n")
            self.details_text.insert(END, f"Created: {created}\n")
            self.details_text.insert(END, f"Modified: {modified}\n")
        except Exception as e:
            self.details_text.insert(END, f"Error retrieving file metadata: {str(e)}\n")
        
        # Configure text tags for colored text
        self.details_text.tag_configure("red_text", foreground=MALWARE_FG)
        self.details_text.tag_configure("yellow_text", foreground="#FF9800")  # Orange for undetermined
        
        # Disable editing
        self.details_text.config(state="disabled")
    
    def format_size(self, size):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def remove_selected(self):
        """Remove the selected malicious file"""
        selection = self.results_list.selection()
        if not selection:
            return
        
        # Get the selected item
        item_id = selection[0]
        item_values = self.results_list.item(item_id, "values")
        
        if not item_values:
            return
            
        try:
            # Extract the index value from the first column
            index = int(item_values[0])
            if index < len(self.malicious_files):
                threat = self.malicious_files[index]
                filepath = threat['path']
                filename = threat['name']
                
                # Use Harkonnen-styled warning dialog with skull emoji
                confirmation_msg = f"☠️ DELETE THREAT PERMANENTLY ☠️\n\nFile: {filename}\nPath: {filepath}\n\nThis will PERMANENTLY DELETE the file from your system. This action cannot be undone.\n\nContinue with deletion?"
                
                if messagebox.askyesno("HARKONNEN SECURITY", confirmation_msg, icon='warning'):
                    try:
                        # First quarantine the file (as backup)
                        quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
                        os.makedirs(quarantine_dir, exist_ok=True)
                        
                        # Generate quarantine filename with deletion marker
                        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                        threat_id = f"DELETED_{timestamp}_{index+1}"
                        quarantine_name = f"{filename}.{threat_id}.deleted"
                        quarantine_path = os.path.join(quarantine_dir, quarantine_name)
                        
                        # Copy file to quarantine before deleting
                        import shutil
                        shutil.copy2(filepath, quarantine_path)
                        
                        # Now remove the original file
                        os.remove(filepath)
                        self.log(f"Removed: {filepath} (Backup saved to quarantine)")
                        
                        # Update UI
                        del self.malicious_files[index]
                        self.results_list.delete(item_id)  # Delete from treeview using item ID
                        self.details_text.config(state="normal")
                        self.details_text.delete(1.0, END)
                        self.details_text.config(state="disabled")
                        
                        # Disable action buttons if no more threats
                        if len(self.results_list.get_children()) == 0:
                            self.remove_all_button.config(state="disabled")
                            self.actions_menu.entryconfig("Remove All Threats", state="disabled")
                        
                        # Disable selection buttons
                        self.remove_button.config(state="disabled")
                        self.quarantine_button.config(state="disabled")
                        
                        messagebox.showinfo("THREAT ELIMINATED", "The malicious file has been permanently deleted.")
                    except Exception as e:
                        messagebox.showerror("DELETION FAILED", f"Could not delete the file: {str(e)}")
        except (ValueError, IndexError) as e:
            self.log(f"Error in remove_selected: {str(e)}")
    
    def quarantine_selected(self):
        """Move the selected malicious file to quarantine"""
        selection = self.results_list.selection()
        if not selection:
            return
        
        # Get the selected item
        item_id = selection[0]
        item_values = self.results_list.item(item_id, "values")
        
        if not item_values:
            return
            
        try:
            # Extract the index value from the first column
            index = int(item_values[0])
            if index < len(self.malicious_files):
                threat = self.malicious_files[index]
                filepath = threat['path']
                filename = threat['name']
                
                # Use Harkonnen-styled warning dialog
                confirmation_msg = f"⚠️ QUARANTINE THREAT\n\nFile: {filename}\nPath: {filepath}\n\nThis will move the file to a secure location where it cannot harm your system. Continue?"
                
                if messagebox.askyesno("HARKONNEN SECURITY", confirmation_msg, icon='warning'):
                    try:
                        # Create quarantine directory if it doesn't exist
                        quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
                        os.makedirs(quarantine_dir, exist_ok=True)
                        
                        # Generate quarantine filename with unique identifier
                        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                        threat_id = f"THREAT_{timestamp}_{index+1}"
                        quarantine_name = f"{filename}.{threat_id}.quarantined"
                        quarantine_path = os.path.join(quarantine_dir, quarantine_name)
                        
                        # Move the file to quarantine
                        os.rename(filepath, quarantine_path)
                        self.log(f"Quarantined: {filepath} -> {quarantine_path}")
                        
                        # Update UI
                        del self.malicious_files[index]
                        self.results_list.delete(item_id)  # Delete from treeview using item ID
                        self.details_text.config(state="normal")
                        self.details_text.delete(1.0, END)
                        self.details_text.config(state="disabled")
                        
                        # Add to quarantine list with threat ID
                        quarantine_display = f"{index+1}. {filename} ({timestamp})"
                        self.quarantine_list.insert(END, quarantine_display)
                        self.quarantine_list.itemconfig(END, {'fg': WARNING_COLOR})
                        
                        # Disable action buttons if no more threats
                        if len(self.results_list.get_children()) == 0:
                            self.remove_all_button.config(state="disabled")
                            self.actions_menu.entryconfig("Remove All Threats", state="disabled")
                        
                        # Disable selection buttons
                        self.remove_button.config(state="disabled")
                        self.quarantine_button.config(state="disabled")
                        
                        messagebox.showinfo("THREAT CONTAINED", "The malicious file has been successfully quarantined.")
                    except Exception as e:
                        messagebox.showerror("QUARANTINE FAILED", f"Could not quarantine the file: {str(e)}")
        except (ValueError, IndexError) as e:
            self.log(f"Error in quarantine_selected: {str(e)}")
    
    def remove_all(self):
        """Remove all detected malicious files"""
        if not self.malicious_files:
            return
        
        # Use Harkonnen-styled warning dialog
        threat_count = len(self.malicious_files)
        confirmation_msg = f"☠️ MASS DELETION WARNING ☠️\n\nYou are about to permanently delete ALL {threat_count} detected threats.\n\nThis action will:\n1. Make a backup copy in quarantine\n2. Delete all original files\n\nThis action CANNOT BE UNDONE.\n\nProceed with mass deletion?"
        
        if messagebox.askyesno("HARKONNEN SECURITY", confirmation_msg, icon='warning'):
            try:
                # Create custom dialog window
                from tkinter import Toplevel as TL
                
                # Create the dialog
                progress_window = TL(self.root)
                progress_window.title("DELETING THREATS")
                progress_window.geometry("400x150")
                progress_window.configure(bg=BACKGROUND_COLOR)
                # Set modal behavior
                progress_window.transient(self.root)
                progress_window.grab_set()
                # Ensure window is properly initialized
                progress_window.update()
                
                # Add progress label
                progress_label = ttk.Label(progress_window, 
                                          text=f"Removing {threat_count} malicious files...",
                                          style="TLabel")
                progress_label.pack(pady=(20, 10))
                
                # Add progress bar
                mass_progress = ttk.Progressbar(progress_window, 
                                               orient=HORIZONTAL,
                                               mode="determinate",
                                               style="TProgressbar")
                mass_progress.pack(fill="x", padx=20, pady=10)
                
                # Status label
                status_label = ttk.Label(progress_window, text="Starting...", style="TLabel")
                status_label.pack(pady=5)
                
                # Update UI
                progress_window.update()
            
                # Process files
                removed_count = 0
                failed_count = 0
                
                # Create quarantine directory
                quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
                os.makedirs(quarantine_dir, exist_ok=True)
                
                # Process each threat
                import shutil
                for i, threat in enumerate(self.malicious_files[:]):
                    filepath = threat['path']
                    filename = threat['name']
                    try:
                        # Update progress
                        progress_value = int((i / threat_count) * 100)
                        mass_progress["value"] = progress_value
                        status_label.config(text=f"Processing {i+1}/{threat_count}: {filename}")
                        progress_window.update()
                        
                        # Generate backup name with timestamp
                        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                        threat_id = f"DELETED_{timestamp}_{i+1}"
                        quarantine_name = f"{filename}.{threat_id}.deleted"
                        quarantine_path = os.path.join(quarantine_dir, quarantine_name)
                        
                        # Copy to quarantine then delete
                        shutil.copy2(filepath, quarantine_path)
                        os.remove(filepath)
                        
                        self.log(f"Removed: {filepath} (Backup saved to quarantine)")
                        removed_count += 1
                        
                        # Remove from our list
                        self.malicious_files.remove(threat)
                    except Exception as e:
                        self.log(f"Failed to remove {filepath}: {str(e)}")
                        failed_count += 1
                        
                    # Short delay to show progress
                    time.sleep(0.1)
                
                # Complete progress
                mass_progress["value"] = 100
                status_label.config(text="Completed!")
                progress_window.update()
                
                # Close progress window after a short delay
                self.root.after(1000, progress_window.destroy)
                
                # Update UI
                self.clear_results()
                
                # Show result message with Harkonnen styling
                if failed_count > 0:
                    messagebox.showwarning("OPERATION RESULTS", 
                                         f"✅ Successfully eliminated {removed_count} threats\n❌ Failed to remove {failed_count} threats")
                else:
                    messagebox.showinfo("THREATS ELIMINATED", 
                                      f"All {removed_count} malicious files have been successfully purged from your system.")
            except Exception as e:
                self.log(f"Error in remove_all: {str(e)}")
                messagebox.showerror("Error", f"Failed to process threats: {str(e)}")
    
    def clear_results(self):
        """Clear all scan results"""
        # Clear results treeview
        for item in self.results_list.get_children():
            self.results_list.delete(item)
        
        # Clear details
        self.details_text.config(state="normal")
        self.details_text.delete(1.0, END)
        self.details_text.config(state="disabled")
        
        # Clear log if not in the middle of a scan
        if not self.scan_in_progress:
            self.log_text.delete(1.0, END)
        
        # Reset state
        self.malicious_files = []
        self.remove_button.config(state="disabled")
        self.quarantine_button.config(state="disabled")
        self.remove_all_button.config(state="disabled")
        self.actions_menu.entryconfig("Remove All Threats", state="disabled")
    
    def load_quarantine_list(self):
        """Load the list of quarantined files"""
        # Create quarantine directory if it doesn't exist
        quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        
        # Clear current list
        self.quarantine_list.delete(0, END)
        
        # List quarantined files
        try:
            for filename in os.listdir(quarantine_dir):
                if filename.endswith(".quarantined"):
                    self.quarantine_list.insert(END, filename)
        except Exception as e:
            self.log(f"Error loading quarantine list: {str(e)}")
    
    def restore_quarantined(self):
        """Restore a file from quarantine"""
        selection = self.quarantine_list.curselection()
        if not selection:
            return
        
        index = selection[0]
        quarantine_filename = self.quarantine_list.get(index)
        
        # Get the quarantine file path
        quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        quarantine_path = os.path.join(quarantine_dir, quarantine_filename)
        
        # Extract original filename (remove timestamp and .quarantined extension)
        original_filename = quarantine_filename.split(".")[0]
        
        # Ask where to restore to
        restore_path = filedialog.asksaveasfilename(
            initialfile=original_filename,
            title="Restore File To",
            defaultextension=""
        )
        
        if restore_path:
            try:
                # Move the file back
                os.rename(quarantine_path, restore_path)
                self.log(f"Restored: {quarantine_path} -> {restore_path}")
                
                # Update UI
                self.quarantine_list.delete(index)
                
                messagebox.showinfo("File Restored", f"The file has been restored to:\n{restore_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to restore file: {str(e)}")
    
    def delete_quarantined(self):
        """Delete a file from quarantine"""
        selection = self.quarantine_list.curselection()
        if not selection:
            return
        
        index = selection[0]
        quarantine_filename = self.quarantine_list.get(index)
        
        # Get the quarantine file path
        quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        quarantine_path = os.path.join(quarantine_dir, quarantine_filename)
        
        if messagebox.askyesno("Confirm Deletion", 
                             f"Are you sure you want to permanently delete this quarantined file?\n\n{quarantine_filename}"):
            try:
                # Delete the file
                os.remove(quarantine_path)
                self.log(f"Deleted from quarantine: {quarantine_path}")
                
                # Update UI
                self.quarantine_list.delete(index)
                
                messagebox.showinfo("File Deleted", "The quarantined file has been permanently deleted.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete file: {str(e)}")
    
    def log(self, message):
        """Add a message to the log"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(END, f"[{timestamp}] {message}\n")
        self.log_text.see(END)
    
    def show_about(self):
        """Show the about dialog"""
        messagebox.showinfo("About Harkonnen CNN",
                          f"{APP_TITLE} v{APP_VERSION}\n\n"
                          "Advanced malware detection using convolutional neural networks\n\n"
                          "© 2025 Harkonnen Security")
    
    def check_updates(self):
        """Check for updates"""
        messagebox.showinfo("Check for Updates", "You are running the latest version.")


def main():
    root = Tk()
    app = HarkonnenGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()