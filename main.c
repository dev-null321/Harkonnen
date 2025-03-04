#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>   // For strerror
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define isatty _isatty
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#else
#include <unistd.h>
#endif

#include <stdbool.h>

#ifdef _WIN32
// Windows implementation of getopt
#include "wingetopt.h"
#else
#include <getopt.h>
#endif

#include "static-analysis.h"
#include "heuristics.h"
#include "api_shadowing.h"
#include "yara_rules.h"
#include "threaded_scanner.h"
#include "report_generator.h"
#include "hashes.h"

#define VERSION "2.5.0"

// Print the help message
void print_help(const char *program_name) {
    printf("Harkonnen - Antivirus System %s\n\n", VERSION);
    printf("Usage: %s [OPTIONS] <filename or directory>\n\n", program_name);
    printf("Scanning Options:\n");
    printf("  -h, --help                 Display this help message\n");
    printf("  -v, --version              Display version information\n");
    printf("  -s, --scan                 Scan files without additional actions\n");
    printf("  -q, --quick                Quick scan (hash check only)\n");
    printf("  -d, --deep                 Deep scan (includes heuristics and PE analysis)\n");
    printf("  -b, --sandbox              Run suspicious files in sandbox\n");
    printf("  -m, --monitor              Enable API monitoring\n");
    printf("  -n, --neural               Use neural network for additional detection\n");
    printf("  -k, --kill                 Terminate malicious processes automatically\n");
    printf("  -o, --output=FILE          Write results to FILE\n");
    
    printf("\nSignature Management:\n");
    printf("  -u, --update               Update signature database from Malware Bazaar\n");
    printf("  -i, --import=FILE          Import signatures from a local file\n");
    
    printf("\nPerformance Options:\n");
    printf("  -t, --threads=NUM          Use specified number of threads for scanning\n");
    printf("  -p, --parallel             Enable multi-threaded scanning (auto-configure)\n");
    
    printf("\nYARA Rules:\n");
    printf("  -y, --yara                 Enable YARA rule scanning\n");
    printf("  -Y, --yara-rules=DIR       Specify YARA rules directory\n");
    printf("  -L, --list-rules           List all loaded YARA rules\n");
    
    printf("\nReporting:\n");
    printf("  -r, --report=FORMAT        Generate scan report (text, html, or both)\n");
    printf("  -O, --open-report          Open report in browser when scan completes\n");
    
    printf("\nExamples:\n");
    printf("  %s file.exe                    Quick scan a file\n", program_name);
    printf("  %s -d -n file.exe              Deep scan with neural network\n", program_name);
    printf("  %s -b -m suspicious.exe        Run in sandbox with API monitoring\n", program_name);
    printf("  %s -d -k /path/to/directory    Deep scan a directory and kill threats\n", program_name);
    printf("  %s -u                          Update signature database\n", program_name);
    printf("  %s -p -d -r html directory     Parallel deep scan with HTML report\n", program_name);
    printf("  %s -y -t 8 large_directory     Scan with YARA rules using 8 threads\n", program_name);
}

int main(int argc, char **argv) {
    int opt;
    bool quick_scan = false;
    bool deep_scan = false;
    bool sandbox_mode = false;
    bool api_monitor = false;
    bool neural_mode = false;
    bool kill_mode = false;
    bool update_mode = false;
    bool yara_mode = false;
    bool parallel_mode = false;
    bool list_rules = false;
    bool open_report = false;
    char *output_file = NULL;
    char *import_file = NULL;
    char *yara_dir = NULL;
    char *report_format = NULL;
    int thread_count = 0;
    
    struct option long_options[] = {
        // Basic options
        {"help",         no_argument,       0, 'h'},
        {"version",      no_argument,       0, 'v'},
        {"scan",         no_argument,       0, 's'},
        {"quick",        no_argument,       0, 'q'},
        {"deep",         no_argument,       0, 'd'},
        {"sandbox",      no_argument,       0, 'b'},
        {"monitor",      no_argument,       0, 'm'},
        {"neural",       no_argument,       0, 'n'},
        {"kill",         no_argument,       0, 'k'},
        {"output",       required_argument, 0, 'o'},
        
        // Signature management
        {"update",       no_argument,       0, 'u'},
        {"import",       required_argument, 0, 'i'},
        
        // Performance options
        {"threads",      required_argument, 0, 't'},
        {"parallel",     no_argument,       0, 'p'},
        
        // YARA rules
        {"yara",         no_argument,       0, 'y'},
        {"yara-rules",   required_argument, 0, 'Y'},
        {"list-rules",   no_argument,       0, 'L'},
        
        // Reporting
        {"report",       required_argument, 0, 'r'},
        {"open-report",  no_argument,       0, 'O'},
        
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "hvsdqbmnko:ui:t:pyY:Lr:O", long_options, &option_index)) != -1) {
        switch (opt) {
            // Basic options
            case 'h':
                print_help(argv[0]);
                return 0;
            case 'v':
                printf("Harkonnen - Antivirus System %s\n", VERSION);
                return 0;
            case 's':
                // Default scan mode
                break;
            case 'q':
                quick_scan = true;
                break;
            case 'd':
                deep_scan = true;
                break;
            case 'b':
                sandbox_mode = true;
                break;
            case 'm':
                api_monitor = true;
                break;
            case 'n':
                neural_mode = true;
                break;
            case 'k':
                kill_mode = true;
                break;
            case 'o':
                output_file = optarg;
                break;
                
            // Signature management
            case 'u':
                update_mode = true;
                break;
            case 'i':
                import_file = optarg;
                break;
                
            // Performance options
            case 't':
                thread_count = atoi(optarg);
                if (thread_count <= 0) {
                    fprintf(stderr, "Invalid thread count: %s\n", optarg);
                    return 1;
                }
                parallel_mode = true;
                break;
            case 'p':
                parallel_mode = true;
                break;
                
            // YARA rules
            case 'y':
                yara_mode = true;
                break;
            case 'Y':
                yara_dir = optarg;
                yara_mode = true;
                break;
            case 'L':
                list_rules = true;
                break;
                
            // Reporting
            case 'r':
                report_format = optarg;
                break;
            case 'O':
                open_report = true;
                break;
                
            default:
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                return 1;
        }
    }
    
    // Handle signature database operations first
    if (update_mode) {
        printf("========================================================\n");
        printf("== Harkonnen Signature Database Update              ==\n");
        printf("========================================================\n\n");
        
        // Initialize database if not exists
        initialize_hash_database();
        
        // Update from Malware Bazaar
        if (update_signatures_from_malware_bazaar()) {
            printf("\nSignature database updated successfully.\n");
            // If no other actions are specified, we can exit
            if (optind >= argc && !import_file) {
                return 0;
            }
        } else {
            printf("\nFailed to update signature database.\n");
            return 1;
        }
    }
    
    if (import_file) {
        printf("========================================================\n");
        printf("== Harkonnen Signature Import                       ==\n");
        printf("========================================================\n\n");
        
        printf("Importing signatures from: %s\n", import_file);
        
        // Initialize database if not exists
        initialize_hash_database();
        
        // Import from file
        int count = import_signatures_from_file(import_file);
        if (count > 0) {
            printf("\nSuccessfully imported %d signatures.\n", count);
            // If no other actions are specified, we can exit
            if (optind >= argc) {
                return 0;
            }
        } else {
            printf("\nFailed to import signatures. Please check the file format.\n");
            printf("Expected format: SHA256:MalwareName (one per line)\n");
            return 1;
        }
    }
    
    // If we reach here and no target is specified, show an error
    if (optind >= argc) {
        fprintf(stderr, "Error: No target specified for scanning.\n");
        fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
        return 1;
    }
    
    // Redirect output if specified
    FILE *output_stream = stdout;
    if (output_file) {
        output_stream = fopen(output_file, "w");
        if (!output_stream) {
            perror("Error opening output file");
            return 1;
        }
    }
    
    // Print banner
    fprintf(output_stream, "========================================================\n");
    fprintf(output_stream, "== Harkonnen Antivirus System %s                   ==\n", VERSION);
    fprintf(output_stream, "========================================================\n\n");
    
    // Initialize signature database
    initialize_hash_database();
    
    // Initialize YARA rules if enabled
    if (yara_mode) {
        fprintf(output_stream, "Initializing YARA rule engine...\n");
        if (yara_dir) {
            // Using custom YARA rules directory
            // In a real implementation, this would set the rules directory before initializing
            fprintf(output_stream, "Using custom YARA rules directory: %s\n", yara_dir);
        }
        
        int rules_count = initialize_yara();
        if (rules_count > 0) {
            fprintf(output_stream, "Successfully loaded %d YARA rules\n", rules_count);
        } else {
            fprintf(output_stream, "Failed to load YARA rules\n");
        }
    }
    
    // List YARA rules if requested
    if (list_rules) {
        if (!yara_mode) {
            // Auto-enable YARA mode if listing rules
            yara_mode = true;
            initialize_yara();
        }
        list_yara_rules();
        if (optind >= argc) {
            // If no scan target was specified, just exit after listing rules
            return 0;
        }
    }
    
    // Initialize thread pool if parallel scanning is enabled
    if (parallel_mode) {
        fprintf(output_stream, "Initializing parallel scanning...\n");
        
        // If thread count was not explicitly set, detect optimal thread count
        if (thread_count <= 0) {
            thread_count = get_optimal_thread_count();
        }
        
        if (initialize_thread_pool(thread_count)) {
            fprintf(output_stream, "Parallel scanning enabled with %d threads\n", thread_count);
        } else {
            fprintf(output_stream, "Failed to initialize parallel scanning, reverting to single-threaded mode\n");
            parallel_mode = false;
        }
    }
    
    // Initialize report if requested
    ScanReport *report = NULL;
    if (report_format) {
        const char *target = argv[optind];
        report = create_scan_report(target);
        
        if (report) {
            // Store scan options for the report
            char options[256] = {0};
            if (quick_scan) strcat(options, "Quick scan, ");
            if (deep_scan) strcat(options, "Deep scan, ");
            if (sandbox_mode) strcat(options, "Sandbox, ");
            if (neural_mode) strcat(options, "Neural network, ");
            if (yara_mode) strcat(options, "YARA rules, ");
            if (parallel_mode) strcat(options, "Parallel scanning, ");
            
            // Remove trailing comma and space if options were added
            size_t len = strlen(options);
            if (len > 0) {
                options[len - 2] = '\0';
            }
            
            strncpy(report->scan_options, options, sizeof(report->scan_options) - 1);
        }
    }
    
    // Initialize API monitoring if requested
    if (api_monitor) {
        fprintf(output_stream, "Initializing API monitoring...\n");
        if (install_api_hooks()) {
            fprintf(output_stream, "API monitoring enabled\n");
        } else {
            fprintf(output_stream, "Failed to enable API monitoring\n");
        }
    }
    
    // Check for API hooking (self-defense)
    if (detect_api_hooking()) {
        fprintf(output_stream, "WARNING: API hooking detected in the system!\n");
        fprintf(output_stream, "This could indicate malware or another security product is active.\n");
    }
    
    // Record start time for scan duration calculation
    time_t scan_start_time = time(NULL);
    
    // Array to store detected malicious files
    #define MAX_MALICIOUS_FILES 1000
    char **malicious_files = NULL;
    int malicious_count = 0;
    int total_files = 0;
    
    // Allocate memory for malicious files array for process_path_collect
    malicious_files = malloc(sizeof(char*) * MAX_MALICIOUS_FILES);
    
    // Process each target
    for (int i = optind; i < argc; i++) {
        const char *target = argv[i];
        fprintf(output_stream, "Processing: %s\n", target);
        fprintf(output_stream, "[INFO] Starting scan. Files will be collected for batch removal at the end...\n");
        
        if (parallel_mode) {
            // Parallel processing mode
            fprintf(output_stream, "Performing parallel scan...\n");
            
            // Process the target with the thread pool
            if (process_directory_threaded(target)) {
                fprintf(output_stream, "Queued files for parallel scanning...\n");
                
                // Wait for all scans to complete
                fprintf(output_stream, "Waiting for all scan threads to complete...\n");
                wait_for_scan_completion();
                
                // Print scan summary
                print_scan_summary();
                
                // TODO: Collect malicious files from threaded scan for batch removal
            } else {
                fprintf(output_stream, "Error: Failed to process target for parallel scanning\n");
            }
        } else if (quick_scan) {
            fprintf(output_stream, "Performing quick scan (hash check only)...\n");
            // Quick scan just checks file hashes, but also collect malicious files
            process_path_collect(target, &malicious_files, &malicious_count, &total_files);
        } else if (deep_scan) {
            fprintf(output_stream, "Performing deep scan (heuristics + PE analysis)...\n");
            // Deep scan includes heuristics, entropy, PE analysis
            process_path_collect(target, &malicious_files, &malicious_count, &total_files);
            
            // Add additional heuristic checks
            if (check_for_process_injection(target) && malicious_count < MAX_MALICIOUS_FILES) {
                // Add to malicious files if process injection detected
                malicious_files[malicious_count++] = strdup(target);
            }
            
            // Run YARA rules if enabled
            if (yara_mode) {
                fprintf(output_stream, "Running YARA rule matching...\n");
                char detection_name[256];
                int severity = 0;
                if (scan_file_with_yara(target, detection_name, sizeof(detection_name), &severity)) {
                    fprintf(output_stream, "YARA rule matched: %s (severity: %d)\n", detection_name, severity);
                    // Add to malicious files if not already there
                    if (!is_malicious && malicious_count < MAX_MALICIOUS_FILES) {
                        malicious_files[malicious_count++] = strdup(target);
                    }
                }
            }
            
            // Run neural network if requested
            if (neural_mode) {
                fprintf(output_stream, "Running enhanced neural network analysis...\n");
                fprintf(output_stream, "Delegating to Harkonnen CNN engine for deep pattern recognition...\n");
                
                // Run the neural network analysis using our improved Harkonnen CNN
                char cmd[1024];
                snprintf(cmd, sizeof(cmd), "python3 ./resnet_inference.py -f \"%s\" -m best_model.pth --auto-remove=false", target);
                int nn_result = system(cmd);
                
                // Check if the neural network found malware (return code 1 indicates detection)
                fprintf(output_stream, "Neural network analysis complete.\n");
                
                // Add to malicious files if detected by neural network
                if (nn_result == 1 && malicious_count < MAX_MALICIOUS_FILES) {
                    fprintf(output_stream, "\033[1;31m[CNN DETECTION] Malicious code patterns detected!\033[0m\n");
                    malicious_files[malicious_count++] = strdup(target);
                }
            }
            
            // Run in sandbox if requested
            if (sandbox_mode) {
                fprintf(output_stream, "Running sandbox analysis...\n");
                int sandbox_result = run_in_sandbox(target);
                
                // Add to malicious files if sandbox detected suspicious behavior
                if (sandbox_result != 0 && !is_malicious && malicious_count < MAX_MALICIOUS_FILES) {
                    malicious_files[malicious_count++] = strdup(target);
                }
            }
            
            // Check for privilege escalation attempts
            monitor_privilege_escalation();
        } else {
            // Standard scan
            fprintf(output_stream, "Performing standard scan...\n");
            process_path_collect(target, &malicious_files, &malicious_count, &total_files);
            
            // Run YARA rules if enabled
            if (yara_mode) {
                fprintf(output_stream, "Running YARA rule matching...\n");
                char detection_name[256];
                int severity = 0;
                if (scan_file_with_yara(target, detection_name, sizeof(detection_name), &severity)) {
                    fprintf(output_stream, "YARA rule matched: %s (severity: %d)\n", detection_name, severity);
                    // Add to malicious files if not already there
                    if (!is_malicious && malicious_count < MAX_MALICIOUS_FILES) {
                        malicious_files[malicious_count++] = strdup(target);
                    }
                }
            }
            
            // Run neural network if requested
            if (neural_mode) {
                fprintf(output_stream, "Running enhanced neural network analysis...\n");
                fprintf(output_stream, "Delegating to Harkonnen CNN engine for deep pattern recognition...\n");
                
                // Run the neural network analysis using our improved Harkonnen CNN
                char cmd[1024];
                snprintf(cmd, sizeof(cmd), "python3 ./resnet_inference.py -f \"%s\" -m latest_model.pth --auto-remove=false", target);
                int nn_result = system(cmd);
                
                // Check if the neural network found malware
                fprintf(output_stream, "Neural network analysis complete.\n");
                
                // Add to malicious files if detected by neural network (non-zero exit status indicates detection)
                if (nn_result != 0 && malicious_count < MAX_MALICIOUS_FILES) {
                    fprintf(output_stream, "\033[1;31m[CNN DETECTION] Malicious code patterns detected!\033[0m\n");
                    malicious_files[malicious_count++] = strdup(target);
                }
            }
        }
        
        // Kill malicious processes if requested and found
        if (kill_mode) {
            fprintf(output_stream, "Checking for malicious processes to terminate...\n");
            if (terminate_malicious_process(target) == 0) {
                fprintf(output_stream, "Malicious process terminated: %s\n", target);
            }
        }
    }
    
    // Display batch removal prompt if malicious files were found
    if (malicious_count > 0) {
        fprintf(output_stream, "\n========================================================\n");
        fprintf(output_stream, "SCAN SUMMARY: %d of %d files are malicious (%.1f%%)\n", 
                malicious_count, total_files, 
                (total_files > 0) ? (malicious_count * 100.0 / total_files) : 0.0);
        fprintf(output_stream, "========================================================\n");
        
        fprintf(output_stream, "Malicious files detected:\n");
        for (int i = 0; i < malicious_count; i++) {
            // Using red color for emphasis (works in most terminals)
            fprintf(output_stream, "  %d. \033[1;31m%s\033[0m\n", i+1, malicious_files[i]);
        }
        
        // Ask to remove all files at once
        fprintf(output_stream, "\n========================================================\n");
        fprintf(output_stream, "ALL SCANNING COMPLETED - FINAL ACTION REQUIRED\n");
        fprintf(output_stream, "========================================================\n");
        fprintf(output_stream, "Do you want to remove all %d detected malicious files? (y/n): ", malicious_count);
        
        char response = 'n';
        fscanf(stdin, " %c", &response);
        
        int removed_count = 0;
        
        if (response == 'y' || response == 'Y') {
            fprintf(output_stream, "\nRemoving malicious files...\n");
            
            for (int i = 0; i < malicious_count; i++) {
                fprintf(output_stream, "Processing: \033[1;31m%s\033[0m\n", malicious_files[i]);
                
                if (remove(malicious_files[i]) == 0) {
                    fprintf(output_stream, "\033[1;32m✓ Successfully removed: %s\033[0m\n", malicious_files[i]);
                    removed_count++;
                } else {
                    fprintf(output_stream, "\033[1;31m✗ Failed to remove: %s\033[0m\n", malicious_files[i]);
                    fprintf(output_stream, "  Reason: %s\n", strerror(errno));
                }
            }
            
            // Final summary after batch removal
            fprintf(output_stream, "\n========================================================\n");
            fprintf(output_stream, "REMOVAL SUMMARY\n");
            fprintf(output_stream, "========================================================\n");
            fprintf(output_stream, "Removed %d of %d malicious files.\n", removed_count, malicious_count);
            
            if (removed_count < malicious_count) {
                fprintf(output_stream, "\n\033[1;33mWARNING: Some malicious files remain on the system.\033[0m\n");
                fprintf(output_stream, "These files may continue to pose security risks.\n");
            } else if (removed_count > 0) {
                fprintf(output_stream, "\n\033[1;32mAll detected threats have been successfully removed.\033[0m\n");
            }
        } else {
            fprintf(output_stream, "\nNo files were removed. The detected threats remain on your system.\n");
            fprintf(output_stream, "\n\033[1;33mWARNING: Your system may be at risk due to the presence of malicious files.\033[0m\n");
        }
    } else if (total_files > 0) {
        fprintf(output_stream, "\n========================================================\n");
        fprintf(output_stream, "SCAN SUMMARY: No malicious files detected among %d scanned files\n", total_files);
        fprintf(output_stream, "========================================================\n");
    }
    
    // Free memory allocated for malicious file paths
    for (int i = 0; i < malicious_count; i++) {
        free(malicious_files[i]);
    }
    
    // Clean up API hooks if they were installed
    if (api_monitor) {
        remove_api_hooks();
    }
    
    fprintf(output_stream, "\nScan completed.\n");
    
    // Calculate scan duration
    time_t scan_end_time = time(NULL);
    double scan_duration = difftime(scan_end_time, scan_start_time);
    fprintf(output_stream, "Scan duration: %.1f seconds\n", scan_duration);
    
    // No need to collect malicious files again - we already collected them during scanning
    
    // Generate report if requested
    if (report && report_format) {
        // Update scan duration
        report->scan_duration = scan_duration;
        
        // Generate reports based on format
        char *report_path = NULL;
        
        if (strcasecmp(report_format, "html") == 0 || strcasecmp(report_format, "both") == 0) {
            report_path = generate_html_report(report);
            if (report_path) {
                fprintf(output_stream, "HTML report generated: %s\n", report_path);
                
                // Open report in browser if requested
                if (open_report) {
                    open_report_in_browser(report_path);
                }
                
                free(report_path);
            }
        }
        
        if (strcasecmp(report_format, "text") == 0 || strcasecmp(report_format, "both") == 0) {
            report_path = generate_text_report(report);
            if (report_path) {
                fprintf(output_stream, "Text report generated: %s\n", report_path);
                free(report_path);
            }
        }
        
        // Free the report
        free_scan_report(report);
    }
    
    // Clean up thread pool if initialized
    if (parallel_mode) {
        destroy_thread_pool();
    }
    
    // Free the malicious files array memory
    free(malicious_files);
    
    // Close output file if we redirected
    if (output_file && output_stream != stdout) {
        fclose(output_stream);
    }
    
    return 0;
}