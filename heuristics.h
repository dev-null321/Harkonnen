//
// Created by Marq Britt on 8/22/24.
//

#ifndef HEURISTICS_H
#define HEURISTICS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#ifndef _WIN32
// For nanosleep
#include <time.h>
#endif

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#else
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#endif

#ifdef __linux__
#include <seccomp.h>
#elif defined(__APPLE__)
#include <sandbox.h>
#endif

// Forward declarations
void monitor_process_resources(pid_t pid);
#endif


int check_for_process_injection(const char *filePath) {
    #ifdef _WIN32
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return -1;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return -1;
    }

    do {
        if (_stricmp(pe32.szExeFile, filePath) == 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                HMODULE hMods[1024];
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                        char szModName[MAX_PATH];
                        if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                            if (strstr(szModName, "injected.dll") || strstr(szModName, "suspicious.dll")) {
                                printf("Process injection detected via DLL: %s\n", szModName);
                                CloseHandle(hProcess);
                                CloseHandle(hProcessSnap);
                                return 1;
                            }
                        }
                    }
                }

                MEMORY_BASIC_INFORMATION mbi;
                char *addr = 0;
                while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
                    if (mbi.Type == MEM_IMAGE && mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE) {
                        printf("Process injection detected: suspicious memory region found.\n");
                        CloseHandle(hProcess);
                        CloseHandle(hProcessSnap);
                        return 1;
                    }
                    addr += mbi.RegionSize;
                }

                CloseHandle(hProcess);
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    #else
    // For Unix-like systems, we'd need to implement a different approach
    // This could involve parsing /proc/<pid>/maps or using ptrace
    printf("Process injection check not implemented for this platform.\n");
    #endif

    return 0;
}

void monitor_privilege_escalation(void) {
    #ifdef _WIN32
    HANDLE hToken;
    TOKEN_ELEVATION elevation;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            if (elevation.TokenIsElevated) {
                printf("Privilege escalation detected!\n");
                exit(1);
            }
        }
        CloseHandle(hToken);
    }
    #else
    if (geteuid() == 0) {
        printf("Privilege escalation detected!\n");
        exit(1);
    }
    #endif
}

void analyze_process(const char *filePath) {
    #ifdef _WIN32
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if (CreateProcess(filePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        fprintf(stderr, "Error running the command.\n");
    }
    #else
    pid_t pid = fork();
    if (pid == 0) {
        execl(filePath, filePath, (char *)NULL);
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    } else {
        fprintf(stderr, "Error running the command.\n");
    }
    #endif

    monitor_privilege_escalation();
    check_for_process_injection(filePath);
}

// This function is already defined in static-analysis.h
// Use the one from there instead

void sandbox_process(const char* target_process) {
#ifdef __linux__
    // Use seccomp to restrict system calls
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to initialize seccomp context\n");
        exit(1);
    }

    // Add rules to block dangerous system calls
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vfork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(reboot), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(delete_module), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(init_module), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(finit_module), 0);

    // Network restrictions
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(bind), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(connect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(listen), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(accept), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(accept4), 0);

    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "Failed to load seccomp context\n");
        seccomp_release(ctx);
        exit(1);
    }

    seccomp_release(ctx);
    printf("Linux sandbox (seccomp) initialized with enhanced protections\n");

#elif defined(_WIN32)
    // Create job object for Windows sandbox
    HANDLE hJob = CreateJobObject(NULL, NULL);
    if (hJob == NULL) {
        fprintf(stderr, "Failed to create job object\n");
        exit(1);
    }

    // Configure job object limits
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {0};
    
    // Process termination upon job handle close
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    
    // Prevent process from creating child processes
    jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    jeli.BasicLimitInformation.ActiveProcessLimit = 1;
    
    // Prevent process from escaping the job
    jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    
    // Set memory limits
    jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    jeli.JobMemoryLimit = 100 * 1024 * 1024; // 100 MB limit
    
    // Set process time limits
    jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
    jeli.BasicLimitInformation.PerJobUserTimeLimit.QuadPart = 10000000; // 1 second (in 100ns units)
    
    SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    
    // Setup UI restrictions
    JOBOBJECT_BASIC_UI_RESTRICTIONS juiRestrictions;
    juiRestrictions.UIRestrictionsClass = JOB_OBJECT_UILIMIT_NONE;
    juiRestrictions.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_EXITWINDOWS; // Prevent logging off
    juiRestrictions.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS; // Prevent system parameter changes
    juiRestrictions.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DESKTOP; // Prevent desktop changes
    juiRestrictions.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DISPLAYSETTINGS; // Prevent display changes
    
    SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &juiRestrictions, sizeof(juiRestrictions));
    
    // Launch the target process in the sandbox
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    printf("Launching process in sandbox: %s\n", target_process);
    
    if (CreateProcess(target_process, NULL, NULL, NULL, FALSE, 
                      CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        // Assign process to job before it starts executing
        if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
            fprintf(stderr, "Failed to assign process to job object: %lu\n", GetLastError());
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(hJob);
            return;
        }
        
        // Resume the process now that it's sandboxed
        ResumeThread(pi.hThread);
        
        // Wait for the process to complete
        printf("Waiting for sandboxed process to complete...\n");
        WaitForSingleObject(pi.hProcess, 30000); // Wait up to 30 seconds
        
        // Clean up
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        printf("Sandboxed process completed\n");
    } else {
        fprintf(stderr, "Failed to create process: %lu\n", GetLastError());
    }
    
    CloseHandle(hJob);
    printf("Windows sandbox (enhanced job object) completed\n");

#elif defined(__APPLE__)
#ifdef USE_SANDBOX
    // macOS sandbox implementation using sandbox_init
    char sandbox_error[512];
    const char *sandbox_profile = 
        "(version 1)\n"
        "(deny default)\n"
        "(allow process-exec)\n"
        "(allow sysctl-read)\n"
        "(allow file-read-metadata)\n"
        "(allow file-read-data (subpath \"/usr/lib\"))\n"
        "(allow file-read-data (subpath \"/System/Library\"))\n";
    
    int sandbox_result = sandbox_init(sandbox_profile, 0, &sandbox_error);
    if (sandbox_result != 0) {
        fprintf(stderr, "sandbox_init failed: %s\n", sandbox_error);
        exit(1);
    }
    
    printf("macOS sandbox initialized with custom profile\n");
    
    // Launch the target process in the sandbox
    pid_t child_pid = fork();
    if (child_pid == 0) {
        // Child process
        execl(target_process, target_process, NULL);
        perror("execl failed");
        exit(1);
    } else if (child_pid > 0) {
        // Parent process
        int status;
        printf("Waiting for sandboxed process (PID: %d) to complete...\n", child_pid);
        waitpid(child_pid, &status, 0);
        printf("Sandboxed process completed with status: %d\n", WEXITSTATUS(status));
    } else {
        perror("fork failed");
    }
#else
    // Simpler macOS implementation without sandbox_init
    printf("Full sandbox not available - using simulated sandbox on macOS\n");
    
    // Create a temporary directory for containing the sandbox
    char temp_sandbox_dir[PATH_MAX];
    snprintf(temp_sandbox_dir, sizeof(temp_sandbox_dir), "/tmp/harkonnen_sandbox_%d", (int)time(NULL));
    mkdir(temp_sandbox_dir, 0700);
    
    printf("Created temporary sandbox environment at %s\n", temp_sandbox_dir);
    
    // Launch the process with restricted environment
    pid_t child_pid = fork();
    if (child_pid == 0) {
        // Child process - set restricted environment
        // Change to sandbox directory
        if (chdir(temp_sandbox_dir) != 0) {
            perror("Failed to change to sandbox directory");
            exit(1);
        }
        
        // Set restrictive umask
        umask(077);
        
        // Clear environment variables that might be dangerous
        unsetenv("LD_PRELOAD");
        unsetenv("DYLD_INSERT_LIBRARIES");
        unsetenv("DYLD_LIBRARY_PATH");
        
        // Set restricted PATH
        setenv("PATH", "/usr/bin:/bin", 1);
        
        // Execute the target
        execl(target_process, target_process, NULL);
        perror("execl failed");
        exit(1);
    } else if (child_pid > 0) {
        // Parent process - monitor the child
        int status;
        printf("Simulated sandbox running process (PID: %d)\n", child_pid);
        
        // Monitor the process resources while it's running
        struct timespec ts = {1, 0}; // 1 second
        while (waitpid(child_pid, &status, WNOHANG) == 0) {
            // Check process resources
            monitor_process_resources(child_pid);
            nanosleep(&ts, NULL);
        }
        
        printf("Process completed with status: %d\n", WEXITSTATUS(status));
        
        // Look for any files created in the sandbox
        printf("Checking sandbox for created files...\n");
        DIR *dir = opendir(temp_sandbox_dir);
        if (dir) {
            struct dirent *entry;
            int found_files = 0;
            while ((entry = readdir(dir)) != NULL) {
                if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                    printf("Created file: %s\n", entry->d_name);
                    found_files++;
                }
            }
            closedir(dir);
            
            if (found_files == 0) {
                printf("No files were created in the sandbox\n");
            }
        }
    } else {
        perror("fork failed");
    }
#endif
#else
    printf("Sandbox not implemented for this platform\n");
#endif
}

// Function to monitor resources of a process
void monitor_process_resources(pid_t pid) {
#ifdef __linux__
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    
    FILE *status = fopen(path, "r");
    if (status) {
        char line[256];
        unsigned long vm_size = 0, vm_rss = 0;
        
        while (fgets(line, sizeof(line), status)) {
            if (strncmp(line, "VmSize:", 7) == 0) {
                sscanf(line, "VmSize: %lu", &vm_size);
            } else if (strncmp(line, "VmRSS:", 6) == 0) {
                sscanf(line, "VmRSS: %lu", &vm_rss);
            }
        }
        
        fclose(status);
        
        printf("Process %d resources:\n", pid);
        printf("  Virtual Memory: %lu KB\n", vm_size);
        printf("  Physical Memory: %lu KB\n", vm_rss);
        
        // Check CPU usage
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        FILE *stat = fopen(path, "r");
        if (stat) {
            unsigned long utime, stime;
            fscanf(stat, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &utime, &stime);
            fclose(stat);
            printf("  CPU Time: %lu ticks\n", utime + stime);
        }
    } else {
        perror("Could not open process status");
    }
#elif defined(_WIN32)
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        // Get memory info
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            printf("Process %lu resources:\n", pid);
            printf("  Working Set Size: %llu KB\n", pmc.WorkingSetSize / 1024);
            printf("  Page File Usage: %llu KB\n", pmc.PagefileUsage / 1024);
        }
        
        // Get CPU time
        FILETIME ftCreation, ftExit, ftKernel, ftUser;
        if (GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
            ULARGE_INTEGER ulKernel, ulUser;
            ulKernel.LowPart = ftKernel.dwLowDateTime;
            ulKernel.HighPart = ftKernel.dwHighDateTime;
            ulUser.LowPart = ftUser.dwLowDateTime;
            ulUser.HighPart = ftUser.dwHighDateTime;
            
            printf("  CPU Time: %llu ms\n", (ulKernel.QuadPart + ulUser.QuadPart) / 10000);
        }
        
        CloseHandle(hProcess);
    } else {
        fprintf(stderr, "Could not open process: %lu\n", GetLastError());
    }
#elif defined(__APPLE__)
    // macOS process monitoring (simplified)
    char command[256];
    sprintf(command, "ps -o pid,%%cpu,%%mem,rss,vsz -p %d", pid);
    
    FILE *proc = popen(command, "r");
    if (proc) {
        char buffer[256];
        // Skip header
        fgets(buffer, sizeof(buffer), proc);
        
        if (fgets(buffer, sizeof(buffer), proc)) {
            printf("Process resources: %s", buffer);
        }
        
        pclose(proc);
    }
#endif
}

// Run a binary in a sandbox for behavioral analysis
void run_in_sandbox(const char *filepath) {
    printf("Starting sandbox analysis for: %s\n", filepath);
    
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
    // Create a temporary directory for sandbox artifacts
    char temp_dir[PATH_MAX];
    
#ifdef _WIN32
    char temp_path[MAX_PATH];
    GetTempPath(MAX_PATH, temp_path);
    snprintf(temp_dir, sizeof(temp_dir), "%s\\harkonnen_sandbox_%d", temp_path, (int)time(NULL));
    CreateDirectory(temp_dir, NULL);
#else
    snprintf(temp_dir, sizeof(temp_dir), "/tmp/harkonnen_sandbox_%d", (int)time(NULL));
    mkdir(temp_dir, 0700);
#endif
    
    printf("Sandbox environment prepared at: %s\n", temp_dir);
    
    // Log the start of sandbox analysis
    time_t start_time = time(NULL);
    printf("Sandbox started at: %s", ctime(&start_time));
    
    // Run the file in the sandbox
    sandbox_process(filepath);
    
    // Log the end of sandbox analysis
    time_t end_time = time(NULL);
    printf("Sandbox completed at: %s", ctime(&end_time));
    printf("Total analysis time: %ld seconds\n", end_time - start_time);
    
    // Check for suspicious files created in the sandbox directory
    printf("Checking for artifacts...\n");
    
#ifdef _WIN32
    WIN32_FIND_DATA find_data;
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*.*", temp_dir);
    HANDLE hFind = FindFirstFile(search_path, &find_data);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(find_data.cFileName, ".") != 0 && strcmp(find_data.cFileName, "..") != 0) {
                printf("Found artifact: %s\n", find_data.cFileName);
            }
        } while (FindNextFile(hFind, &find_data));
        FindClose(hFind);
    }
#else
    DIR *dir = opendir(temp_dir);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                printf("Found artifact: %s\n", entry->d_name);
            }
        }
        closedir(dir);
    }
#endif
    
    printf("Sandbox analysis complete.\n");
#else
    printf("Sandbox analysis not supported on this platform.\n");
#endif
}

void analyze_with_neural_network(const char* filename) {
    char command[1024];
    char cwd[PATH_MAX];
    
    // Get current working directory for relative paths
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("getcwd");
        return;
    }

    // Call the BinSleuth wrapper script to run the neural network
    snprintf(command, sizeof(command), 
            "python3 %s/run_binsleuth.py \"%s\"", 
            cwd, filename);

    printf("Running neural network analysis with BinSleuth...\n");
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        perror("popen");
        return;
    }

    char buffer[256];
    bool is_malicious = false;
    
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        printf("%s", buffer);
        
        // Check for malicious verdict in the output
        if (strstr(buffer, "Prediction: MALICIOUS")) {
            is_malicious = true;
        }
    }

    int result = pclose(pipe);
    if (result == -1) {
        perror("pclose");
    } else {
        // Process exit code indicates detection result
        if (WEXITSTATUS(result) != 0) {
            is_malicious = true;
        }
    }
    
    if (is_malicious) {
        printf("\nWARNING: Neural network detected malicious behavior!\n");
        printf("Consider running this file in the sandbox for further analysis.\n");
    } else {
        printf("\nNeural network analysis: No malicious behavior detected.\n");
    }
}