#ifndef API_SHADOWING_H
#define API_SHADOWING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>

// Original function pointers
typedef HANDLE (WINAPI *CreateFileA_t)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

typedef BOOL (WINAPI *WriteFile_t)(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

typedef BOOL (WINAPI *ReadFile_t)(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

// Hooked function declarations
HANDLE WINAPI hooked_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

BOOL WINAPI hooked_WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

BOOL WINAPI hooked_ReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

// Original function pointers
static CreateFileA_t original_CreateFileA = NULL;
static WriteFile_t original_WriteFile = NULL;
static ReadFile_t original_ReadFile = NULL;

// Hook installation function
bool install_api_hooks(void) {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) {
        fprintf(stderr, "Failed to get kernel32.dll handle\n");
        return false;
    }

    // Save original function pointers
    original_CreateFileA = (CreateFileA_t)GetProcAddress(kernel32, "CreateFileA");
    original_WriteFile = (WriteFile_t)GetProcAddress(kernel32, "WriteFile");
    original_ReadFile = (ReadFile_t)GetProcAddress(kernel32, "ReadFile");

    if (!original_CreateFileA || !original_WriteFile || !original_ReadFile) {
        fprintf(stderr, "Failed to get function addresses\n");
        return false;
    }

    // Here we would install the hooks using a hooking library like Detours
    // For the toy implementation, we'll just print that hooks are installed
    printf("API hooks installed successfully\n");
    return true;
}

// Unhook function
void remove_api_hooks(void) {
    // Here we would remove the hooks
    printf("API hooks removed\n");
}

// Implementation of hooked functions
HANDLE WINAPI hooked_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    // Log the file access
    printf("[API Monitor] CreateFileA: %s\n", lpFileName);
    
    // Check if this is suspicious
    if (strstr(lpFileName, "system32") || strstr(lpFileName, "WINDOWS") ||
        strstr(lpFileName, ".exe") || strstr(lpFileName, ".dll")) {
        printf("[WARNING] Suspicious file access detected: %s\n", lpFileName);
    }
    
    // Call the original function
    return original_CreateFileA(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );
}

BOOL WINAPI hooked_WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
) {
    // Log the write operation
    printf("[API Monitor] WriteFile: %d bytes\n", nNumberOfBytesToWrite);
    
    // Check for suspicious patterns in the buffer
    const char *buffer = (const char *)lpBuffer;
    if (memmem(buffer, nNumberOfBytesToWrite, "MZ", 2) ||  // EXE magic bytes
        memmem(buffer, nNumberOfBytesToWrite, "TVqQ", 4)) { // Base64 encoded MZ
        printf("[WARNING] Suspicious WriteFile operation: possible executable content\n");
    }
    
    // Call the original function
    return original_WriteFile(
        hFile,
        lpBuffer,
        nNumberOfBytesToWrite,
        lpNumberOfBytesWritten,
        lpOverlapped
    );
}

BOOL WINAPI hooked_ReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
) {
    // Log the read operation
    printf("[API Monitor] ReadFile: %d bytes requested\n", nNumberOfBytesToRead);
    
    // Call the original function
    BOOL result = original_ReadFile(
        hFile,
        lpBuffer,
        nNumberOfBytesToRead,
        lpNumberOfBytesRead,
        lpOverlapped
    );
    
    // Check the read buffer for suspicious content
    if (result && lpNumberOfBytesRead && *lpNumberOfBytesRead > 0) {
        const char *buffer = (const char *)lpBuffer;
        if (memmem(buffer, *lpNumberOfBytesRead, "MZ", 2)) {
            printf("[WARNING] Suspicious ReadFile operation: possible executable content\n");
        }
    }
    
    return result;
}

#elif defined(__linux__) || defined(__APPLE__)
// Linux/macOS implementation using function interposition
// (would be implemented with LD_PRELOAD or DYLD_INSERT_LIBRARIES)
bool install_api_hooks(void) {
    printf("API hooking on Unix-like systems would use LD_PRELOAD/DYLD_INSERT_LIBRARIES\n");
    return true;
}

void remove_api_hooks(void) {
    printf("API hooks removed\n");
}
#endif

// Function to detect if the current process is being hooked
bool detect_api_hooking(void) {
    bool hooking_detected = false;
    
#ifdef _WIN32
    // Check if important DLLs are loaded from unexpected locations
    HMODULE hModules[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();
    
    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hModules[i], szModName, sizeof(szModName) / sizeof(char))) {
                // Check if system DLLs are loaded from non-system directories
                if ((strstr(szModName, "kernel32.dll") || 
                     strstr(szModName, "ntdll.dll") || 
                     strstr(szModName, "user32.dll")) && 
                    !strstr(szModName, "System32") && 
                    !strstr(szModName, "SysWOW64")) {
                    printf("[WARNING] System DLL loaded from suspicious location: %s\n", szModName);
                    hooking_detected = true;
                }
                
                // Check for known hooking libraries
                if (strstr(szModName, "detours") || 
                    strstr(szModName, "hook") || 
                    strstr(szModName, "inject")) {
                    printf("[WARNING] Potential hooking library detected: %s\n", szModName);
                    hooking_detected = true;
                }
            }
        }
    }
    
    // Check for inline hooks in key functions by examining their first bytes
    // This is a simplified example - real implementation would be more complex
    BYTE *pCreateFile = (BYTE *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");
    if (pCreateFile && (pCreateFile[0] == 0xE9 || pCreateFile[0] == 0xEB)) {
        printf("[WARNING] Possible inline hook detected in CreateFileA\n");
        hooking_detected = true;
    }
#elif defined(__linux__)
    // Check for suspicious LD_PRELOAD
    const char *preload = getenv("LD_PRELOAD");
    if (preload) {
        printf("[WARNING] LD_PRELOAD in use: %s\n", preload);
        hooking_detected = true;
    }
    
    // On Linux we could also examine /proc/self/maps for suspicious libraries
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            if (strstr(line, "hook") || strstr(line, "inject") || strstr(line, "detour")) {
                printf("[WARNING] Suspicious library detected: %s", line);
                hooking_detected = true;
            }
        }
        fclose(maps);
    }
#elif defined(__APPLE__)
    // Check for suspicious DYLD_INSERT_LIBRARIES
    const char *insert_libs = getenv("DYLD_INSERT_LIBRARIES");
    if (insert_libs) {
        printf("[WARNING] DYLD_INSERT_LIBRARIES in use: %s\n", insert_libs);
        hooking_detected = true;
    }
    
    // Additional macOS-specific checks would go here
#endif

    return hooking_detected;
}

#endif // API_SHADOWING_H