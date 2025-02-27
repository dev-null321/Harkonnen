#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <libgen.h>
#include "hashes.h"
#ifdef USE_CURL
#include <curl/curl.h>
#endif

#ifdef USE_CJSON
#include <cjson/cJSON.h>
#endif

// Including local header with quotation marks instead of angle brackets
#include "pe_parser.h"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#else
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#endif

#define BUFFER_SIZE 256
#define BYTE_RANGE 256
#define API_URL "https://mb-api.abuse.ch/api/v1/"

struct MemoryStruct {
    char *memory;
    size_t size;
};

// Function declarations
void process_path(const char *path);
void analyze_file(const char *filename);
void calculate_file_hashes(const char *filename, char *md5_result, char *sha256_result, size_t result_size);
bool check_hash_in_database(const char *hash, const char *filename, int *threat_level, const char **threat_name);
void search_hash_in_hash_list(const char *hash, const char *filename);
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
bool query_malware_bazaar(const char *hash);
int terminate_malicious_process(const char *filePath);
double calculate_file_entropy(const char* filename);
bool is_pe_file(const char* filename);
bool check_for_suspicious_patterns(const char* filename);
void analyze_with_neural_network(const char* filename);
void parse_pe_file(const char* filename);
bool remove_malicious_file(const char *file_path);
void display_malware_info(const char *threat_name);

// Function to delete a malicious file
bool remove_malicious_file(const char *file_path) {
    printf("[ACTION] Removing malicious file: %s\n", file_path);
    
    if (remove(file_path) == 0) {
        printf("[SUCCESS] File was successfully deleted\n");
        return true;
    } else {
        printf("[ERROR] Failed to delete file: %s\n", strerror(errno));
        return false;
    }
}

// Function to provide detailed malware information
void display_malware_info(const char *threat_name) {
    printf("\n[INFO] Malware Information (180 chars or less):\n");
    
    // Sample malware information database (in a real implementation, this would be more comprehensive)
    struct {
        const char *name;
        const char *info;
    } malware_db[] = {
        {"WannaCry", "Ransomware that spread globally in May 2017, encrypting files and demanding Bitcoin payment. Exploits EternalBlue vulnerability in SMBv1."},
        {"Emotet", "Banking trojan turned modular malware. Spreads via phishing emails with malicious macros. Known for stealing credentials and delivering other malware."},
        {"Ryuk", "Targeted ransomware operated by WIZARD SPIDER group. Known for targeting large organizations with high ransom demands. Uses TrickBot/BazarLoader for delivery."},
        {"TrickBot", "Banking trojan evolved into modular malware-as-a-service platform. Primarily used for credential theft, network traversal, and ransomware delivery."},
        {"Conti", "Human-operated ransomware using double extortion tactics. Affiliates breach networks, exfiltrate data, then deploy ransomware. Known for high-profile attacks."},
        {"Mimikatz", "Credential harvesting tool that extracts passwords, hashes, PINs and tickets from memory. Legitimate pentest tool often abused by attackers."},
        {"ZeuS", "Banking trojan designed to steal credentials through web injects and form grabbing. Source code leaked in 2011, spawning many variants."},
        {"CobaltStrike", "Legitimate penetration testing tool frequently abused by threat actors. Features include beacon payloads, C2 communication, and lateral movement."},
        {"Remcos", "Remote Access Trojan (RAT) with legitimate and malicious uses. Features keylogging, screen recording, credential theft, and file exfiltration."},
        {"NetWire", "Cross-platform RAT offering control of infected systems. Features include keylogging, file transfers, screen captures and remote shell access."},
        {"Malicious-File", "Generic malicious file detected through signature matching. Could be any type of malware including virus, trojan, ransomware, or spyware."}
    };
    
    // Find the matching malware
    for (size_t i = 0; i < sizeof(malware_db) / sizeof(malware_db[0]); i++) {
        if (threat_name && strstr(threat_name, malware_db[i].name)) {
            printf("\033[33m%s\033[0m: %s\n", malware_db[i].name, malware_db[i].info);
            return;
        }
    }
    
    // Default case: if no matching info is found
    printf("No detailed information available for this specific malware.\n");
}

// Function to handle files and directories
void process_path(const char *path) {
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        printf("[ERROR] Failed to access: %s\n", path);
        perror("Reason");
        return;
    }

    if (S_ISREG(path_stat.st_mode)) {
        // If it's a file, analyze it
        analyze_file(path);
    } else if (S_ISDIR(path_stat.st_mode)) {
        // If it's a directory, process each file in the directory
        printf("\n[INFO] Scanning directory: %s\n", path);
        printf("----------------------------------------\n");
        
        DIR *dir = opendir(path);
        if (dir == NULL) {
            printf("[ERROR] Failed to open directory: %s\n", path);
            perror("Reason");
            return;
        }

        int file_count = 0;
        int threats_found = 0;
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            // Skip "." and ".."
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            // Construct the full path to the file
            char full_path[PATH_MAX];
            snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
            
            // Check if it's a directory
            struct stat entry_stat;
            if (stat(full_path, &entry_stat) == 0) {
                if (S_ISDIR(entry_stat.st_mode)) {
                    // Recursively process subdirectories
                    process_path(full_path);
                    continue;
                }
                
                // Count regular files only
                file_count++;
                
                // Analyze the file
                printf("\n[SCANNING] %s\n", entry->d_name);
                
                // Simple file analysis for directory scan (avoid full output)
                char md5[BUFFER_SIZE], sha256[BUFFER_SIZE];
                int is_threat = 0;
                
                calculate_file_hashes(full_path, md5, sha256, BUFFER_SIZE);
                
                // Check hash in database
                const char *threat_name = NULL;
                int threat_level = 0;
                if (check_hash_in_database(sha256, full_path, &threat_level, &threat_name)) {
                    // Known threat detected
                    is_threat = 1;
                    threats_found++;
                    printf("[DETECTED] %s - \033[31mMALICIOUS\033[0m", entry->d_name);
                    if (threat_name) {
                        printf(" (%s)", threat_name);
                        // Display malware information
                        display_malware_info(threat_name);
                    }
                    printf("\n");
                    
                    // Ask user if they want to remove the malicious file
                    char response[10];
                    printf("[QUESTION] Do you want to remove this malicious file? (y/n): ");
                    if (fgets(response, sizeof(response), stdin) != NULL) {
                        if (response[0] == 'y' || response[0] == 'Y') {
                            remove_malicious_file(full_path);
                        } else {
                            printf("[WARNING] Malicious file was kept on the system!\n");
                        }
                    }
                } else {
                    // Check for suspicious patterns
                    FILE *file = fopen(full_path, "rb");
                    if (file) {
                        // Simple pattern check for efficiency
                        char buffer[4096];
                        size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
                        fclose(file);
                        
                        // Look for some basic suspicious patterns
                        if (bytes_read > 0 && (
                            memmem(buffer, bytes_read, "CreateRemoteThread", 18) || 
                            memmem(buffer, bytes_read, "VirtualAllocEx", 14) ||
                            memmem(buffer, bytes_read, "\xEB\xFE", 2) ||
                            memmem(buffer, bytes_read, "http://", 7)
                        )) {
                            // Suspicious patterns found
                            printf("[DETECTED] %s - \033[33mSUSPICIOUS\033[0m\n", entry->d_name);
                            is_threat = 1;
                            threats_found++;
                            
                            // Ask user if they want to remove the suspicious file
                            char response[10];
                            printf("[QUESTION] This file appears suspicious. Do you want to remove it? (y/n): ");
                            if (fgets(response, sizeof(response), stdin) != NULL) {
                                if (response[0] == 'y' || response[0] == 'Y') {
                                    remove_malicious_file(full_path);
                                } else {
                                    printf("[WARNING] Suspicious file was kept on the system!\n");
                                }
                            }
                        } else {
                            // Clean file
                            printf("[CLEAN] %s\n", entry->d_name);
                        }
                    } else {
                        printf("[ERROR] Could not open file: %s\n", entry->d_name);
                    }
                }
            }
        }
        
        closedir(dir);
        
        // Print summary
        printf("\n----------------------------------------\n");
        printf("DIRECTORY SCAN SUMMARY: %s\n", path);
        printf("----------------------------------------\n");
        printf("Files scanned: %d\n", file_count);
        printf("Threats found: %d\n", threats_found);
        
        if (threats_found > 0) {
            printf("\033[31mWARNING: Threats detected in this directory!\033[0m\n");
        } else {
            printf("\033[32mDirectory is clean.\033[0m\n");
        }
        printf("----------------------------------------\n");
    } else {
        printf("[WARNING] Unknown file type: %s\n", path);
    }
}

// Main file analysis function
void analyze_file(const char *filename) {
    char md5[BUFFER_SIZE], sha256[BUFFER_SIZE];
    int threat_level = 0;  // 0 = clean, 1 = suspicious, 2 = malicious
    const char *threat_name = NULL;
    
    printf("\n[SCANNING] %s\n", filename);
    printf("----------------------------------------\n");
    
    // Calculate hashes
    calculate_file_hashes(filename, md5, sha256, BUFFER_SIZE);

    // Calculate entropy and check for packed/encrypted files
    double entropy = calculate_file_entropy(filename);
    printf("File entropy: %.2f\n", entropy);
    
    // High entropy might indicate packing or encryption
    if (entropy > 7.0) {
        printf("[WARNING] High entropy detected (%.2f). File may be packed or encrypted.\n", entropy);
        threat_level = 1; // suspicious
    }

    // Check if it's a PE file, and if so, analyze it
    if (is_pe_file(filename)) {
        printf("[INFO] PE file detected, performing detailed analysis...\n");
        parse_pe_file(filename);
    }

    // Check for known malicious hashes - this will set threat_level = 2 if found
    if (check_hash_in_database(sha256, filename, &threat_level, &threat_name)) {
        // Hash was found in database
        if (threat_name) {
            // Display malware information
            display_malware_info(threat_name);
        }
    } else {
        // Query online threat intelligence database if not found locally
        if (query_malware_bazaar(sha256)) {
            // If we found a threat online, update the threat level
            threat_level = 2; // Mark as malicious
        }
    }
    
    // Perform pattern-based detection
    if (check_for_suspicious_patterns(filename) && threat_level < 2) {
        threat_level = 1; // At least suspicious
    }
    
    // Display final verdict
    printf("----------------------------------------\n");
    printf("VERDICT: ");
    
    switch (threat_level) {
        case 0:
            printf("\033[32mCLEAN\033[0m - No threats detected\n");
            break;
        case 1:
            printf("\033[33mSUSPICIOUS\033[0m - Potentially unwanted behavior detected\n");
            
            // Ask user if they want to remove the suspicious file
            char response[10];
            printf("[QUESTION] This file appears suspicious. Do you want to remove it? (y/n): ");
            if (fgets(response, sizeof(response), stdin) != NULL) {
                if (response[0] == 'y' || response[0] == 'Y') {
                    remove_malicious_file(filename);
                } else {
                    printf("[WARNING] Suspicious file was kept on the system!\n");
                }
            }
            break;
        case 2:
            printf("\033[31mMALICIOUS\033[0m - Threat detected");
            if (threat_name) {
                printf(": %s", threat_name);
            }
            printf("\n");
            
            // Ask user if they want to remove the malicious file
            printf("[QUESTION] Do you want to remove this malicious file? (y/n): ");
            if (fgets(response, sizeof(response), stdin) != NULL) {
                if (response[0] == 'y' || response[0] == 'Y') {
                    remove_malicious_file(filename);
                } else {
                    printf("[WARNING] Malicious file was kept on the system!\n");
                }
            }
            break;
    }
    printf("----------------------------------------\n");
}

// Main hash calculation function
void calculate_file_hashes(const char *filename, char *md5_result, char *sha256_result, size_t result_size) {
    char command[BUFFER_SIZE * 2];
    char buffer[BUFFER_SIZE];

    // Calculate MD5
    snprintf(command, sizeof(command), "md5sum %s 2>/dev/null || md5 -q %s 2>/dev/null", filename, filename);
    FILE *md5 = popen(command, "r");
    if (md5 == NULL) {
        perror("Couldn't calculate md5 hash");
        return;
    }
    if (fgets(buffer, sizeof(buffer), md5) != NULL) {
        char *space = strchr(buffer, ' ');
        if (space != NULL) {
            *space = '\0';
        }
        strncpy(md5_result, buffer, result_size);
        md5_result[result_size - 1] = '\0';  // Ensure null-termination
    } else {
        strncpy(md5_result, "Failed to calculate MD5", result_size);
    }
    pclose(md5);

    // Calculate SHA256
    snprintf(command, sizeof(command), "sha256sum %s 2>/dev/null || shasum -a 256 %s 2>/dev/null", filename, filename);
    FILE *sha256 = popen(command, "r");
    if (sha256 == NULL) {
        perror("Couldn't calculate sha256 hash");
        return;
    }
    if (fgets(buffer, sizeof(buffer), sha256) != NULL) {
        char *space = strchr(buffer, ' ');
        if (space != NULL) {
            *space = '\0';
        }
        strncpy(sha256_result, buffer, result_size);
        sha256_result[result_size - 1] = '\0';  // Ensure null-termination
    } else {
        strncpy(sha256_result, "Failed to calculate SHA256", result_size);
    }
    pclose(sha256);

    printf("MD5: %s\n", md5_result);
    printf("SHA256: %s\n", sha256_result);
}

// Search for known hashes (new version with threat levels)
bool check_hash_in_database(const char *hash, const char *filename, int *threat_level, const char **threat_name) {
    static char detected_name[256] = "Malicious-File";
    
    // Initialize the hash database if it hasn't been already
    initialize_hash_database();
    
    // Check if hash exists in our database
    if (lookup_hash_in_database(hash, detected_name, sizeof(detected_name))) {
        printf("[ALERT] Malicious file signature detected: %s!\n", detected_name);
        *threat_level = 2; // Malicious
        *threat_name = detected_name;
        
        // Attempt to terminate the process if it's running
        if (terminate_malicious_process(filename) == 0) {
            printf("[ACTION] Process terminated successfully\n");
        }
        
        return true;
    }
    
    // Hash not found in local database
    printf("[INFO] File hash not found in local threat database\n");
    return false;
}

// For backward compatibility
void search_hash_in_hash_list(const char *hash, const char *filename) {
    int threat_level = 0;
    const char *threat_name = NULL;
    check_hash_in_database(hash, filename, &threat_level, &threat_name);
}

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

bool query_malware_bazaar(const char *hash) {
#if defined(USE_CURL) && defined(USE_CJSON)
    printf("[INFO] Querying Malware Bazaar for threat intelligence...\n");
    
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    bool found_threat = false;
    static char detected_name[256] = "Unknown-Malware";

    chunk.memory = malloc(1);  // will be grown as needed by the realloc above
    chunk.size = 0;    // no data at this point

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

        char post_fields[256];
        snprintf(post_fields, sizeof(post_fields), "query=get_info&hash=%s", hash);

        curl_easy_setopt(curl, CURLOPT_URL, API_URL);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            printf("[ERROR] API query failed: %s\n", curl_easy_strerror(res));
        } else {
            // Parse JSON response
            cJSON *json = cJSON_Parse(chunk.memory);
            if (json == NULL) {
                printf("[ERROR] Failed to parse response\n");
            } else {
                // Extract the data
                cJSON *data_array = cJSON_GetObjectItem(json, "data");
                if (cJSON_IsArray(data_array) && cJSON_GetArraySize(data_array) > 0) {
                    cJSON *data_item = cJSON_GetArrayItem(data_array, 0);
                    
                    // Extract info
                    cJSON *file_name = cJSON_GetObjectItem(data_item, "file_name");
                    cJSON *tags = cJSON_GetObjectItem(data_item, "tags");
                    cJSON *signature = cJSON_GetObjectItem(data_item, "signature");
                    
                    printf("[ALERT] Threat intelligence found!\n");
                    found_threat = true;
                    
                    // Store the hash and threat name for future use
                    if (cJSON_IsString(signature)) {
                        strncpy(detected_name, signature->valuestring, sizeof(detected_name) - 1);
                        detected_name[sizeof(detected_name) - 1] = '\0';
                        
                        // Add to our modern hash database
                        add_hash_to_database(hash, detected_name);
                    } else if (cJSON_IsString(file_name)) {
                        strncpy(detected_name, file_name->valuestring, sizeof(detected_name) - 1);
                        detected_name[sizeof(detected_name) - 1] = '\0';
                        
                        // Add to our modern hash database
                        add_hash_to_database(hash, detected_name);
                    }
                    
                    if (cJSON_IsString(file_name)) {
                        printf("         - Name: %s\n", file_name->valuestring);
                    }
                    
                    if (cJSON_IsString(signature)) {
                        printf("         - Signature: %s\n", signature->valuestring);
                        // Display malware information if we have it
                        display_malware_info(signature->valuestring);
                    }
                    
                    if (cJSON_IsArray(tags)) {
                        printf("         - Tags: ");
                        int tag_count = cJSON_GetArraySize(tags);
                        for (int i = 0; i < tag_count && i < 5; i++) {
                            cJSON *tag = cJSON_GetArrayItem(tags, i);
                            if (cJSON_IsString(tag)) {
                                printf("%s", tag->valuestring);
                                if (i < tag_count - 1 && i < 4) {
                                    printf(", ");
                                }
                            }
                        }
                        if (tag_count > 5) {
                            printf("...");
                        }
                        printf("\n");
                    }
                    
                    // No need to ask for removal here - this will be handled later
                    // The main analyze_file function will ask for removal after updating the threat level
                } else {
                    printf("[INFO] No online threat intelligence found for hash: %s\n", hash);
                }
                cJSON_Delete(json);
            }
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    free(chunk.memory);
    return found_threat;
#else
    // If libcurl is not available, try to update from local database
    printf("[INFO] Online threat intelligence not available (requires libcurl and cJSON)\n");
    printf("[INFO] Checking for recent signature updates in local database...\n");
    
    // Initialize hash database if needed
    initialize_hash_database();
    
    return false;
#endif
}

double calculate_file_entropy(const char* filename) {
    FILE *entropy_file;
    entropy_file = fopen(filename, "rb");
    if (entropy_file == NULL) {
        printf("Error calculating entropy");
        return -1;
    }

    unsigned long long byte_counts[BYTE_RANGE] = {0};
    unsigned long long file_size = 0;
    int ch;

    while ((ch = fgetc(entropy_file)) != EOF) {
        byte_counts[ch]++;
        file_size++;
    }

    fclose(entropy_file);

    double entropy = 0.0;
    for (int i = 0; i < BYTE_RANGE; i++) {
        if (byte_counts[i] > 0) {
            double probability = (double)byte_counts[i] / file_size;
            entropy -= probability * log2(probability);
        }
    }
    return entropy;
}

int terminate_malicious_process(const char *filePath) {
    #ifdef _WIN32
    // Windows-specific code
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
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
                CloseHandle(hProcessSnap);
                return 0;
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return -1;
    #else
    // Unix-specific code
    char path[PATH_MAX];
    
    #ifdef __linux__
    // Linux-specific: get process path from /proc filesystem
    if (realpath("/proc/self/exe", path) == NULL) {
        perror("Error getting executable path");
        return -1;
    }
    #elif defined(__APPLE__)
    // macOS doesn't have /proc filesystem
    // Use alternate method like _NSGetExecutablePath()
    // For now, just compare process name
    char *process_name = basename((char *)filePath);
    if (getpid() == 0) {
        printf("Cannot determine current process\n");
        return -1;
    }
    #else
    // Other Unix systems
    printf("Process termination not fully implemented for this system\n");
    return -1;
    #endif
    
    #ifdef __linux__
    if (strcmp(path, filePath) == 0) {
        if (kill(getpid(), SIGKILL) == 0) {
            printf("Process killed!\n");
            return 0;
        } else {
            perror("Error killing process");
            return -1;
        }
    }
    #elif defined(__APPLE__)
    // Just report it rather than actually killing for safety
    printf("Would terminate process: %s (simulation)\n", process_name);
    return 0;
    #endif
    
    return -1;
    #endif
}

// Check if a file is a PE (Portable Executable) file
bool is_pe_file(const char* filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return false;
    }
    
    unsigned char header[2];
    size_t read = fread(header, 1, 2, file);
    fclose(file);
    
    if (read != 2) {
        return false;
    }
    
    // Check for MZ header (0x4D, 0x5A)
    return (header[0] == 0x4D && header[1] == 0x5A);
}

// Look for suspicious patterns in the file
bool check_for_suspicious_patterns(const char* filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file for pattern matching");
        return false;
    }
    
    char buffer[4096];
    size_t bytes_read;
    bool suspicious = false;
    
    printf("[INFO] Scanning for suspicious code patterns...\n");
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // Check for common shellcode patterns
        if (memmem(buffer, bytes_read, "\x31\xc0\x50\x68", 4)) { 
            printf("[DETECT] Found shellcode pattern: XOR EAX, EAX; PUSH EAX; PUSH\n");
            suspicious = true;
        }
        
        if (memmem(buffer, bytes_read, "\x68\x63\x6d\x64\x00", 5)) {
            printf("[DETECT] Found suspicious command string: \"cmd\"\n");
            suspicious = true;
        }
        
        if (memmem(buffer, bytes_read, "\x68\x65\x78\x65\x00", 5)) {
            printf("[DETECT] Found suspicious executable reference: \"exe\"\n");
            suspicious = true;
        }
        
        if (memmem(buffer, bytes_read, "\xEB\xFE", 2)) {
            printf("[DETECT] Found potential infinite loop (JMP $-2)\n");
            suspicious = true;
        }
        
        // Check for suspicious API references
        const char *suspicious_apis[] = {
            "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
            "URLDownloadToFile", "WinExec", "ShellExecute", "LoadLibrary",
            "GetProcAddress", "CreateProcess", "socket", "connect"
        };
        
        for (size_t i = 0; i < sizeof(suspicious_apis) / sizeof(suspicious_apis[0]); i++) {
            if (memmem(buffer, bytes_read, suspicious_apis[i], strlen(suspicious_apis[i]))) {
                printf("[DETECT] Found suspicious API reference: %s\n", suspicious_apis[i]);
                suspicious = true;
            }
        }
        
        if (suspicious) {
            break;  // No need to continue if we've already found something
        }
    }
    
    fclose(file);
    
    // Scan for embedded URLs and IP addresses
    file = fopen(filename, "r");
    if (file) {
        int url_count = 0;
        int ip_count = 0;
        
        while (fgets(buffer, sizeof(buffer), file)) {
            // Simple regex-like patterns for URLs
            if (strstr(buffer, "http://") || strstr(buffer, "https://")) {
                if (url_count == 0) {
                    printf("[DETECT] Found network references:\n");
                }
                
                if (url_count < 3) {  // Limit output to 3 URLs
                    char *url = strstr(buffer, "http");
                    char url_buf[256] = {0};
                    strncpy(url_buf, url, 255);
                    
                    // Truncate at whitespace or control chars
                    for (char *p = url_buf; *p; p++) {
                        if (*p <= 32) {
                            *p = 0;
                            break;
                        }
                    }
                    
                    printf("         - URL: %s\n", url_buf);
                } else if (url_count == 3) {
                    printf("         - Additional URLs found...\n");
                }
                
                url_count++;
                suspicious = true;
            }
            
            // Very simple IP address pattern matching
            char *ip_start = buffer;
            while ((ip_start = strstr(ip_start, ".")) != NULL) {
                if (ip_start > buffer && isdigit(*(ip_start-1)) && 
                    ip_start+1 < buffer+strlen(buffer) && isdigit(*(ip_start+1))) {
                    
                    if (ip_count == 0) {
                        if (url_count == 0) {
                            printf("[DETECT] Found network references:\n");
                        }
                    }
                    
                    if (ip_count < 3) {  // Limit output to 3 IPs
                        // Try to extract the IP
                        char ip_buf[20] = {0};
                        char *p = ip_start;
                        int dots = 0;
                        
                        // Go back to find the start of the IP
                        while (p > buffer && (isdigit(*(p-1)) || *(p-1) == '.')) {
                            p--;
                        }
                        
                        // Copy the IP address
                        int j = 0;
                        while (*p && j < 19 && (isdigit(*p) || *p == '.')) {
                            if (*p == '.') dots++;
                            if (dots > 3) break;  // Ensure we don't go past the IP
                            ip_buf[j++] = *p++;
                        }
                        
                        printf("         - IP: %s\n", ip_buf);
                    } else if (ip_count == 3) {
                        printf("         - Additional IPs found...\n");
                    }
                    
                    ip_count++;
                    suspicious = true;
                    break;
                }
                ip_start++;
            }
        }
        
        fclose(file);
    }
    
    if (suspicious) {
        printf("[WARNING] Suspicious patterns detected in file\n");
    } else {
        printf("[INFO] No suspicious patterns detected in file content\n");
    }
    
    return suspicious;
}
