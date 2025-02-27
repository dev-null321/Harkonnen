/*
 * yara_rules.h - YARA rule support for Harkonnen Antivirus
 *
 * This module provides YARA rule integration for custom pattern-based 
 * malware detection capabilities.
 */

#ifndef YARA_RULES_H
#define YARA_RULES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>

// Default YARA rules directory
#define YARA_RULES_DIR "rules"
#define MAX_RULE_SIZE 10240
#define MAX_MATCH_BUFFER 4096
#define RULES_LOADED_LIMIT 64

// Rule structure to store loaded rules
typedef struct {
    char name[256];
    char description[512];
    char pattern[MAX_RULE_SIZE];
    int severity; // 1-Low, 2-Medium, 3-High
    char tags[512];
} YaraRule;

// Global array of loaded rules
static YaraRule loaded_rules[RULES_LOADED_LIMIT];
static int rule_count = 0;

// Initialize YARA system
int initialize_yara() {
    DIR *dir;
    struct dirent *entry;
    struct stat path_stat;
    
    printf("[YARA] Initializing YARA rule engine...\n");
    
    // Create rules directory if it doesn't exist
    if (stat(YARA_RULES_DIR, &path_stat) != 0) {
        printf("[YARA] Rules directory not found, creating...\n");
        
        #ifdef _WIN32
        mkdir(YARA_RULES_DIR);
        #else
        mkdir(YARA_RULES_DIR, 0755);
        #endif
        
        // Create example rules
        create_example_rules();
        printf("[YARA] Created example rules in %s directory\n", YARA_RULES_DIR);
    }
    
    // Open the rules directory
    dir = opendir(YARA_RULES_DIR);
    if (dir == NULL) {
        printf("[YARA ERROR] Failed to open rules directory\n");
        return 0;
    }
    
    // Load all .yar files
    rule_count = 0;
    while ((entry = readdir(dir)) != NULL && rule_count < RULES_LOADED_LIMIT) {
        if (strstr(entry->d_name, ".yar") || strstr(entry->d_name, ".yara")) {
            char rule_path[512];
            snprintf(rule_path, sizeof(rule_path), "%s/%s", YARA_RULES_DIR, entry->d_name);
            
            if (load_yara_rule(rule_path, &loaded_rules[rule_count])) {
                rule_count++;
                printf("[YARA] Loaded rule: %s\n", entry->d_name);
            }
        }
    }
    
    closedir(dir);
    printf("[YARA] Successfully loaded %d rules\n", rule_count);
    return rule_count;
}

// Load a single YARA rule file
int load_yara_rule(const char *rule_path, YaraRule *rule) {
    FILE *file = fopen(rule_path, "r");
    if (file == NULL) {
        printf("[YARA ERROR] Failed to open rule file: %s\n", rule_path);
        return 0;
    }
    
    // Extract rule name from filename
    const char *filename = strrchr(rule_path, '/');
    if (filename) {
        filename++; // Skip the slash
    } else {
        filename = rule_path;
    }
    
    strncpy(rule->name, filename, sizeof(rule->name) - 1);
    rule->name[sizeof(rule->name) - 1] = '\0';
    
    // Default values
    strcpy(rule->description, "No description");
    rule->severity = 2; // Medium by default
    strcpy(rule->tags, "custom");
    
    // Read file contents
    char buffer[MAX_RULE_SIZE] = {0};
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
    buffer[bytes_read] = '\0';
    
    // Copy pattern
    strncpy(rule->pattern, buffer, sizeof(rule->pattern) - 1);
    rule->pattern[sizeof(rule->pattern) - 1] = '\0';
    
    // Parse metadata if available
    char *meta_start = strstr(buffer, "meta:");
    if (meta_start) {
        char *meta_end = strstr(meta_start, "strings:");
        if (!meta_end) {
            meta_end = strstr(meta_start, "condition:");
        }
        
        if (meta_end) {
            // Extract description
            char *desc = strstr(meta_start, "description =");
            if (desc && desc < meta_end) {
                desc += 13; // Skip "description ="
                while (*desc == ' ' || *desc == '\"') desc++; // Skip spaces and quotes
                
                char *desc_end = strchr(desc, '\"');
                if (desc_end) {
                    size_t desc_len = desc_end - desc;
                    if (desc_len < sizeof(rule->description)) {
                        strncpy(rule->description, desc, desc_len);
                        rule->description[desc_len] = '\0';
                    }
                }
            }
            
            // Extract severity
            char *severity = strstr(meta_start, "severity =");
            if (severity && severity < meta_end) {
                severity += 10; // Skip "severity ="
                while (*severity == ' ' || *severity == '\"') severity++; // Skip spaces and quotes
                
                if (*severity == '1' || *severity == 'l' || *severity == 'L')
                    rule->severity = 1;
                else if (*severity == '3' || *severity == 'h' || *severity == 'H')
                    rule->severity = 3;
                else
                    rule->severity = 2; // Default to medium
            }
            
            // Extract tags
            char *tags = strstr(meta_start, "tags =");
            if (tags && tags < meta_end) {
                tags += 6; // Skip "tags ="
                while (*tags == ' ' || *tags == '\"') tags++; // Skip spaces and quotes
                
                char *tags_end = strchr(tags, '\"');
                if (tags_end) {
                    size_t tags_len = tags_end - tags;
                    if (tags_len < sizeof(rule->tags)) {
                        strncpy(rule->tags, tags, tags_len);
                        rule->tags[tags_len] = '\0';
                    }
                }
            }
        }
    }
    
    fclose(file);
    return 1;
}

// Create example YARA rules
void create_example_rules() {
    // Example rule 1: Generic PowerShell obfuscation
    const char *rule1 = 
        "rule PowerShell_Obfuscation {\n"
        "    meta:\n"
        "        description = \"Detects obfuscated PowerShell scripts\"\n"
        "        severity = \"medium\"\n"
        "        tags = \"powershell,obfuscation\"\n"
        "    strings:\n"
        "        $s1 = \"[System.Convert]::FromBase64String\" nocase\n"
        "        $s2 = \"Invoke-Expression\" nocase\n"
        "        $s3 = \"IEX\" nocase\n"
        "        $s4 = \"-enc\" nocase\n"
        "        $s5 = \"-encodedcommand\" nocase\n"
        "    condition:\n"
        "        2 of them\n"
        "}\n";
    
    // Example rule 2: Generic ransomware indicators
    const char *rule2 = 
        "rule Ransomware_Generic_Indicators {\n"
        "    meta:\n"
        "        description = \"Detects common ransomware indicators\"\n"
        "        severity = \"high\"\n"
        "        tags = \"ransomware,encryption\"\n"
        "    strings:\n"
        "        $readme1 = \"readme.txt\" nocase\n"
        "        $readme2 = \"how_to_decrypt\" nocase\n"
        "        $readme3 = \"your_files_are_encrypted\" nocase\n"
        "        $ext1 = \".encrypted\" nocase\n"
        "        $ext2 = \".locked\" nocase\n"
        "        $ext3 = \".crypto\" nocase\n"
        "        $bitcoin = \"bitcoin\" nocase\n"
        "        $wallet = \"wallet\" nocase\n"
        "        $ransom = \"ransom\" nocase\n"
        "        $decrypt = \"decrypt\" nocase\n"
        "    condition:\n"
        "        (1 of ($readme*)) and (1 of ($ext*)) and (2 of ($bitcoin, $wallet, $ransom, $decrypt))\n"
        "}\n";
    
    // Example rule 3: Suspicious command execution
    const char *rule3 = 
        "rule Suspicious_Command_Execution {\n"
        "    meta:\n"
        "        description = \"Detects suspicious command execution patterns\"\n"
        "        severity = \"medium\"\n"
        "        tags = \"command,execution,shell\"\n"
        "    strings:\n"
        "        $cmd1 = \"cmd.exe /c\" nocase\n"
        "        $cmd2 = \"powershell.exe -\" nocase\n"
        "        $cmd3 = \"WScript.Shell\" nocase\n"
        "        $cmd4 = \"Process.Start\" nocase\n"
        "        $cmd5 = \"ShellExecute\" nocase\n"
        "        $cmd6 = \"shell32.dll\" nocase\n"
        "    condition:\n"
        "        2 of them\n"
        "}\n";
    
    // Write the example rules to files
    char rule_path[512];
    FILE *file;
    
    // Rule 1
    snprintf(rule_path, sizeof(rule_path), "%s/powershell_obfuscation.yar", YARA_RULES_DIR);
    file = fopen(rule_path, "w");
    if (file) {
        fputs(rule1, file);
        fclose(file);
    }
    
    // Rule 2
    snprintf(rule_path, sizeof(rule_path), "%s/ransomware_indicators.yar", YARA_RULES_DIR);
    file = fopen(rule_path, "w");
    if (file) {
        fputs(rule2, file);
        fclose(file);
    }
    
    // Rule 3
    snprintf(rule_path, sizeof(rule_path), "%s/suspicious_command.yar", YARA_RULES_DIR);
    file = fopen(rule_path, "w");
    if (file) {
        fputs(rule3, file);
        fclose(file);
    }
}

// Scan file with YARA rules (simplified implementation)
int scan_file_with_yara(const char *filepath, char *detection_name, size_t name_size, int *severity) {
    FILE *file = fopen(filepath, "rb");
    if (file == NULL) {
        printf("[YARA ERROR] Failed to open file for scanning: %s\n", filepath);
        return 0;
    }
    
    // Read file content for pattern matching
    char buffer[MAX_MATCH_BUFFER];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
    buffer[bytes_read] = '\0';
    fclose(file);
    
    // Check each rule
    for (int i = 0; i < rule_count; i++) {
        YaraRule *rule = &loaded_rules[i];
        
        // Simple pattern matching simulation
        // In a real implementation, this would use the YARA library
        if (strstr(rule->pattern, "condition:") && 
            (strstr(buffer, "powershell") || 
             strstr(buffer, "cmd.exe") || 
             strstr(buffer, "decrypt") ||
             strstr(buffer, "ransom") ||
             strstr(buffer, "bitcoin") ||
             strstr(buffer, ".encrypted"))) {
            
            // Found a match
            if (detection_name) {
                snprintf(detection_name, name_size, "YARA:%s", rule->name);
            }
            
            if (severity) {
                *severity = rule->severity;
            }
            
            printf("[YARA] Rule matched: %s - %s\n", rule->name, rule->description);
            return 1;
        }
    }
    
    return 0;
}

// Implements a simplified version of the YARA matching engine
// In a real implementation, this would use the actual YARA library
int yara_match_data(const char *data, size_t length, char *detection_name, size_t name_size, int *severity) {
    // Check each rule
    for (int i = 0; i < rule_count; i++) {
        YaraRule *rule = &loaded_rules[i];
        
        // Extract string patterns from rule (very simplified)
        char *strings_start = strstr(rule->pattern, "strings:");
        if (!strings_start) continue;
        
        char *condition_start = strstr(rule->pattern, "condition:");
        if (!condition_start) continue;
        
        // Parse out the string patterns (simplified)
        char *ptr = strings_start;
        int match_count = 0;
        int required_matches = 1; // Default
        
        // Find condition requirements like "2 of them" or "1 of ($a*)"
        char *of_them = strstr(condition_start, "of them");
        if (of_them) {
            char *num = of_them - 3;
            while (num > condition_start && (*num == ' ' || *num == '\t')) num--;
            if (isdigit(*num)) {
                required_matches = *num - '0';
            }
        }
        
        // Perform matching
        while (ptr < condition_start) {
            // Find string definition lines like $s1 = "pattern"
            char *string_def = strstr(ptr, "$");
            if (!string_def || string_def >= condition_start) break;
            
            // Find the quoted pattern
            char *pattern_start = strchr(string_def, '\"');
            if (!pattern_start || pattern_start >= condition_start) {
                ptr = string_def + 1;
                continue;
            }
            
            // Find end of pattern
            char *pattern_end = strchr(pattern_start + 1, '\"');
            if (!pattern_end || pattern_end >= condition_start) {
                ptr = pattern_start + 1;
                continue;
            }
            
            // Extract the pattern
            size_t pattern_len = pattern_end - pattern_start - 1;
            if (pattern_len < 1) {
                ptr = pattern_end + 1;
                continue;
            }
            
            char pattern[256] = {0};
            if (pattern_len > sizeof(pattern) - 1) {
                pattern_len = sizeof(pattern) - 1;
            }
            strncpy(pattern, pattern_start + 1, pattern_len);
            pattern[pattern_len] = '\0';
            
            // Check for nocase modifier
            int case_insensitive = strstr(pattern_end, "nocase") != NULL && 
                                  strstr(pattern_end, "nocase") < (ptr + 20);
            
            // Perform the actual pattern match
            int found = 0;
            if (case_insensitive) {
                // Case-insensitive search
                for (size_t i = 0; i <= length - pattern_len; i++) {
                    if (strncasecmp(data + i, pattern, pattern_len) == 0) {
                        found = 1;
                        break;
                    }
                }
            } else {
                // Case-sensitive search
                for (size_t i = 0; i <= length - pattern_len; i++) {
                    if (strncmp(data + i, pattern, pattern_len) == 0) {
                        found = 1;
                        break;
                    }
                }
            }
            
            if (found) {
                match_count++;
                if (match_count >= required_matches) {
                    // Rule matched
                    if (detection_name) {
                        snprintf(detection_name, name_size, "YARA:%s", rule->name);
                    }
                    
                    if (severity) {
                        *severity = rule->severity;
                    }
                    
                    printf("[YARA] Rule matched: %s - %s\n", rule->name, rule->description);
                    return 1;
                }
            }
            
            ptr = pattern_end + 1;
        }
    }
    
    return 0;
}

// Add a new YARA rule
int add_yara_rule(const char *rule_name, const char *rule_content) {
    char rule_path[512];
    snprintf(rule_path, sizeof(rule_path), "%s/%s.yar", YARA_RULES_DIR, rule_name);
    
    // Check if rule already exists
    if (access(rule_path, F_OK) == 0) {
        printf("[YARA ERROR] Rule already exists: %s\n", rule_name);
        return 0;
    }
    
    // Write the rule to a file
    FILE *file = fopen(rule_path, "w");
    if (!file) {
        printf("[YARA ERROR] Failed to create rule file: %s\n", rule_path);
        return 0;
    }
    
    fputs(rule_content, file);
    fclose(file);
    
    // Reload the rules
    if (rule_count < RULES_LOADED_LIMIT) {
        if (load_yara_rule(rule_path, &loaded_rules[rule_count])) {
            rule_count++;
            printf("[YARA] Added new rule: %s\n", rule_name);
            return 1;
        }
    } else {
        printf("[YARA ERROR] Maximum number of rules reached\n");
    }
    
    return 0;
}

// List all loaded YARA rules
void list_yara_rules() {
    printf("========================================================\n");
    printf("== YARA Rules List                                    ==\n");
    printf("========================================================\n\n");
    
    printf("Total rules loaded: %d\n\n", rule_count);
    
    printf("%-30s %-15s %-30s\n", "Rule Name", "Severity", "Description");
    printf("%-30s %-15s %-30s\n", "-----------------------------", "---------------", "-----------------------------");
    
    for (int i = 0; i < rule_count; i++) {
        const char *severity_str;
        switch (loaded_rules[i].severity) {
            case 1: severity_str = "Low"; break;
            case 3: severity_str = "High"; break;
            default: severity_str = "Medium"; break;
        }
        
        printf("%-30s %-15s %-30s\n", 
               loaded_rules[i].name, 
               severity_str, 
               loaded_rules[i].description);
    }
    
    printf("\n");
}

#endif /* YARA_RULES_H */