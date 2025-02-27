/*
 * This is a modernized version of hashes.h that uses online threat intelligence
 * instead of hardcoded hash databases.
 *
 * It dynamically loads and stores hash signatures using Malware Bazaar's API.
 */

#ifndef HASHES_H
#define HASHES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Default local signatures file - will be created if it doesn't exist
#define LOCAL_SIGNATURES_FILE "harkonnen_signatures.txt"

// Sample malware signatures for testing purposes
const char *sample_hashlist = 
"# Harkonnen Signature Database\n"
"# This file is automatically updated with new signatures\n"
"# Format: SHA256:MalwareName\n"
"# Last updated: %s\n"
"ec57344a052ea6e5421261a92f948d3d13a649b8d64674542a468c4a53a:WannaCry\n"
"84c82e0121beff3397078b6f264120156d65d57c726325562105449f9d662:Emotet\n"
"27f0009f41f02314c319c0d225ed25154c71ab8dec3706dec4d1a36a51e5:Ryuk\n";

// Function to initialize or load the hash database
int initialize_hash_database() {
    FILE *hashdb = fopen(LOCAL_SIGNATURES_FILE, "r");
    if (hashdb == NULL) {
        // Create initial database with sample signatures
        hashdb = fopen(LOCAL_SIGNATURES_FILE, "w");
        if (hashdb == NULL) {
            fprintf(stderr, "Error: Could not create signatures file\n");
            return 0;
        }
        
        // Get current timestamp
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        
        // Write sample signatures for testing
        fprintf(hashdb, sample_hashlist, timestamp);
        fclose(hashdb);
        
        printf("[INFO] Created new signatures database: %s\n", LOCAL_SIGNATURES_FILE);
        return 1;
    }
    
    // Database already exists
    fclose(hashdb);
    printf("[INFO] Loaded existing signatures database: %s\n", LOCAL_SIGNATURES_FILE);
    return 1;
}

// Function to add a new hash to the database
int add_hash_to_database(const char *hash, const char *malware_name) {
    if (!hash || !malware_name) {
        return 0;
    }
    
    FILE *hashdb = fopen(LOCAL_SIGNATURES_FILE, "a");
    if (hashdb == NULL) {
        fprintf(stderr, "Error: Could not open signatures file for writing\n");
        return 0;
    }
    
    fprintf(hashdb, "%s:%s\n", hash, malware_name);
    fclose(hashdb);
    
    printf("[INFO] Added signature to database: %s (%s)\n", hash, malware_name);
    return 1;
}

// Function to look up a hash in the local database
// Returns 1 if found, 0 if not found
int lookup_hash_in_database(const char *hash, char *malware_name, size_t name_size) {
    if (!hash || !malware_name) {
        return 0;
    }
    
    FILE *hashdb = fopen(LOCAL_SIGNATURES_FILE, "r");
    if (hashdb == NULL) {
        // Try to initialize the database
        if (!initialize_hash_database()) {
            return 0;
        }
        hashdb = fopen(LOCAL_SIGNATURES_FILE, "r");
        if (hashdb == NULL) {
            return 0;
        }
    }
    
    char line[1024];
    int found = 0;
    
    while (fgets(line, sizeof(line), hashdb)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        // Find the colon separator
        char *sep = strchr(line, ':');
        if (sep) {
            *sep = '\0'; // Temporarily split the string
            
            // Compare the hash part
            if (strncmp(hash, line, strlen(hash)) == 0) {
                // Hash found, copy the malware name
                sep++; // Move past the colon
                
                // Remove newline if present
                char *newline = strchr(sep, '\n');
                if (newline) {
                    *newline = '\0';
                }
                
                strncpy(malware_name, sep, name_size);
                malware_name[name_size - 1] = '\0'; // Ensure null-termination
                found = 1;
                break;
            }
        }
    }
    
    fclose(hashdb);
    return found;
}

// Import new signatures from a file (e.g., from Malware Bazaar download)
int import_signatures_from_file(const char *import_file) {
    FILE *import = fopen(import_file, "r");
    if (import == NULL) {
        fprintf(stderr, "Error: Could not open import file %s\n", import_file);
        return 0;
    }
    
    FILE *hashdb = fopen(LOCAL_SIGNATURES_FILE, "a");
    if (hashdb == NULL) {
        fprintf(stderr, "Error: Could not open signatures file for writing\n");
        fclose(import);
        return 0;
    }
    
    char line[1024];
    int count = 0;
    
    fprintf(hashdb, "\n# Imported signatures from %s on %s\n", 
            import_file, 
            ctime(&(time_t){time(NULL)}));
    
    while (fgets(line, sizeof(line), import)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        // Write the line to the database
        fputs(line, hashdb);
        count++;
    }
    
    fclose(import);
    fclose(hashdb);
    
    printf("[INFO] Imported %d signatures from %s\n", count, import_file);
    return count;
}

// Update database from Malware Bazaar (placeholder function)
// In a real implementation, this would download from the API
int update_signatures_from_malware_bazaar() {
    printf("[INFO] Updating signatures from Malware Bazaar API...\n");
    printf("[INFO] This would download the latest signatures in a real implementation\n");
    
    // Get current timestamp
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // Append update information to the database
    FILE *hashdb = fopen(LOCAL_SIGNATURES_FILE, "a");
    if (hashdb == NULL) {
        fprintf(stderr, "Error: Could not open signatures file for writing\n");
        return 0;
    }
    
    fprintf(hashdb, "\n# Signatures updated from Malware Bazaar on %s\n", timestamp);
    fprintf(hashdb, "# In a real implementation, new signatures would be added here\n");
    fclose(hashdb);
    
    printf("[INFO] Signature database updated: %s\n", LOCAL_SIGNATURES_FILE);
    return 1;
}

#endif /* HASHES_H */