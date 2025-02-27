/*
 * threaded_scanner.h - Multi-threaded scanning for Harkonnen Antivirus
 *
 * This module provides multi-threaded file scanning capabilities to improve 
 * performance on multi-core systems.
 */

#ifndef THREADED_SCANNER_H
#define THREADED_SCANNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_THREAD_COUNT 16
#define MAX_PATH_LENGTH 1024
#define MAX_QUEUE_SIZE 10000

// Scan result structure
typedef struct {
    char filepath[MAX_PATH_LENGTH];
    int threat_level;  // 0 = clean, 1 = suspicious, 2 = malicious
    char threat_name[256];
    double scan_time;
} ScanResult;

// Scan queue for worker threads
typedef struct {
    char filepaths[MAX_QUEUE_SIZE][MAX_PATH_LENGTH];
    int front;
    int rear;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    int finished;  // Flag to indicate no more files to scan
} ScanQueue;

// Results storage
typedef struct {
    ScanResult results[MAX_QUEUE_SIZE];
    int count;
    pthread_mutex_t mutex;
} ResultsStorage;

// Thread pool
typedef struct {
    pthread_t threads[MAX_THREAD_COUNT];
    int thread_count;
    ScanQueue queue;
    ResultsStorage results;
    pthread_mutex_t stats_mutex;
    int files_processed;
    int threats_found;
} ThreadPool;

// Global thread pool
static ThreadPool thread_pool;

// Function prototypes
int initialize_thread_pool(int thread_count);
void destroy_thread_pool();
int queue_file_for_scanning(const char *filepath);
int process_directory_threaded(const char *dirpath);
ScanResult *get_scan_results(int *count);
void print_scan_summary();
void wait_for_scan_completion();

// Worker thread function declaration
void *scanner_worker(void *arg);

// Initialize the thread pool and start worker threads
int initialize_thread_pool(int thread_count) {
    if (thread_count <= 0) {
        thread_count = 4;  // Default to 4 threads
    } else if (thread_count > MAX_THREAD_COUNT) {
        thread_count = MAX_THREAD_COUNT;
    }
    
    // Initialize the scan queue
    thread_pool.queue.front = 0;
    thread_pool.queue.rear = 0;
    thread_pool.queue.count = 0;
    thread_pool.queue.finished = 0;
    pthread_mutex_init(&thread_pool.queue.mutex, NULL);
    pthread_cond_init(&thread_pool.queue.not_empty, NULL);
    pthread_cond_init(&thread_pool.queue.not_full, NULL);
    
    // Initialize results storage
    thread_pool.results.count = 0;
    pthread_mutex_init(&thread_pool.results.mutex, NULL);
    
    // Initialize statistics
    pthread_mutex_init(&thread_pool.stats_mutex, NULL);
    thread_pool.files_processed = 0;
    thread_pool.threats_found = 0;
    
    // Start worker threads
    thread_pool.thread_count = thread_count;
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&thread_pool.threads[i], NULL, scanner_worker, NULL) != 0) {
            fprintf(stderr, "[THREAD ERROR] Failed to create worker thread %d\n", i);
            return 0;
        }
    }
    
    printf("[THREADING] Started %d scanner threads\n", thread_count);
    return 1;
}

// Destroy the thread pool and clean up resources
void destroy_thread_pool() {
    // Mark the queue as finished
    pthread_mutex_lock(&thread_pool.queue.mutex);
    thread_pool.queue.finished = 1;
    pthread_cond_broadcast(&thread_pool.queue.not_empty);
    pthread_mutex_unlock(&thread_pool.queue.mutex);
    
    // Wait for all threads to finish
    for (int i = 0; i < thread_pool.thread_count; i++) {
        pthread_join(thread_pool.threads[i], NULL);
    }
    
    // Clean up mutexes and condition variables
    pthread_mutex_destroy(&thread_pool.queue.mutex);
    pthread_cond_destroy(&thread_pool.queue.not_empty);
    pthread_cond_destroy(&thread_pool.queue.not_full);
    pthread_mutex_destroy(&thread_pool.results.mutex);
    pthread_mutex_destroy(&thread_pool.stats_mutex);
    
    printf("[THREADING] Thread pool shutdown complete\n");
}

// Add a file to the scan queue
int queue_file_for_scanning(const char *filepath) {
    pthread_mutex_lock(&thread_pool.queue.mutex);
    
    // Check if queue is full
    while (thread_pool.queue.count >= MAX_QUEUE_SIZE) {
        pthread_cond_wait(&thread_pool.queue.not_full, &thread_pool.queue.mutex);
    }
    
    // Add the file to the queue
    strncpy(thread_pool.queue.filepaths[thread_pool.queue.rear], filepath, MAX_PATH_LENGTH - 1);
    thread_pool.queue.filepaths[thread_pool.queue.rear][MAX_PATH_LENGTH - 1] = '\0';
    
    thread_pool.queue.rear = (thread_pool.queue.rear + 1) % MAX_QUEUE_SIZE;
    thread_pool.queue.count++;
    
    // Signal that the queue is not empty
    pthread_cond_signal(&thread_pool.queue.not_empty);
    pthread_mutex_unlock(&thread_pool.queue.mutex);
    
    return 1;
}

// Recursively process a directory with the thread pool
int process_directory_threaded(const char *dirpath) {
    DIR *dir;
    struct dirent *entry;
    struct stat path_stat;
    
    dir = opendir(dirpath);
    if (dir == NULL) {
        fprintf(stderr, "[ERROR] Failed to open directory: %s\n", dirpath);
        return 0;
    }
    
    int file_count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        // Construct the full path
        char full_path[MAX_PATH_LENGTH];
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);
        
        if (stat(full_path, &path_stat) != 0) {
            fprintf(stderr, "[ERROR] Failed to stat file: %s\n", full_path);
            continue;
        }
        
        if (S_ISDIR(path_stat.st_mode)) {
            // Recursively process subdirectories
            process_directory_threaded(full_path);
        } else if (S_ISREG(path_stat.st_mode)) {
            // Queue the file for scanning
            queue_file_for_scanning(full_path);
            file_count++;
        }
    }
    
    closedir(dir);
    return file_count;
}

// Get the scan results
ScanResult *get_scan_results(int *count) {
    pthread_mutex_lock(&thread_pool.results.mutex);
    *count = thread_pool.results.count;
    ScanResult *results = thread_pool.results.results;
    pthread_mutex_unlock(&thread_pool.results.mutex);
    
    return results;
}

// Print a summary of the scan results
void print_scan_summary() {
    pthread_mutex_lock(&thread_pool.stats_mutex);
    int files_processed = thread_pool.files_processed;
    int threats_found = thread_pool.threats_found;
    pthread_mutex_unlock(&thread_pool.stats_mutex);
    
    printf("\n========================================================\n");
    printf("MULTI-THREADED SCAN SUMMARY\n");
    printf("========================================================\n");
    printf("Files scanned: %d\n", files_processed);
    printf("Threats found: %d\n", threats_found);
    
    if (threats_found > 0) {
        printf("\033[31mWARNING: Threats detected!\033[0m\n");
    } else {
        printf("\033[32mAll files are clean.\033[0m\n");
    }
    printf("========================================================\n");
}

// Wait for all queued scans to complete
void wait_for_scan_completion() {
    // Wait until the queue is empty and all threads have processed their files
    while (1) {
        pthread_mutex_lock(&thread_pool.queue.mutex);
        int queue_empty = (thread_pool.queue.count == 0);
        pthread_mutex_unlock(&thread_pool.queue.mutex);
        
        if (queue_empty) {
            break;
        }
        
        // Sleep for a short time to avoid busy waiting
        usleep(100000);  // 100ms
    }
    
    // Give threads a moment to finish processing
    usleep(500000);  // 500ms
}

// Worker thread function
void *scanner_worker(void *arg) {
    while (1) {
        char filepath[MAX_PATH_LENGTH];
        int dequeued = 0;
        
        // Get a file from the queue
        pthread_mutex_lock(&thread_pool.queue.mutex);
        
        while (thread_pool.queue.count == 0) {
            // If there are no more files to scan and the queue is marked as finished, exit
            if (thread_pool.queue.finished) {
                pthread_mutex_unlock(&thread_pool.queue.mutex);
                return NULL;
            }
            
            // Wait for a file to be added to the queue
            pthread_cond_wait(&thread_pool.queue.not_empty, &thread_pool.queue.mutex);
            
            // Check again if we should exit
            if (thread_pool.queue.finished && thread_pool.queue.count == 0) {
                pthread_mutex_unlock(&thread_pool.queue.mutex);
                return NULL;
            }
        }
        
        // Get the file from the front of the queue
        strncpy(filepath, thread_pool.queue.filepaths[thread_pool.queue.front], MAX_PATH_LENGTH);
        thread_pool.queue.front = (thread_pool.queue.front + 1) % MAX_QUEUE_SIZE;
        thread_pool.queue.count--;
        dequeued = 1;
        
        // Signal that the queue is not full
        pthread_cond_signal(&thread_pool.queue.not_full);
        pthread_mutex_unlock(&thread_pool.queue.mutex);
        
        if (dequeued) {
            // Scan the file (simplified here)
            // In a real implementation, this would call into the main scanning functions
            
            // Simulated scan
            ScanResult result;
            strncpy(result.filepath, filepath, MAX_PATH_LENGTH - 1);
            result.filepath[MAX_PATH_LENGTH - 1] = '\0';
            
            // Call the scanning function(s) to get actual results
            // This is a placeholder - replace with actual scanning function calls
            result.threat_level = 0;  // Assuming clean by default
            result.threat_name[0] = '\0';
            
            // Pretend to analyze the file
            // In the real implementation, call analyze_file() or similar
            const char *filename = strrchr(filepath, '/');
            if (filename) {
                filename++;  // Skip the slash
            } else {
                filename = filepath;
            }
            
            // For demonstration purposes only - a real implementation would call the actual scanning functions
            if (strstr(filename, "virus") || strstr(filename, "malware")) {
                result.threat_level = 2;  // Malicious
                strcpy(result.threat_name, "Demo-Malware");
            } else if (strstr(filename, "suspect") || strstr(filename, "suspicious")) {
                result.threat_level = 1;  // Suspicious
                strcpy(result.threat_name, "Demo-Suspicious");
            }
            
            // Update statistics
            pthread_mutex_lock(&thread_pool.stats_mutex);
            thread_pool.files_processed++;
            if (result.threat_level > 0) {
                thread_pool.threats_found++;
            }
            pthread_mutex_unlock(&thread_pool.stats_mutex);
            
            // Store the result
            pthread_mutex_lock(&thread_pool.results.mutex);
            if (thread_pool.results.count < MAX_QUEUE_SIZE) {
                thread_pool.results.results[thread_pool.results.count] = result;
                thread_pool.results.count++;
            }
            pthread_mutex_unlock(&thread_pool.results.mutex);
            
            // Print progress every 10 files (optional)
            pthread_mutex_lock(&thread_pool.stats_mutex);
            if (thread_pool.files_processed % 10 == 0) {
                printf("\r[PROGRESS] Files scanned: %d, Threats found: %d", 
                       thread_pool.files_processed, thread_pool.threats_found);
                fflush(stdout);
            }
            pthread_mutex_unlock(&thread_pool.stats_mutex);
        }
    }
    
    return NULL;
}

// Helper function to estimate how many threads to use based on available cores
int get_optimal_thread_count() {
    int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores <= 0) {
        return 4;  // Default to 4 if we can't determine
    }
    
    // Use 75% of available cores for scanning
    int thread_count = (num_cores * 3) / 4;
    if (thread_count < 1) thread_count = 1;
    if (thread_count > MAX_THREAD_COUNT) thread_count = MAX_THREAD_COUNT;
    
    return thread_count;
}

#endif /* THREADED_SCANNER_H */