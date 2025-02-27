/*
 * report_generator.h - Report generation for Harkonnen Antivirus
 *
 * This module generates detailed HTML and text reports of scan results.
 */

#ifndef REPORT_GENERATOR_H
#define REPORT_GENERATOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define REPORT_DIR "reports"
#define MAX_PATH_LENGTH 1024

// Report data structure
typedef struct {
    char scan_target[MAX_PATH_LENGTH];
    char scan_date[64];
    int total_files;
    int clean_files;
    int suspicious_files;
    int malicious_files;
    double scan_duration;
    char scan_options[256];
    
    // Detection records
    struct {
        char filepath[MAX_PATH_LENGTH];
        int threat_level;  // 0 = clean, 1 = suspicious, 2 = malicious
        char threat_name[256];
        char threat_description[512];
        double entropy;
    } detections[1000];
    int detection_count;
    
    // System information
    char system_name[64];
    char system_version[64];
    char harkonnen_version[32];
} ScanReport;

// Create a new scan report
ScanReport *create_scan_report(const char *target) {
    ScanReport *report = (ScanReport *)malloc(sizeof(ScanReport));
    if (!report) {
        fprintf(stderr, "[ERROR] Failed to allocate memory for scan report\n");
        return NULL;
    }
    
    // Initialize report
    memset(report, 0, sizeof(ScanReport));
    
    // Set scan target
    strncpy(report->scan_target, target, MAX_PATH_LENGTH - 1);
    
    // Set scan date
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(report->scan_date, sizeof(report->scan_date), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Set system information
    #ifdef _WIN32
    strcpy(report->system_name, "Windows");
    OSVERSIONINFOEX os_info;
    memset(&os_info, 0, sizeof(OSVERSIONINFOEX));
    os_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((OSVERSIONINFO*)&os_info);
    sprintf(report->system_version, "%d.%d.%d", 
            os_info.dwMajorVersion, os_info.dwMinorVersion, os_info.dwBuildNumber);
    #elif defined(__APPLE__)
    strcpy(report->system_name, "macOS");
    FILE *fp = popen("sw_vers -productVersion", "r");
    if (fp) {
        fgets(report->system_version, sizeof(report->system_version), fp);
        pclose(fp);
    } else {
        strcpy(report->system_version, "Unknown");
    }
    #elif defined(__linux__)
    strcpy(report->system_name, "Linux");
    FILE *fp = popen("uname -r", "r");
    if (fp) {
        fgets(report->system_version, sizeof(report->system_version), fp);
        pclose(fp);
    } else {
        strcpy(report->system_version, "Unknown");
    }
    #else
    strcpy(report->system_name, "Unknown");
    strcpy(report->system_version, "Unknown");
    #endif
    
    // Set Harkonnen version
    strcpy(report->harkonnen_version, "2.0.0");
    
    return report;
}

// Add a detection to the report
void add_detection_to_report(ScanReport *report, const char *filepath, int threat_level, 
                           const char *threat_name, const char *threat_description, double entropy) {
    if (!report || report->detection_count >= 1000) {
        return;
    }
    
    int idx = report->detection_count;
    
    strncpy(report->detections[idx].filepath, filepath, MAX_PATH_LENGTH - 1);
    report->detections[idx].threat_level = threat_level;
    
    if (threat_name) {
        strncpy(report->detections[idx].threat_name, threat_name, sizeof(report->detections[idx].threat_name) - 1);
    } else {
        strcpy(report->detections[idx].threat_name, "Unknown");
    }
    
    if (threat_description) {
        strncpy(report->detections[idx].threat_description, threat_description, 
                sizeof(report->detections[idx].threat_description) - 1);
    } else {
        strcpy(report->detections[idx].threat_description, "No description available");
    }
    
    report->detections[idx].entropy = entropy;
    report->detection_count++;
    
    // Update counters
    report->total_files++;
    if (threat_level == 0) {
        report->clean_files++;
    } else if (threat_level == 1) {
        report->suspicious_files++;
    } else if (threat_level == 2) {
        report->malicious_files++;
    }
}

// Generate HTML report
char *generate_html_report(ScanReport *report) {
    if (!report) {
        return NULL;
    }
    
    // Create reports directory if it doesn't exist
    struct stat st = {0};
    if (stat(REPORT_DIR, &st) == -1) {
        #ifdef _WIN32
        mkdir(REPORT_DIR);
        #else
        mkdir(REPORT_DIR, 0755);
        #endif
    }
    
    // Generate report filename
    char report_file[MAX_PATH_LENGTH];
    char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    
    snprintf(report_file, sizeof(report_file), "%s/harkonnen_report_%s.html", REPORT_DIR, timestamp);
    
    FILE *fp = fopen(report_file, "w");
    if (!fp) {
        fprintf(stderr, "[ERROR] Failed to create report file: %s\n", report_file);
        return NULL;
    }
    
    // Write HTML header
    fprintf(fp, "<!DOCTYPE html>\n");
    fprintf(fp, "<html lang=\"en\">\n");
    fprintf(fp, "<head>\n");
    fprintf(fp, "    <meta charset=\"UTF-8\">\n");
    fprintf(fp, "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    fprintf(fp, "    <title>Harkonnen Antivirus Scan Report</title>\n");
    fprintf(fp, "    <style>\n");
    fprintf(fp, "        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }\n");
    fprintf(fp, "        .container { max-width: 1200px; margin: 0 auto; }\n");
    fprintf(fp, "        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px 5px 0 0; }\n");
    fprintf(fp, "        .summary { background-color: #f8f9fa; padding: 20px; border-left: 1px solid #ddd; border-right: 1px solid #ddd; }\n");
    fprintf(fp, "        .details { padding: 20px; border: 1px solid #ddd; border-radius: 0 0 5px 5px; }\n");
    fprintf(fp, "        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }\n");
    fprintf(fp, "        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }\n");
    fprintf(fp, "        th { background-color: #f8f9fa; }\n");
    fprintf(fp, "        .clean { color: green; }\n");
    fprintf(fp, "        .suspicious { color: orange; }\n");
    fprintf(fp, "        .malicious { color: red; }\n");
    fprintf(fp, "        .chart { height: 20px; background-color: #e9ecef; border-radius: 3px; overflow: hidden; margin: 10px 0; }\n");
    fprintf(fp, "        .chart-bar { height: 100%%; float: left; }\n");
    fprintf(fp, "        .chart-clean { background-color: #28a745; }\n");
    fprintf(fp, "        .chart-suspicious { background-color: #ffc107; }\n");
    fprintf(fp, "        .chart-malicious { background-color: #dc3545; }\n");
    fprintf(fp, "        .footer { margin-top: 30px; text-align: center; color: #777; font-size: 0.9em; }\n");
    fprintf(fp, "    </style>\n");
    fprintf(fp, "</head>\n");
    fprintf(fp, "<body>\n");
    fprintf(fp, "    <div class=\"container\">\n");
    
    // Header
    fprintf(fp, "        <div class=\"header\">\n");
    fprintf(fp, "            <h1>Harkonnen Antivirus Scan Report</h1>\n");
    fprintf(fp, "            <p>Generated on %s</p>\n", report->scan_date);
    fprintf(fp, "        </div>\n");
    
    // Summary
    fprintf(fp, "        <div class=\"summary\">\n");
    fprintf(fp, "            <h2>Scan Summary</h2>\n");
    fprintf(fp, "            <table>\n");
    fprintf(fp, "                <tr><td><strong>Scan Target:</strong></td><td>%s</td></tr>\n", report->scan_target);
    fprintf(fp, "                <tr><td><strong>Scan Date:</strong></td><td>%s</td></tr>\n", report->scan_date);
    fprintf(fp, "                <tr><td><strong>Duration:</strong></td><td>%.2f seconds</td></tr>\n", report->scan_duration);
    fprintf(fp, "                <tr><td><strong>Files Scanned:</strong></td><td>%d</td></tr>\n", report->total_files);
    fprintf(fp, "                <tr><td><strong>System:</strong></td><td>%s %s</td></tr>\n", 
            report->system_name, report->system_version);
    fprintf(fp, "                <tr><td><strong>Harkonnen Version:</strong></td><td>%s</td></tr>\n", report->harkonnen_version);
    fprintf(fp, "                <tr><td><strong>Scan Options:</strong></td><td>%s</td></tr>\n", 
            report->scan_options[0] ? report->scan_options : "Standard scan");
    fprintf(fp, "            </table>\n");
    
    // Results chart
    int clean_pct = report->total_files > 0 ? (report->clean_files * 100 / report->total_files) : 0;
    int suspicious_pct = report->total_files > 0 ? (report->suspicious_files * 100 / report->total_files) : 0;
    int malicious_pct = report->total_files > 0 ? (report->malicious_files * 100 / report->total_files) : 0;
    
    fprintf(fp, "            <h3>Results Overview</h3>\n");
    fprintf(fp, "            <div class=\"chart\">\n");
    if (clean_pct > 0)
        fprintf(fp, "                <div class=\"chart-bar chart-clean\" style=\"width: %d%%\" title=\"%d%% Clean\"></div>\n", 
                clean_pct, clean_pct);
    if (suspicious_pct > 0)
        fprintf(fp, "                <div class=\"chart-bar chart-suspicious\" style=\"width: %d%%\" title=\"%d%% Suspicious\"></div>\n", 
                suspicious_pct, suspicious_pct);
    if (malicious_pct > 0)
        fprintf(fp, "                <div class=\"chart-bar chart-malicious\" style=\"width: %d%%\" title=\"%d%% Malicious\"></div>\n", 
                malicious_pct, malicious_pct);
    fprintf(fp, "            </div>\n");
    
    fprintf(fp, "            <table>\n");
    fprintf(fp, "                <tr><td><strong>Clean Files:</strong></td><td class=\"clean\">%d</td></tr>\n", report->clean_files);
    fprintf(fp, "                <tr><td><strong>Suspicious Files:</strong></td><td class=\"suspicious\">%d</td></tr>\n", 
            report->suspicious_files);
    fprintf(fp, "                <tr><td><strong>Malicious Files:</strong></td><td class=\"malicious\">%d</td></tr>\n", 
            report->malicious_files);
    fprintf(fp, "            </table>\n");
    fprintf(fp, "        </div>\n");
    
    // Details
    fprintf(fp, "        <div class=\"details\">\n");
    fprintf(fp, "            <h2>Detection Details</h2>\n");
    
    if (report->detection_count == 0) {
        fprintf(fp, "            <p>No threats detected.</p>\n");
    } else {
        fprintf(fp, "            <table>\n");
        fprintf(fp, "                <thead>\n");
        fprintf(fp, "                    <tr>\n");
        fprintf(fp, "                        <th>File</th>\n");
        fprintf(fp, "                        <th>Status</th>\n");
        fprintf(fp, "                        <th>Threat Name</th>\n");
        fprintf(fp, "                        <th>Entropy</th>\n");
        fprintf(fp, "                        <th>Description</th>\n");
        fprintf(fp, "                    </tr>\n");
        fprintf(fp, "                </thead>\n");
        fprintf(fp, "                <tbody>\n");
        
        for (int i = 0; i < report->detection_count; i++) {
            if (report->detections[i].threat_level > 0) {  // Only show suspicious and malicious
                const char *status_class = report->detections[i].threat_level == 1 ? "suspicious" : "malicious";
                const char *status_text = report->detections[i].threat_level == 1 ? "Suspicious" : "Malicious";
                
                fprintf(fp, "                    <tr>\n");
                fprintf(fp, "                        <td>%s</td>\n", report->detections[i].filepath);
                fprintf(fp, "                        <td class=\"%s\">%s</td>\n", status_class, status_text);
                fprintf(fp, "                        <td>%s</td>\n", report->detections[i].threat_name);
                fprintf(fp, "                        <td>%.2f</td>\n", report->detections[i].entropy);
                fprintf(fp, "                        <td>%s</td>\n", report->detections[i].threat_description);
                fprintf(fp, "                    </tr>\n");
            }
        }
        
        fprintf(fp, "                </tbody>\n");
        fprintf(fp, "            </table>\n");
    }
    
    fprintf(fp, "        </div>\n");
    
    // Footer
    fprintf(fp, "        <div class=\"footer\">\n");
    fprintf(fp, "            <p>Generated by Harkonnen Antivirus %s</p>\n", report->harkonnen_version);
    fprintf(fp, "        </div>\n");
    
    fprintf(fp, "    </div>\n");
    fprintf(fp, "</body>\n");
    fprintf(fp, "</html>\n");
    
    fclose(fp);
    
    // Return the path to the report file
    char *report_path = strdup(report_file);
    return report_path;
}

// Generate text report
char *generate_text_report(ScanReport *report) {
    if (!report) {
        return NULL;
    }
    
    // Create reports directory if it doesn't exist
    struct stat st = {0};
    if (stat(REPORT_DIR, &st) == -1) {
        #ifdef _WIN32
        mkdir(REPORT_DIR);
        #else
        mkdir(REPORT_DIR, 0755);
        #endif
    }
    
    // Generate report filename
    char report_file[MAX_PATH_LENGTH];
    char timestamp[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    
    snprintf(report_file, sizeof(report_file), "%s/harkonnen_report_%s.txt", REPORT_DIR, timestamp);
    
    FILE *fp = fopen(report_file, "w");
    if (!fp) {
        fprintf(stderr, "[ERROR] Failed to create report file: %s\n", report_file);
        return NULL;
    }
    
    // Write header
    fprintf(fp, "========================================================\n");
    fprintf(fp, "==           HARKONNEN ANTIVIRUS SCAN REPORT          ==\n");
    fprintf(fp, "========================================================\n\n");
    
    // Write summary
    fprintf(fp, "SCAN SUMMARY\n");
    fprintf(fp, "----------------------------------------\n");
    fprintf(fp, "Scan Target: %s\n", report->scan_target);
    fprintf(fp, "Scan Date: %s\n", report->scan_date);
    fprintf(fp, "Duration: %.2f seconds\n", report->scan_duration);
    fprintf(fp, "Files Scanned: %d\n", report->total_files);
    fprintf(fp, "System: %s %s\n", report->system_name, report->system_version);
    fprintf(fp, "Harkonnen Version: %s\n", report->harkonnen_version);
    fprintf(fp, "Scan Options: %s\n", report->scan_options[0] ? report->scan_options : "Standard scan");
    fprintf(fp, "\n");
    
    // Write results overview
    fprintf(fp, "RESULTS OVERVIEW\n");
    fprintf(fp, "----------------------------------------\n");
    fprintf(fp, "Clean Files: %d\n", report->clean_files);
    fprintf(fp, "Suspicious Files: %d\n", report->suspicious_files);
    fprintf(fp, "Malicious Files: %d\n", report->malicious_files);
    fprintf(fp, "\n");
    
    // Write detection details
    fprintf(fp, "DETECTION DETAILS\n");
    fprintf(fp, "----------------------------------------\n");
    
    if (report->detection_count == 0) {
        fprintf(fp, "No threats detected.\n");
    } else {
        for (int i = 0; i < report->detection_count; i++) {
            if (report->detections[i].threat_level > 0) {  // Only show suspicious and malicious
                const char *status_text = report->detections[i].threat_level == 1 ? "SUSPICIOUS" : "MALICIOUS";
                
                fprintf(fp, "File: %s\n", report->detections[i].filepath);
                fprintf(fp, "Status: %s\n", status_text);
                fprintf(fp, "Threat Name: %s\n", report->detections[i].threat_name);
                fprintf(fp, "Entropy: %.2f\n", report->detections[i].entropy);
                fprintf(fp, "Description: %s\n", report->detections[i].threat_description);
                fprintf(fp, "----------------------------------------\n");
            }
        }
    }
    
    // Footer
    fprintf(fp, "\nGenerated by Harkonnen Antivirus %s\n", report->harkonnen_version);
    
    fclose(fp);
    
    // Return the path to the report file
    char *report_path = strdup(report_file);
    return report_path;
}

// Free scan report
void free_scan_report(ScanReport *report) {
    if (report) {
        free(report);
    }
}

// Open the report in the default browser (platform-specific)
void open_report_in_browser(const char *report_path) {
    if (!report_path) {
        return;
    }
    
    #ifdef _WIN32
    // Windows
    char command[MAX_PATH_LENGTH + 10];
    snprintf(command, sizeof(command), "start %s", report_path);
    system(command);
    #elif defined(__APPLE__)
    // macOS
    char command[MAX_PATH_LENGTH + 10];
    snprintf(command, sizeof(command), "open %s", report_path);
    system(command);
    #elif defined(__linux__)
    // Linux
    char command[MAX_PATH_LENGTH + 30];
    snprintf(command, sizeof(command), "xdg-open %s >/dev/null 2>&1 &", report_path);
    system(command);
    #endif
}

#endif /* REPORT_GENERATOR_H */