/*
 * mach_o_parser.h - Mach-O binary format parser for Harkonnen Antivirus
 *
 * Parses Mach-O headers, load commands, segments, sections.
 * Detects suspicious indicators: packed/encrypted binaries, unsigned code,
 * suspicious dylib loads, high-entropy sections.
 *
 * Created for Harkonnen Antivirus 2.5.0
 */

#ifndef MACH_O_PARSER_H
#define MACH_O_PARSER_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

/* ================================================================
 * Mach-O constants and structures (portable, no system headers needed)
 * ================================================================ */

// Magic numbers
#define MACHO_MAGIC_32      0xFEEDFACE
#define MACHO_MAGIC_64      0xFEEDFACF
#define MACHO_CIGAM_32      0xCEFAEDFE  // byte-swapped
#define MACHO_CIGAM_64      0xCFFAEDFE  // byte-swapped
#define MACHO_FAT_MAGIC     0xCAFEBABE
#define MACHO_FAT_CIGAM     0xBEBAFECA

// CPU types
#define MACHO_CPU_TYPE_X86      7
#define MACHO_CPU_TYPE_X86_64   (7 | 0x01000000)
#define MACHO_CPU_TYPE_ARM      12
#define MACHO_CPU_TYPE_ARM64    (12 | 0x01000000)
#define MACHO_CPU_TYPE_POWERPC  18

// File types
#define MACHO_MH_OBJECT     1
#define MACHO_MH_EXECUTE    2
#define MACHO_MH_FVMLIB     3
#define MACHO_MH_CORE       4
#define MACHO_MH_PRELOAD    5
#define MACHO_MH_DYLIB      6
#define MACHO_MH_DYLINKER   7
#define MACHO_MH_BUNDLE     8
#define MACHO_MH_DSYM       10
#define MACHO_MH_KEXT_BUNDLE 11

// Load command types
#define MACHO_LC_SEGMENT            0x01
#define MACHO_LC_SEGMENT_64         0x19
#define MACHO_LC_LOAD_DYLIB         0x0C
#define MACHO_LC_LOAD_WEAK_DYLIB    0x18 | 0x80000000
#define MACHO_LC_ID_DYLIB           0x0D
#define MACHO_LC_CODE_SIGNATURE     0x1D
#define MACHO_LC_ENCRYPTION_INFO    0x21
#define MACHO_LC_ENCRYPTION_INFO_64 0x2C
#define MACHO_LC_RPATH              0x1C | 0x80000000
#define MACHO_LC_REEXPORT_DYLIB     0x1F | 0x80000000

// Flags
#define MACHO_MH_PIE            0x00200000
#define MACHO_MH_NO_HEAP_EXEC   0x01000000
#define MACHO_MH_ALLOW_STACK_EXEC 0x00020000

// Structures
typedef struct {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
} MachOHeader32;

typedef struct {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} MachOHeader64;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} MachOLoadCommand;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} MachOSegmentCommand32;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} MachOSegmentCommand64;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
} MachOSection32;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} MachOSection64;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
} MachOEncryptionInfo32;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
    uint32_t pad;
} MachOEncryptionInfo64;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    union {
        uint32_t offset;
    } name;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
} MachODylibCommand;

// Analysis result
typedef struct {
    bool     is_valid;
    bool     is_64bit;
    bool     is_fat;
    bool     is_swapped;
    uint32_t cputype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t flags;
    
    // Security indicators
    bool     has_code_signature;
    bool     has_encryption;
    bool     is_pie;
    bool     allows_stack_exec;
    bool     no_heap_exec;
    int      suspicious_dylib_count;
    int      suspicious_segment_count;
    int      high_entropy_section_count;
    double   max_section_entropy;
    
    // Summary
    int      threat_score;  // 0-100
} MachOAnalysis;

/* ================================================================
 * Helper functions
 * ================================================================ */

static uint32_t macho_swap32(uint32_t val) {
    return ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) |
           ((val >> 8) & 0xFF00) | ((val >> 24) & 0xFF);
}

static uint64_t macho_swap64(uint64_t val) {
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}

static const char *macho_cpu_name(uint32_t cputype) {
    switch (cputype) {
        case MACHO_CPU_TYPE_X86:     return "x86";
        case MACHO_CPU_TYPE_X86_64:  return "x86_64";
        case MACHO_CPU_TYPE_ARM:     return "ARM";
        case MACHO_CPU_TYPE_ARM64:   return "ARM64";
        case MACHO_CPU_TYPE_POWERPC: return "PowerPC";
        default:                     return "Unknown";
    }
}

static const char *macho_filetype_name(uint32_t filetype) {
    switch (filetype) {
        case MACHO_MH_OBJECT:      return "Object";
        case MACHO_MH_EXECUTE:     return "Executable";
        case MACHO_MH_DYLIB:       return "Dynamic Library";
        case MACHO_MH_DYLINKER:    return "Dynamic Linker";
        case MACHO_MH_BUNDLE:      return "Bundle";
        case MACHO_MH_CORE:        return "Core Dump";
        case MACHO_MH_DSYM:        return "dSYM";
        case MACHO_MH_KEXT_BUNDLE: return "Kernel Extension";
        default:                   return "Unknown";
    }
}

static double macho_calc_section_entropy(FILE *fp, uint64_t offset, uint64_t size) {
    if (size == 0 || size > 100 * 1024 * 1024) return 0.0;  // Skip empty or very large
    
    long saved_pos = ftell(fp);
    fseek(fp, (long)offset, SEEK_SET);
    
    unsigned long long counts[256] = {0};
    unsigned long long total = 0;
    unsigned char buf[8192];
    uint64_t remaining = size;
    
    while (remaining > 0) {
        size_t to_read = remaining > sizeof(buf) ? sizeof(buf) : (size_t)remaining;
        size_t got = fread(buf, 1, to_read, fp);
        if (got == 0) break;
        for (size_t i = 0; i < got; i++) {
            counts[buf[i]]++;
        }
        total += got;
        remaining -= got;
    }
    
    fseek(fp, saved_pos, SEEK_SET);
    
    if (total == 0) return 0.0;
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / (double)total;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// Known suspicious dylibs
static bool macho_is_suspicious_dylib(const char *name) {
    static const char *suspicious[] = {
        "libinject", "libhook", "libsubstrate", "libcycript",
        "MobileSubstrate", "SubstrateLoader", "frida",
        "libSystem.B.dylib.patched", "libssl.0.9.8.dylib",
        NULL
    };
    for (int i = 0; suspicious[i]; i++) {
        if (strstr(name, suspicious[i])) return true;
    }
    return false;
}

// Known suspicious segment names
static bool macho_is_suspicious_segment(const char *name) {
    static const char *suspicious[] = {
        "__IMPORT", "__INJECT", "__HOOK", "__PAYLOAD",
        "__ENCRYPT", "UPX", "__PACKED",
        NULL
    };
    for (int i = 0; suspicious[i]; i++) {
        if (strstr(name, suspicious[i])) return true;
    }
    return false;
}

/* ================================================================
 * Main parse/analysis function
 * ================================================================ */

static MachOAnalysis parse_macho_file(const char *file_path, FILE *output) {
    MachOAnalysis result = {0};
    
    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        fprintf(output, "\033[1;31m[ERROR]\033[0m Could not open file: %s\n", file_path);
        return result;
    }
    
    // Read magic number
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, fp) != 1) {
        fprintf(output, "\033[1;31m[ERROR]\033[0m Could not read Mach-O header\n");
        fclose(fp);
        return result;
    }
    
    // Determine format
    bool swapped = false;
    bool is64 = false;
    
    switch (magic) {
        case MACHO_MAGIC_64:
            is64 = true;
            break;
        case MACHO_MAGIC_32:
            break;
        case MACHO_CIGAM_64:
            is64 = true;
            swapped = true;
            break;
        case MACHO_CIGAM_32:
            swapped = true;
            break;
        case MACHO_FAT_MAGIC:
        case MACHO_FAT_CIGAM:
            fprintf(output, "[INFO] Fat/Universal binary detected. Analyzing first slice.\n");
            result.is_fat = true;
            // Skip fat header and parse first arch
            // For simplicity, skip 8 bytes (fat header) + read offset of first arch
            {
                uint32_t nfat;
                if (fread(&nfat, 4, 1, fp) != 1) { fclose(fp); return result; }
                if (magic == MACHO_FAT_CIGAM) nfat = macho_swap32(nfat);
                
                if (nfat > 0) {
                    uint32_t arch_data[5]; // cputype, cpusub, offset, size, align
                    if (fread(arch_data, sizeof(arch_data), 1, fp) != 1) { fclose(fp); return result; }
                    uint32_t offset = arch_data[2];
                    if (magic == MACHO_FAT_CIGAM) offset = macho_swap32(offset);
                    fseek(fp, (long)offset, SEEK_SET);
                    if (fread(&magic, sizeof(magic), 1, fp) != 1) { fclose(fp); return result; }
                    
                    if (magic == MACHO_MAGIC_64 || magic == MACHO_CIGAM_64) is64 = true;
                    if (magic == MACHO_CIGAM_32 || magic == MACHO_CIGAM_64) swapped = true;
                }
            }
            break;
        default:
            fprintf(output, "\033[1;31m[ERROR]\033[0m Not a valid Mach-O file (magic: 0x%08X)\n", magic);
            fclose(fp);
            return result;
    }
    
    result.is_valid = true;
    result.is_64bit = is64;
    result.is_swapped = swapped;
    
    // Read the rest of the header
    uint32_t cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags;
    
    if (fread(&cputype, 4, 1, fp) != 1 ||
        fread(&cpusubtype, 4, 1, fp) != 1 ||
        fread(&filetype, 4, 1, fp) != 1 ||
        fread(&ncmds, 4, 1, fp) != 1 ||
        fread(&sizeofcmds, 4, 1, fp) != 1 ||
        fread(&flags, 4, 1, fp) != 1) {
        fprintf(output, "\033[1;31m[ERROR]\033[0m Truncated Mach-O header\n");
        fclose(fp);
        return result;
    }
    
    if (is64) {
        uint32_t reserved;
        if (fread(&reserved, 4, 1, fp) != 1) {
            /* ignore - may be truncated */
        }
    }
    
    if (swapped) {
        cputype = macho_swap32(cputype);
        cpusubtype = macho_swap32(cpusubtype);
        filetype = macho_swap32(filetype);
        ncmds = macho_swap32(ncmds);
        sizeofcmds = macho_swap32(sizeofcmds);
        flags = macho_swap32(flags);
    }
    
    result.cputype = cputype;
    result.filetype = filetype;
    result.ncmds = ncmds;
    result.flags = flags;
    
    // Print header info
    fprintf(output, "\n\033[1;36m=== Mach-O File Analysis ===\033[0m\n");
    fprintf(output, "  Format:    %s Mach-O\n", is64 ? "64-bit" : "32-bit");
    fprintf(output, "  CPU:       %s (0x%X)\n", macho_cpu_name(cputype), cputype);
    fprintf(output, "  File Type: %s (%u)\n", macho_filetype_name(filetype), filetype);
    fprintf(output, "  Commands:  %u (total size: %u bytes)\n", ncmds, sizeofcmds);
    fprintf(output, "  Flags:     0x%08X", flags);
    
    // Analyze flags
    result.is_pie = (flags & MACHO_MH_PIE) != 0;
    result.allows_stack_exec = (flags & MACHO_MH_ALLOW_STACK_EXEC) != 0;
    result.no_heap_exec = (flags & MACHO_MH_NO_HEAP_EXEC) != 0;
    
    if (result.is_pie) fprintf(output, " [PIE]");
    if (result.allows_stack_exec) fprintf(output, " \033[1;33m[STACK_EXEC]\033[0m");
    if (result.no_heap_exec) fprintf(output, " [NO_HEAP_EXEC]");
    fprintf(output, "\n");
    
    // Security check: stack execution
    if (result.allows_stack_exec) {
        fprintf(output, "  \033[1;33m[WARNING]\033[0m Executable stack allowed - potential code injection vector\n");
        result.threat_score += 15;
    }
    
    // Security check: PIE
    if (!result.is_pie && filetype == MACHO_MH_EXECUTE) {
        fprintf(output, "  \033[1;33m[WARNING]\033[0m Not position-independent (no PIE) - ASLR ineffective\n");
        result.threat_score += 10;
    }
    
    // Parse load commands
    fprintf(output, "\n  --- Load Commands ---\n");
    
    long lc_start = ftell(fp);
    
    // Safety limit on ncmds
    if (ncmds > 1000) {
        fprintf(output, "  \033[1;31m[WARNING]\033[0m Excessive number of load commands (%u) - possible corruption\n", ncmds);
        ncmds = 1000;
        result.threat_score += 20;
    }
    
    for (uint32_t i = 0; i < ncmds; i++) {
        long cmd_pos = ftell(fp);
        MachOLoadCommand lc;
        if (fread(&lc, sizeof(lc), 1, fp) != 1) break;
        
        uint32_t cmd = swapped ? macho_swap32(lc.cmd) : lc.cmd;
        uint32_t cmdsize = swapped ? macho_swap32(lc.cmdsize) : lc.cmdsize;
        
        if (cmdsize < sizeof(MachOLoadCommand) || cmdsize > sizeofcmds) break;
        
        // Handle segments
        if (cmd == MACHO_LC_SEGMENT_64 || cmd == MACHO_LC_SEGMENT) {
            // Seek back to read full segment command
            fseek(fp, cmd_pos, SEEK_SET);
            
            char segname[17] = {0};
            uint64_t fileoff = 0, filesize = 0;
            uint32_t nsects = 0;
            
            if (cmd == MACHO_LC_SEGMENT_64) {
                MachOSegmentCommand64 seg;
                if (fread(&seg, sizeof(seg), 1, fp) != 1) break;
                memcpy(segname, seg.segname, 16);
                fileoff = swapped ? macho_swap64(seg.fileoff) : seg.fileoff;
                filesize = swapped ? macho_swap64(seg.filesize) : seg.filesize;
                nsects = swapped ? macho_swap32(seg.nsects) : seg.nsects;
            } else {
                MachOSegmentCommand32 seg;
                if (fread(&seg, sizeof(seg), 1, fp) != 1) break;
                memcpy(segname, seg.segname, 16);
                fileoff = swapped ? macho_swap32(seg.fileoff) : seg.fileoff;
                filesize = swapped ? macho_swap32(seg.filesize) : seg.filesize;
                nsects = swapped ? macho_swap32(seg.nsects) : seg.nsects;
            }
            
            fprintf(output, "  Segment: %-16s (offset: 0x%llX, size: %llu, sections: %u)\n",
                    segname, (unsigned long long)fileoff, (unsigned long long)filesize, nsects);
            
            // Check for suspicious segment names
            if (macho_is_suspicious_segment(segname)) {
                fprintf(output, "    \033[1;31m[SUSPICIOUS]\033[0m Unusual segment name: %s\n", segname);
                result.suspicious_segment_count++;
                result.threat_score += 20;
            }
            
            // Parse sections within segment
            if (nsects > 256) nsects = 256; // safety
            for (uint32_t s = 0; s < nsects; s++) {
                char sect_name[17] = {0};
                char sect_seg[17] = {0};
                uint64_t sect_offset = 0, sect_size = 0;
                
                if (is64) {
                    MachOSection64 sect;
                    if (fread(&sect, sizeof(sect), 1, fp) != 1) break;
                    memcpy(sect_name, sect.sectname, 16);
                    memcpy(sect_seg, sect.segname, 16);
                    sect_offset = swapped ? macho_swap32(sect.offset) : sect.offset;
                    sect_size = swapped ? macho_swap64(sect.size) : sect.size;
                } else {
                    MachOSection32 sect;
                    if (fread(&sect, sizeof(sect), 1, fp) != 1) break;
                    memcpy(sect_name, sect.sectname, 16);
                    memcpy(sect_seg, sect.segname, 16);
                    sect_offset = swapped ? macho_swap32(sect.offset) : sect.offset;
                    sect_size = swapped ? macho_swap32(sect.size) : sect.size;
                }
                
                // Calculate section entropy
                double ent = 0.0;
                if (sect_size > 0 && sect_size < 50 * 1024 * 1024) {
                    ent = macho_calc_section_entropy(fp, sect_offset, sect_size);
                }
                
                fprintf(output, "    Section: %s,%s (size: %llu, entropy: %.2f)",
                        sect_seg, sect_name, (unsigned long long)sect_size, ent);
                
                if (ent > 7.0) {
                    fprintf(output, " \033[1;33m[HIGH ENTROPY]\033[0m");
                    result.high_entropy_section_count++;
                    if (ent > result.max_section_entropy)
                        result.max_section_entropy = ent;
                }
                fprintf(output, "\n");
            }
            
        } else if (cmd == MACHO_LC_LOAD_DYLIB || cmd == MACHO_LC_ID_DYLIB ||
                   cmd == (uint32_t)(MACHO_LC_LOAD_WEAK_DYLIB) ||
                   cmd == (uint32_t)(MACHO_LC_REEXPORT_DYLIB)) {
            // Read dylib name
            fseek(fp, cmd_pos, SEEK_SET);
            MachODylibCommand dylib;
            if (fread(&dylib, sizeof(dylib), 1, fp) != 1) break;
            
            uint32_t name_offset = swapped ? macho_swap32(dylib.name.offset) : dylib.name.offset;
            if (name_offset < cmdsize) {
                char dylib_name[512] = {0};
                fseek(fp, cmd_pos + name_offset, SEEK_SET);
                size_t name_len = cmdsize - name_offset;
                if (name_len > sizeof(dylib_name) - 1) name_len = sizeof(dylib_name) - 1;
                if (fread(dylib_name, 1, name_len, fp) > 0) {
                    dylib_name[name_len] = '\0';
                    fprintf(output, "  Dylib: %s\n", dylib_name);
                    
                    if (macho_is_suspicious_dylib(dylib_name)) {
                        fprintf(output, "    \033[1;31m[SUSPICIOUS]\033[0m Suspicious dynamic library: %s\n", dylib_name);
                        result.suspicious_dylib_count++;
                        result.threat_score += 25;
                    }
                }
            }
            
        } else if (cmd == MACHO_LC_CODE_SIGNATURE) {
            fprintf(output, "  \033[1;32m[CODE SIGNATURE]\033[0m Code signature present\n");
            result.has_code_signature = true;
            
        } else if (cmd == MACHO_LC_ENCRYPTION_INFO || cmd == MACHO_LC_ENCRYPTION_INFO_64) {
            fseek(fp, cmd_pos, SEEK_SET);
            uint32_t enc_data[6]; // enough for both 32 and 64
            size_t enc_size = (cmd == MACHO_LC_ENCRYPTION_INFO_64) ? sizeof(MachOEncryptionInfo64) : sizeof(MachOEncryptionInfo32);
            if (fread(enc_data, 1, enc_size, fp) == enc_size) {
                uint32_t cryptid = swapped ? macho_swap32(enc_data[4]) : enc_data[4];
                if (cryptid != 0) {
                    fprintf(output, "  \033[1;31m[ENCRYPTED]\033[0m Binary is encrypted (cryptid=%u)\n", cryptid);
                    result.has_encryption = true;
                    result.threat_score += 15;
                } else {
                    fprintf(output, "  [ENCRYPTION] Encryption info present but not active (decrypted)\n");
                }
            }
        }
        
        // Move to next load command
        fseek(fp, cmd_pos + cmdsize, SEEK_SET);
    }
    
    (void)lc_start;
    
    // No code signature on executable is suspicious
    if (!result.has_code_signature && filetype == MACHO_MH_EXECUTE) {
        fprintf(output, "\n  \033[1;33m[WARNING]\033[0m No code signature found - binary is unsigned\n");
        result.threat_score += 15;
    }
    
    // High entropy sections suggest packing
    if (result.high_entropy_section_count > 0) {
        fprintf(output, "\n  \033[1;33m[WARNING]\033[0m %d section(s) with high entropy (max: %.2f) - possible packing/encryption\n",
                result.high_entropy_section_count, result.max_section_entropy);
        result.threat_score += result.high_entropy_section_count * 10;
    }
    
    // Summary
    fprintf(output, "\n  --- Analysis Summary ---\n");
    fprintf(output, "  Suspicious segments:  %d\n", result.suspicious_segment_count);
    fprintf(output, "  Suspicious dylibs:    %d\n", result.suspicious_dylib_count);
    fprintf(output, "  High entropy sections: %d\n", result.high_entropy_section_count);
    fprintf(output, "  Code signed:          %s\n", result.has_code_signature ? "Yes" : "No");
    fprintf(output, "  Encrypted:            %s\n", result.has_encryption ? "Yes" : "No");
    fprintf(output, "  PIE:                  %s\n", result.is_pie ? "Yes" : "No");
    
    // Cap threat score
    if (result.threat_score > 100) result.threat_score = 100;
    
    if (result.threat_score >= 50) {
        fprintf(output, "  Threat Score:         \033[1;31m%d/100 (HIGH)\033[0m\n", result.threat_score);
    } else if (result.threat_score >= 25) {
        fprintf(output, "  Threat Score:         \033[1;33m%d/100 (MEDIUM)\033[0m\n", result.threat_score);
    } else {
        fprintf(output, "  Threat Score:         \033[1;32m%d/100 (LOW)\033[0m\n", result.threat_score);
    }
    
    fclose(fp);
    return result;
}

/* Public API: check if file is Mach-O */
static bool is_macho_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return false;
    
    uint32_t magic;
    bool result = false;
    if (fread(&magic, sizeof(magic), 1, fp) == 1) {
        result = (magic == MACHO_MAGIC_32 || magic == MACHO_MAGIC_64 ||
                  magic == MACHO_CIGAM_32 || magic == MACHO_CIGAM_64 ||
                  magic == MACHO_FAT_MAGIC || magic == MACHO_FAT_CIGAM);
    }
    fclose(fp);
    return result;
}

/* Public API: parse and print Mach-O analysis */
static void parse_macho_to_stream(const char *file_path, FILE *output) {
    parse_macho_file(file_path, output);
}

#endif /* MACH_O_PARSER_H */
