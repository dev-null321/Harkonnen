/*
 * elf_parser.h - ELF binary format parser for Harkonnen Antivirus
 *
 * Parses ELF headers, section headers, program headers.
 * Detects suspicious indicators: anti-debugging, packers (UPX),
 * suspicious sections, high-entropy sections, static linking.
 *
 * Created for Harkonnen Antivirus 2.5.0
 */

#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

/* ================================================================
 * ELF constants and structures (portable, no system headers needed)
 * ================================================================ */

// ELF magic
#define ELF_MAGIC_0  0x7F
#define ELF_MAGIC_1  'E'
#define ELF_MAGIC_2  'L'
#define ELF_MAGIC_3  'F'

// ELF class
#define ELF_CLASS_NONE 0
#define ELF_CLASS_32   1
#define ELF_CLASS_64   2

// ELF data encoding
#define ELF_DATA_NONE  0
#define ELF_DATA_LSB   1  // Little-endian
#define ELF_DATA_MSB   2  // Big-endian

// ELF type
#define ELF_ET_NONE  0
#define ELF_ET_REL   1
#define ELF_ET_EXEC  2
#define ELF_ET_DYN   3
#define ELF_ET_CORE  4

// ELF machine
#define ELF_EM_386    3
#define ELF_EM_ARM    40
#define ELF_EM_X86_64 62
#define ELF_EM_AARCH64 183
#define ELF_EM_MIPS   8
#define ELF_EM_PPC    20
#define ELF_EM_PPC64  21
#define ELF_EM_RISCV  243

// Section header types
#define ELF_SHT_NULL     0
#define ELF_SHT_PROGBITS 1
#define ELF_SHT_SYMTAB   2
#define ELF_SHT_STRTAB   3
#define ELF_SHT_DYNAMIC  6
#define ELF_SHT_NOTE     7
#define ELF_SHT_NOBITS   8
#define ELF_SHT_DYNSYM   11

// Section header flags
#define ELF_SHF_WRITE      0x1
#define ELF_SHF_ALLOC      0x2
#define ELF_SHF_EXECINSTR  0x4

// Program header types
#define ELF_PT_NULL    0
#define ELF_PT_LOAD    1
#define ELF_PT_DYNAMIC 2
#define ELF_PT_INTERP  3
#define ELF_PT_NOTE    4
#define ELF_PT_PHDR    6
#define ELF_PT_GNU_STACK 0x6474E551
#define ELF_PT_GNU_RELRO 0x6474E552

// Program header flags
#define ELF_PF_X 0x1
#define ELF_PF_W 0x2
#define ELF_PF_R 0x4

// Dynamic tags
#define ELF_DT_NULL    0
#define ELF_DT_NEEDED  1
#define ELF_DT_SONAME  14

/* ================================================================
 * Structures
 * ================================================================ */

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf32Header;

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64Header;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
} Elf32SectionHeader;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64SectionHeader;

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} Elf32ProgramHeader;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64ProgramHeader;

// Analysis result
typedef struct {
    bool     is_valid;
    bool     is_64bit;
    uint8_t  data_encoding;  // LSB or MSB
    uint16_t type;
    uint16_t machine;
    uint64_t entry_point;
    
    // Security indicators
    bool     has_interp;          // Has dynamic linker (dynamically linked)
    bool     is_statically_linked;
    bool     has_executable_stack;
    bool     has_relro;
    int      rwx_segment_count;   // Segments that are RWX (very suspicious)
    
    // Suspicious patterns
    bool     has_upx;
    bool     has_anti_debug;
    int      suspicious_section_count;
    int      high_entropy_section_count;
    double   max_section_entropy;
    
    // Summary
    int      threat_score;  // 0-100
} ElfAnalysis;

/* ================================================================
 * Helper functions
 * ================================================================ */

static const char *elf_type_name(uint16_t type) {
    switch (type) {
        case ELF_ET_NONE: return "None";
        case ELF_ET_REL:  return "Relocatable";
        case ELF_ET_EXEC: return "Executable";
        case ELF_ET_DYN:  return "Shared Object/PIE";
        case ELF_ET_CORE: return "Core Dump";
        default:          return "Unknown";
    }
}

static const char *elf_machine_name(uint16_t machine) {
    switch (machine) {
        case ELF_EM_386:     return "x86";
        case ELF_EM_X86_64:  return "x86_64";
        case ELF_EM_ARM:     return "ARM";
        case ELF_EM_AARCH64: return "AArch64";
        case ELF_EM_MIPS:    return "MIPS";
        case ELF_EM_PPC:     return "PowerPC";
        case ELF_EM_PPC64:   return "PowerPC64";
        case ELF_EM_RISCV:   return "RISC-V";
        default:             return "Unknown";
    }
}

static double elf_calc_section_entropy(FILE *fp, uint64_t offset, uint64_t size) {
    if (size == 0 || size > 100 * 1024 * 1024) return 0.0;
    
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

// Get section name from string table
static const char *elf_get_section_name(FILE *fp, uint64_t strtab_offset, uint32_t name_index) {
    static char name_buf[256];
    name_buf[0] = '\0';
    
    if (strtab_offset == 0) return "(no strtab)";
    
    long saved = ftell(fp);
    fseek(fp, (long)(strtab_offset + name_index), SEEK_SET);
    
    size_t got = fread(name_buf, 1, sizeof(name_buf) - 1, fp);
    name_buf[got] = '\0';
    
    // Truncate at first null (it's a C string in the strtab)
    // Already null-terminated by design of strtab
    
    fseek(fp, saved, SEEK_SET);
    return name_buf;
}

// Check for suspicious section names
static bool elf_is_suspicious_section(const char *name) {
    static const char *suspicious[] = {
        ".injected", ".payload", ".hook", ".packed",
        "UPX", ".evil", ".rootkit", ".backdoor",
        ".hidden", ".crypt", ".obfusc",
        NULL
    };
    for (int i = 0; suspicious[i]; i++) {
        if (strstr(name, suspicious[i])) return true;
    }
    return false;
}

// Check for anti-debugging patterns in a section's data
static bool elf_check_anti_debug(FILE *fp, uint64_t offset, uint64_t size) {
    if (size == 0 || size > 10 * 1024 * 1024) return false;
    
    long saved = ftell(fp);
    fseek(fp, (long)offset, SEEK_SET);
    
    // Read up to 64KB for pattern checking
    size_t check_size = size > 65536 ? 65536 : (size_t)size;
    char *data = (char *)malloc(check_size);
    if (!data) { fseek(fp, saved, SEEK_SET); return false; }
    
    size_t got = fread(data, 1, check_size, fp);
    fseek(fp, saved, SEEK_SET);
    
    bool found = false;
    
    // Check for ptrace anti-debug
    static const char *patterns[] = {
        "PTRACE_TRACEME",
        "ptrace",
        "prctl",
        "PR_SET_DUMPABLE",
        "/proc/self/status",
        "TracerPid",
        NULL
    };
    
    for (int i = 0; patterns[i] && !found; i++) {
        size_t plen = strlen(patterns[i]);
        for (size_t j = 0; j + plen <= got; j++) {
            if (memcmp(data + j, patterns[i], plen) == 0) {
                found = true;
                break;
            }
        }
    }
    
    free(data);
    return found;
}

// Check for UPX packer signature
static bool elf_check_upx(FILE *fp) {
    long saved = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    // Read first 8KB to check for UPX signatures
    char buf[8192];
    size_t got = fread(buf, 1, sizeof(buf), fp);
    fseek(fp, saved, SEEK_SET);
    
    // UPX signatures
    static const char *sigs[] = { "UPX!", "UPX0", "UPX1", "UPX2", NULL };
    for (int i = 0; sigs[i]; i++) {
        for (size_t j = 0; j + 4 <= got; j++) {
            if (memcmp(buf + j, sigs[i], 4) == 0) return true;
        }
    }
    
    return false;
}

/* ================================================================
 * Main parse/analysis function
 * ================================================================ */

static ElfAnalysis parse_elf_file(const char *file_path, FILE *output) {
    ElfAnalysis result = {0};
    
    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        fprintf(output, "\033[1;31m[ERROR]\033[0m Could not open file: %s\n", file_path);
        return result;
    }
    
    // Read and validate ELF magic
    uint8_t ident[16];
    if (fread(ident, 1, 16, fp) != 16) {
        fprintf(output, "\033[1;31m[ERROR]\033[0m Could not read ELF header\n");
        fclose(fp);
        return result;
    }
    
    if (ident[0] != ELF_MAGIC_0 || ident[1] != ELF_MAGIC_1 ||
        ident[2] != ELF_MAGIC_2 || ident[3] != ELF_MAGIC_3) {
        fprintf(output, "\033[1;31m[ERROR]\033[0m Not a valid ELF file\n");
        fclose(fp);
        return result;
    }
    
    result.is_valid = true;
    result.is_64bit = (ident[4] == ELF_CLASS_64);
    result.data_encoding = ident[5];
    
    // Note: for simplicity we assume native byte order matches file byte order.
    // A production parser would byte-swap based on ident[5].
    
    fseek(fp, 0, SEEK_SET);
    
    uint16_t e_type, e_machine;
    uint64_t e_entry, e_phoff, e_shoff;
    uint16_t e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
    
    if (result.is_64bit) {
        Elf64Header hdr;
        if (fread(&hdr, sizeof(hdr), 1, fp) != 1) {
            fclose(fp); return result;
        }
        e_type = hdr.e_type;
        e_machine = hdr.e_machine;
        e_entry = hdr.e_entry;
        e_phoff = hdr.e_phoff;
        e_shoff = hdr.e_shoff;
        e_phentsize = hdr.e_phentsize;
        e_phnum = hdr.e_phnum;
        e_shentsize = hdr.e_shentsize;
        e_shnum = hdr.e_shnum;
        e_shstrndx = hdr.e_shstrndx;
    } else {
        Elf32Header hdr;
        if (fread(&hdr, sizeof(hdr), 1, fp) != 1) {
            fclose(fp); return result;
        }
        e_type = hdr.e_type;
        e_machine = hdr.e_machine;
        e_entry = hdr.e_entry;
        e_phoff = hdr.e_phoff;
        e_shoff = hdr.e_shoff;
        e_phentsize = hdr.e_phentsize;
        e_phnum = hdr.e_phnum;
        e_shentsize = hdr.e_shentsize;
        e_shnum = hdr.e_shnum;
        e_shstrndx = hdr.e_shstrndx;
    }
    
    result.type = e_type;
    result.machine = e_machine;
    result.entry_point = e_entry;
    
    // Print header info
    fprintf(output, "\n\033[1;36m=== ELF File Analysis ===\033[0m\n");
    fprintf(output, "  Format:      %s ELF (%s endian)\n",
            result.is_64bit ? "64-bit" : "32-bit",
            result.data_encoding == ELF_DATA_LSB ? "little" : "big");
    fprintf(output, "  Type:        %s (%u)\n", elf_type_name(e_type), e_type);
    fprintf(output, "  Machine:     %s (%u)\n", elf_machine_name(e_machine), e_machine);
    fprintf(output, "  Entry Point: 0x%llX\n", (unsigned long long)e_entry);
    fprintf(output, "  Sections:    %u\n", e_shnum);
    fprintf(output, "  Segments:    %u\n", e_phnum);
    
    // Check for UPX packer
    result.has_upx = elf_check_upx(fp);
    if (result.has_upx) {
        fprintf(output, "\n  \033[1;31m[PACKER]\033[0m UPX packer detected!\n");
        result.threat_score += 25;
    }
    
    // ---- Parse Program Headers ----
    fprintf(output, "\n  --- Program Headers ---\n");
    
    result.has_interp = false;
    result.has_executable_stack = false;
    result.has_relro = false;
    
    if (e_phnum > 0 && e_phoff > 0 && e_phnum < 1000) {
        for (uint16_t i = 0; i < e_phnum; i++) {
            fseek(fp, (long)(e_phoff + i * e_phentsize), SEEK_SET);
            
            uint32_t p_type, p_flags;
            uint64_t p_offset, p_filesz, p_memsz;
            
            if (result.is_64bit) {
                Elf64ProgramHeader phdr;
                if (fread(&phdr, sizeof(phdr), 1, fp) != 1) break;
                p_type = phdr.p_type;
                p_flags = phdr.p_flags;
                p_offset = phdr.p_offset;
                p_filesz = phdr.p_filesz;
                p_memsz = phdr.p_memsz;
            } else {
                Elf32ProgramHeader phdr;
                if (fread(&phdr, sizeof(phdr), 1, fp) != 1) break;
                p_type = phdr.p_type;
                p_flags = phdr.p_flags;
                p_offset = phdr.p_offset;
                p_filesz = phdr.p_filesz;
                p_memsz = phdr.p_memsz;
            }
            
            const char *type_str = "OTHER";
            switch (p_type) {
                case ELF_PT_NULL:      type_str = "NULL"; break;
                case ELF_PT_LOAD:      type_str = "LOAD"; break;
                case ELF_PT_DYNAMIC:   type_str = "DYNAMIC"; break;
                case ELF_PT_INTERP:    type_str = "INTERP"; result.has_interp = true; break;
                case ELF_PT_NOTE:      type_str = "NOTE"; break;
                case ELF_PT_PHDR:      type_str = "PHDR"; break;
                case ELF_PT_GNU_STACK: type_str = "GNU_STACK"; break;
                case ELF_PT_GNU_RELRO: type_str = "GNU_RELRO"; result.has_relro = true; break;
            }
            
            char flags_str[4] = "---";
            if (p_flags & ELF_PF_R) flags_str[0] = 'R';
            if (p_flags & ELF_PF_W) flags_str[1] = 'W';
            if (p_flags & ELF_PF_X) flags_str[2] = 'X';
            
            fprintf(output, "  %-12s %s  offset=0x%llX filesz=%llu memsz=%llu",
                    type_str, flags_str,
                    (unsigned long long)p_offset,
                    (unsigned long long)p_filesz,
                    (unsigned long long)p_memsz);
            
            // Check for GNU_STACK with execute permission
            if (p_type == ELF_PT_GNU_STACK && (p_flags & ELF_PF_X)) {
                fprintf(output, " \033[1;31m[EXEC STACK]\033[0m");
                result.has_executable_stack = true;
                result.threat_score += 20;
            }
            
            // Check for RWX segments (very suspicious)
            if (p_type == ELF_PT_LOAD &&
                (p_flags & ELF_PF_R) && (p_flags & ELF_PF_W) && (p_flags & ELF_PF_X)) {
                fprintf(output, " \033[1;31m[RWX SEGMENT]\033[0m");
                result.rwx_segment_count++;
                result.threat_score += 25;
            }
            
            fprintf(output, "\n");
        }
    }
    
    // Check if statically linked
    result.is_statically_linked = !result.has_interp;
    if (result.is_statically_linked && (e_type == ELF_ET_EXEC || e_type == ELF_ET_DYN)) {
        fprintf(output, "\n  \033[1;33m[WARNING]\033[0m Statically linked binary - imports are hidden\n");
        result.threat_score += 10;
    }
    
    // ---- Parse Section Headers ----
    fprintf(output, "\n  --- Section Headers ---\n");
    
    // First get the string table for section names
    uint64_t strtab_offset = 0;
    if (e_shstrndx < e_shnum && e_shoff > 0 && e_shnum < 10000) {
        fseek(fp, (long)(e_shoff + e_shstrndx * e_shentsize), SEEK_SET);
        if (result.is_64bit) {
            Elf64SectionHeader shdr;
            if (fread(&shdr, sizeof(shdr), 1, fp) == 1) {
                strtab_offset = shdr.sh_offset;
            }
        } else {
            Elf32SectionHeader shdr;
            if (fread(&shdr, sizeof(shdr), 1, fp) == 1) {
                strtab_offset = shdr.sh_offset;
            }
        }
    }
    
    bool anti_debug_found = false;
    
    if (e_shnum > 0 && e_shoff > 0 && e_shnum < 10000) {
        for (uint16_t i = 0; i < e_shnum; i++) {
            fseek(fp, (long)(e_shoff + i * e_shentsize), SEEK_SET);
            
            uint32_t sh_name, sh_type;
            uint64_t sh_flags, sh_offset, sh_size;
            
            if (result.is_64bit) {
                Elf64SectionHeader shdr;
                if (fread(&shdr, sizeof(shdr), 1, fp) != 1) break;
                sh_name = shdr.sh_name;
                sh_type = shdr.sh_type;
                sh_flags = shdr.sh_flags;
                sh_offset = shdr.sh_offset;
                sh_size = shdr.sh_size;
            } else {
                Elf32SectionHeader shdr;
                if (fread(&shdr, sizeof(shdr), 1, fp) != 1) break;
                sh_name = shdr.sh_name;
                sh_type = shdr.sh_type;
                sh_flags = shdr.sh_flags;
                sh_offset = shdr.sh_offset;
                sh_size = shdr.sh_size;
            }
            
            const char *name = elf_get_section_name(fp, strtab_offset, sh_name);
            
            // Skip null sections
            if (sh_type == ELF_SHT_NULL) continue;
            
            // Build flags string
            char flags_str[4] = "---";
            if (sh_flags & ELF_SHF_ALLOC) flags_str[0] = 'A';
            if (sh_flags & ELF_SHF_WRITE) flags_str[1] = 'W';
            if (sh_flags & ELF_SHF_EXECINSTR) flags_str[2] = 'X';
            
            // Calculate entropy for PROGBITS sections
            double ent = 0.0;
            if (sh_type == ELF_SHT_PROGBITS && sh_size > 0 && sh_size < 50 * 1024 * 1024) {
                ent = elf_calc_section_entropy(fp, sh_offset, sh_size);
            }
            
            fprintf(output, "  [%2u] %-20s %s size=%llu",
                    i, name, flags_str, (unsigned long long)sh_size);
            
            if (sh_type == ELF_SHT_PROGBITS && ent > 0.0) {
                fprintf(output, " entropy=%.2f", ent);
                if (ent > 7.0) {
                    fprintf(output, " \033[1;33m[HIGH ENTROPY]\033[0m");
                    result.high_entropy_section_count++;
                    if (ent > result.max_section_entropy)
                        result.max_section_entropy = ent;
                }
            }
            
            // Check for suspicious section names
            if (elf_is_suspicious_section(name)) {
                fprintf(output, " \033[1;31m[SUSPICIOUS]\033[0m");
                result.suspicious_section_count++;
                result.threat_score += 15;
            }
            
            // Check .note.GNU-stack for execute permission
            if (strcmp(name, ".note.GNU-stack") == 0 && (sh_flags & ELF_SHF_EXECINSTR)) {
                fprintf(output, " \033[1;31m[EXEC NOTE STACK]\033[0m");
                result.threat_score += 15;
            }
            
            fprintf(output, "\n");
            
            // Check for anti-debugging patterns in text/rodata sections
            if (!anti_debug_found && sh_type == ELF_SHT_PROGBITS &&
                (strcmp(name, ".rodata") == 0 || strcmp(name, ".text") == 0 ||
                 strcmp(name, ".data") == 0)) {
                if (elf_check_anti_debug(fp, sh_offset, sh_size)) {
                    anti_debug_found = true;
                }
            }
        }
    }
    
    result.has_anti_debug = anti_debug_found;
    if (anti_debug_found) {
        fprintf(output, "\n  \033[1;31m[ANTI-DEBUG]\033[0m Anti-debugging references detected (ptrace/prctl patterns)\n");
        result.threat_score += 20;
    }
    
    // Security summary
    if (result.has_executable_stack) {
        fprintf(output, "  \033[1;33m[WARNING]\033[0m Executable stack enabled\n");
    }
    
    if (!result.has_relro && (e_type == ELF_ET_EXEC || e_type == ELF_ET_DYN)) {
        fprintf(output, "  \033[1;33m[WARNING]\033[0m No RELRO - GOT is writable\n");
        result.threat_score += 5;
    }
    
    if (result.rwx_segment_count > 0) {
        fprintf(output, "  \033[1;31m[WARNING]\033[0m %d RWX segment(s) detected - code injection possible\n",
                result.rwx_segment_count);
    }
    
    if (result.high_entropy_section_count > 0) {
        fprintf(output, "\n  \033[1;33m[WARNING]\033[0m %d section(s) with high entropy (max: %.2f) - possible packing/encryption\n",
                result.high_entropy_section_count, result.max_section_entropy);
        result.threat_score += result.high_entropy_section_count * 10;
    }
    
    // Summary
    fprintf(output, "\n  --- Analysis Summary ---\n");
    fprintf(output, "  Statically linked:     %s\n", result.is_statically_linked ? "Yes" : "No");
    fprintf(output, "  Executable stack:      %s\n", result.has_executable_stack ? "Yes" : "No");
    fprintf(output, "  RELRO:                 %s\n", result.has_relro ? "Yes" : "No");
    fprintf(output, "  RWX segments:          %d\n", result.rwx_segment_count);
    fprintf(output, "  UPX packed:            %s\n", result.has_upx ? "Yes" : "No");
    fprintf(output, "  Anti-debug:            %s\n", result.has_anti_debug ? "Yes" : "No");
    fprintf(output, "  Suspicious sections:   %d\n", result.suspicious_section_count);
    fprintf(output, "  High entropy sections: %d\n", result.high_entropy_section_count);
    
    // Cap threat score
    if (result.threat_score > 100) result.threat_score = 100;
    
    if (result.threat_score >= 50) {
        fprintf(output, "  Threat Score:          \033[1;31m%d/100 (HIGH)\033[0m\n", result.threat_score);
    } else if (result.threat_score >= 25) {
        fprintf(output, "  Threat Score:          \033[1;33m%d/100 (MEDIUM)\033[0m\n", result.threat_score);
    } else {
        fprintf(output, "  Threat Score:          \033[1;32m%d/100 (LOW)\033[0m\n", result.threat_score);
    }
    
    fclose(fp);
    return result;
}

/* Public API: check if file is ELF */
static bool is_elf_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) return false;
    
    uint8_t magic[4];
    bool result = false;
    if (fread(magic, 1, 4, fp) == 4) {
        result = (magic[0] == ELF_MAGIC_0 && magic[1] == ELF_MAGIC_1 &&
                  magic[2] == ELF_MAGIC_2 && magic[3] == ELF_MAGIC_3);
    }
    fclose(fp);
    return result;
}

/* Public API: parse and print ELF analysis */
static void parse_elf_to_stream(const char *file_path, FILE *output) {
    parse_elf_file(file_path, output);
}

#endif /* ELF_PARSER_H */
