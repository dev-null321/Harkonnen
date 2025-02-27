#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifndef PE_PARSER_H
#define PE_PARSER_H
void parse_pe_file(const char *file_path);
#endif // PE_PARSER_H



// Define constants
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL

// Define structures
typedef struct _IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS32 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    uint8_t Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;
    };
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

uint32_t rva_to_file_offset(FILE* file, uint32_t rva, void* nt_headers, int is_32bit) {
    IMAGE_SECTION_HEADER section;
    uint32_t section_count;
    long original_position = ftell(file);

    if (is_32bit) {
        IMAGE_NT_HEADERS32* nt_headers32 = (IMAGE_NT_HEADERS32*)nt_headers;
        section_count = nt_headers32->FileHeader.NumberOfSections;
        fseek(file, original_position + sizeof(IMAGE_NT_HEADERS32), SEEK_SET);
    } else {
        IMAGE_NT_HEADERS64* nt_headers64 = (IMAGE_NT_HEADERS64*)nt_headers;
        section_count = nt_headers64->FileHeader.NumberOfSections;
        fseek(file, original_position + sizeof(IMAGE_NT_HEADERS64), SEEK_SET);
    }

    for (uint32_t i = 0; i < section_count; i++) {
        fread(&section, sizeof(IMAGE_SECTION_HEADER), 1, file);
        if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.Misc.VirtualSize) {
            fseek(file, original_position, SEEK_SET);
            return rva - section.VirtualAddress + section.PointerToRawData;
        }
    }

    fseek(file, original_position, SEEK_SET);
    return 0;
}

void parse_imports(FILE* file, void* nt_headers, int is_32bit) {
    IMAGE_DATA_DIRECTORY import_directory;
    uint32_t import_table_offset;

    if (is_32bit) {
        IMAGE_NT_HEADERS32* nt_headers32 = (IMAGE_NT_HEADERS32*)nt_headers;
        import_directory = nt_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    } else {
        IMAGE_NT_HEADERS64* nt_headers64 = (IMAGE_NT_HEADERS64*)nt_headers;
        import_directory = nt_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }

    import_table_offset = rva_to_file_offset(file, import_directory.VirtualAddress, nt_headers, is_32bit);
    
    if (import_table_offset == 0) {
        printf("Failed to find import table\n");
        return;
    }

    fseek(file, import_table_offset, SEEK_SET);
    IMAGE_IMPORT_DESCRIPTOR import_descriptor;

    while (1) {
        fread(&import_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, file);
        if (import_descriptor.Name == 0) break;

        uint32_t name_offset = rva_to_file_offset(file, import_descriptor.Name, nt_headers, is_32bit);
        if (name_offset == 0) {
            printf("Failed to find DLL name\n");
            continue;
        }

        fseek(file, name_offset, SEEK_SET);
        char dll_name[256];
        fread(dll_name, 1, 256, file);
        printf("\nDLL: %s\n", dll_name);

        uint32_t thunk_offset = rva_to_file_offset(file, import_descriptor.FirstThunk, nt_headers, is_32bit);
        if (thunk_offset == 0) {
            printf("Failed to find thunk data\n");
            continue;
        }

        fseek(file, thunk_offset, SEEK_SET);
        
        while (1) {
            uint64_t thunk_data;
            if (is_32bit) {
                uint32_t thunk_data_32;
                fread(&thunk_data_32, sizeof(uint32_t), 1, file);
                thunk_data = thunk_data_32;
            } else {
                fread(&thunk_data, sizeof(uint64_t), 1, file);
            }

            if (thunk_data == 0) break;

            if (!(thunk_data & (is_32bit ? IMAGE_ORDINAL_FLAG32 : IMAGE_ORDINAL_FLAG64))) {
                uint32_t name_offset = rva_to_file_offset(file, (uint32_t)(thunk_data & 0xFFFFFFFF) + 2, nt_headers, is_32bit);
                if (name_offset == 0) {
                    printf("Failed to find function name\n");
                    continue;
                }

                fseek(file, name_offset, SEEK_SET);
                char function_name[256];
                fread(function_name, 1, 256, file);
                printf(" Function: %s\n", function_name);
            } else {
                printf(" Function: Ordinal: %llu\n", thunk_data & 0xFFFF);
            }
        }
    }
}

void parse_pe_file(const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        printf("Couldn't load file\n");
        return;
    }

    IMAGE_DOS_HEADER dos_header;
    fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, file);
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature\n");
        fclose(file);
        return;
    }

    fseek(file, dos_header.e_lfanew, SEEK_SET);

    uint32_t nt_signature;
    fread(&nt_signature, sizeof(uint32_t), 1, file);
    if (nt_signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature\n");
        fclose(file);
        return;
    }

    IMAGE_FILE_HEADER file_header;
    fread(&file_header, sizeof(IMAGE_FILE_HEADER), 1, file);

    uint16_t magic;
    fread(&magic, sizeof(uint16_t), 1, file);
    fseek(file, -sizeof(uint16_t), SEEK_CUR);

    int is_32bit = (magic == 0x10B);

    if (is_32bit) {
        IMAGE_NT_HEADERS32 nt_headers;
        fread(&nt_headers, sizeof(IMAGE_NT_HEADERS32), 1, file);
        
        printf("PE File Headers:\n");
        printf("Machine: 0x%X\n", nt_headers.FileHeader.Machine);
        printf("Number of sections: %d\n", nt_headers.FileHeader.NumberOfSections);
        printf("TimeDateStamp: %u\n", nt_headers.FileHeader.TimeDateStamp);
        printf("Characteristics: 0x%X\n", nt_headers.FileHeader.Characteristics);

        printf("\nOptional Headers:\n");
        printf("Magic: 0x%X\n", nt_headers.OptionalHeader.Magic);
        printf("LinkerVersion: %d.%d\n", nt_headers.OptionalHeader.MajorLinkerVersion, nt_headers.OptionalHeader.MinorLinkerVersion);
        printf("SizeOfCode: %u\n", nt_headers.OptionalHeader.SizeOfCode);
        printf("AddressOfEntryPoint: 0x%X\n", nt_headers.OptionalHeader.AddressOfEntryPoint);
        printf("ImageBase: 0x%X\n", nt_headers.OptionalHeader.ImageBase);

        printf("\nImport Table:\n");
        parse_imports(file, &nt_headers, 1);
    } else {
        IMAGE_NT_HEADERS64 nt_headers;
        fread(&nt_headers, sizeof(IMAGE_NT_HEADERS64), 1, file);
        
        printf("PE File Headers:\n");
        printf("Machine: 0x%X\n", nt_headers.FileHeader.Machine);
        printf("Number of sections: %d\n", nt_headers.FileHeader.NumberOfSections);
        printf("TimeDateStamp: %u\n", nt_headers.FileHeader.TimeDateStamp);
        printf("Characteristics: 0x%X\n", nt_headers.FileHeader.Characteristics);

        printf("\nOptional Headers:\n");
        printf("Magic: 0x%X\n", nt_headers.OptionalHeader.Magic);
        printf("LinkerVersion: %d.%d\n", nt_headers.OptionalHeader.MajorLinkerVersion, nt_headers.OptionalHeader.MinorLinkerVersion);
        printf("SizeOfCode: %u\n", nt_headers.OptionalHeader.SizeOfCode);
        printf("AddressOfEntryPoint: 0x%X\n", nt_headers.OptionalHeader.AddressOfEntryPoint);
        printf("ImageBase: 0x%llX\n", (unsigned long long)nt_headers.OptionalHeader.ImageBase);

        printf("\nImport Table:\n");
        parse_imports(file, &nt_headers, 0);
    }

    fclose(file);
}



