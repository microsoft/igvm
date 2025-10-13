/* 
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Copyright (c) 2023 SUSE LLC
 *
 * Author: Roy Hopkins <rhopkins@suse.de>
*/
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "../include/igvm.h"

static char* filename = NULL;
static int hex_context = INT_MAX;
static char *section_name[] = { "platform", "initialization", "directive" };

static void hexdump(const void* data, size_t size, int columns, int address) {
    int rows = (size + (columns - 1)) / columns;
    int row;
    int col;

    for (row = 0; row < rows; ++row) {
        printf("| %08X | ", address + row * columns);
        for (col = 0; col < columns; ++col) {
            size_t index = row * columns + col;
            if (index >= size) {
                printf("   ");
            }
            else {
                printf("%02X ", ((unsigned char *)data)[index]);
            }
        }
        printf("| ");
        for (col = 0; col < columns; ++col) {
            size_t index = row * columns + col;
            if (index >= size) {
                printf(" ");
            }
            else {
                char c = ((char *)data)[index];
                if ((c >= 32) && (c < 127)) {
                    printf("%c", c);
                }
                else {
                    printf(".");
                }
            }
        }
        printf(" |\n");
    }
}

static char *igvm_type_to_text(uint32_t type)
{
    switch (type & 0x7fffffff) {
    case IGVM_VHT_SUPPORTED_PLATFORM:
        return "IGVM_VHT_SUPPORTED_PLATFORM";
    case IGVM_VHT_GUEST_POLICY:
        return "IGVM_VHT_GUEST_POLICY";
    case IGVM_VHT_RELOCATABLE_REGION:
        return "IGVM_VHT_RELOCATABLE_REGION";
    case IGVM_VHT_PAGE_TABLE_RELOCATION_REGION:
        return "IGVM_VHT_PAGE_TABLE_RELOCATION_REGION";
    case IGVM_VHT_PARAMETER_AREA:
        return "IGVM_VHT_PARAMETER_AREA";
    case IGVM_VHT_PAGE_DATA:
        return "IGVM_VHT_PAGE_DATA";
    case IGVM_VHT_PARAMETER_INSERT:
        return "IGVM_VHT_PARAMETER_INSERT";
    case IGVM_VHT_VP_CONTEXT:
        return "IGVM_VHT_VP_CONTEXT";
    case IGVM_VHT_REQUIRED_MEMORY:
        return "IGVM_VHT_REQUIRED_MEMORY";
    case IGVM_VHT_VP_COUNT_PARAMETER:
        return "IGVM_VHT_VP_COUNT_PARAMETER";
    case IGVM_VHT_SRAT:
        return "IGVM_VHT_SRAT";
    case IGVM_VHT_MADT:
        return "IGVM_VHT_MADT";
    case IGVM_VHT_MMIO_RANGES:
        return "IGVM_VHT_MMIO_RANGES";
    case IGVM_VHT_SNP_ID_BLOCK:
        return "IGVM_VHT_SNP_ID_BLOCK";
    case IGVM_VHT_MEMORY_MAP:
        return "IGVM_VHT_MEMORY_MAP";
    case IGVM_VHT_ERROR_RANGE:
        return "IGVM_VHT_ERROR_RANGE";
    case IGVM_VHT_COMMAND_LINE:
        return "IGVM_VHT_COMMAND_LINE";
    case IGVM_VHT_SLIT:
        return "IGVM_VHT_SLIT";
    case IGVM_VHT_PPTT:
        return "IGVM_VHT_PPTT";
    case IGVM_VHT_VBS_MEASUREMENT:
        return "IGVM_VHT_VBS_MEASUREMENT";
    case IGVM_VHT_DEVICE_TREE:
        return "IGVM_VHT_DEVICE_TREE";
    case IGVM_VHT_ENVIRONMENT_INFO_PARAMETER:
        return "IGVM_VHT_ENVIRONMENT_INFO_PARAMETER";
    default:
        return "Unknown type";
    }
}

static void igvm_dump_parameter(IGVM_VHS_PARAMETER *param)
{
    printf("  IGVM_VHS_PARAMETER:\n");
    printf("    ParameterPageIndex: %08X\n", param->parameter_area_index);
    printf("    ByteOffset: %08X\n", param->byte_offset);
    printf("\n");
}

static void igvm_dump_variable_header(IGVM_VHS_VARIABLE_HEADER *header)
{
    void* vh_data = (uint8_t *)header + sizeof(IGVM_VHS_VARIABLE_HEADER);
    printf("%s:\n", igvm_type_to_text(header->typ));
    switch (header->typ) {
    case IGVM_VHT_SUPPORTED_PLATFORM: {
        IGVM_VHS_SUPPORTED_PLATFORM *vhs =
            (IGVM_VHS_SUPPORTED_PLATFORM *)vh_data;
        printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
        printf("  HighestVtl: %02X\n", vhs->highest_vtl);
        printf("  PlatformType: %02X\n", vhs->platform_type);
        printf("  PlatformVersion: %04X\n", vhs->platform_version);
        printf("  SharedGPABoundary: %lX\n", vhs->shared_gpa_boundary);
        break;
    }
    case IGVM_VHT_GUEST_POLICY: {
        IGVM_VHS_GUEST_POLICY *vhs = (IGVM_VHS_GUEST_POLICY *)vh_data;
        printf("  Policy: %016lX\n", vhs->policy);
        printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
        printf("  Reserved: %08X\n", vhs->reserved);
        break;
    }
    case IGVM_VHT_RELOCATABLE_REGION: {
        IGVM_VHS_RELOCATABLE_REGION *vhs =
            (IGVM_VHS_RELOCATABLE_REGION *)vh_data;
        printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
        printf("  VpIndex: %04X\n", vhs->vp_index);
        printf("  VTL: %02X\n", vhs->vtl);
        printf("  Flags: %02X\n", vhs->flags);
        printf("  RelocationAlignment: %016lX\n",
               vhs->relocation_alignment);
        printf("  RelocationRegionGPA: %016lX\n",
               vhs->relocation_region_gpa);
        printf("  RelocationRegionSize: %016lX\n",
               vhs->relocation_region_size);
        printf("  MinimumRelocationGPA: %016lX\n",
               vhs->minimum_relocation_gpa);
        printf("  MaximumRelocationGPA: %016lX\n",
               vhs->maximum_relocation_gpa);
        break;
    }
    case IGVM_VHT_PAGE_TABLE_RELOCATION_REGION: {
        IGVM_VHS_PAGE_TABLE_RELOCATION *vhs =
            (IGVM_VHS_PAGE_TABLE_RELOCATION *)vh_data;
        printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
        printf("  VpIndex: %04X\n", vhs->vp_index);
        printf("  VTL: %02X\n", vhs->vtl);
        printf("  Reserved: %02X\n", vhs->reserved);
        printf("  GPA: %016lX\n", vhs->gpa);
        printf("  Size: %016lX\n", vhs->size);
        printf("  UsedSize: %016lX\n", vhs->used_size);
        break;
    }
    case IGVM_VHT_PARAMETER_AREA: {
        IGVM_VHS_PARAMETER_AREA *vhs =
            (IGVM_VHS_PARAMETER_AREA *)vh_data;
        printf("  NumberOfBytes: %016lX\n", vhs->number_of_bytes);
        printf("  ParameterAreaIndex: %08X\n",
               vhs->parameter_area_index);
        printf("  FileOffset: %08X\n", vhs->file_offset);
        break;
    }
    case IGVM_VHT_PAGE_DATA: {
        IGVM_VHS_PAGE_DATA *vhs = (IGVM_VHS_PAGE_DATA *)vh_data;
        printf("  GPA: %016lX\n", vhs->gpa);
        printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
        printf("  FileOffset: %08X\n", vhs->file_offset);
        printf("  Flags: %08X\n", IGVM_UINT32_FLAGS_VALUE(vhs->flags));
        printf("  Reserved: %08X\n", vhs->reserved);
        break;
    }
    case IGVM_VHT_PARAMETER_INSERT: {
        IGVM_VHS_PARAMETER_INSERT *vhs =
            (IGVM_VHS_PARAMETER_INSERT *)vh_data;
        printf("  GPA: %016lX\n", vhs->gpa);
        printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
        printf("  ParameterAreaIndex: %08X\n",
               vhs->parameter_area_index);
        break;
    }
    case IGVM_VHT_VP_CONTEXT: {
        IGVM_VHS_VP_CONTEXT *vhs = (IGVM_VHS_VP_CONTEXT *)vh_data;
        printf("  GPA: %016lX\n", vhs->gpa);
        printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
        printf("  FileOffset: %08X\n", vhs->file_offset);
        printf("  VPIndex: %04X\n", vhs->vp_index);
        printf("  Reserved: %04X\n", vhs->reserved);
        break;
    }
    case IGVM_VHT_REQUIRED_MEMORY: {
        IGVM_VHS_REQUIRED_MEMORY *vhs =
            (IGVM_VHS_REQUIRED_MEMORY *)vh_data;
        printf("  GPA: %016lX\n", vhs->gpa);
        printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
        printf("  NumberOfBytes: %08X\n", vhs->number_of_bytes);
        printf("  Flags: %08X\n", IGVM_UINT32_FLAGS_VALUE(vhs->flags));
        printf("  Reserved: %08X\n", vhs->reserved);
        break;
    }
    case IGVM_VHT_VP_COUNT_PARAMETER:
    case IGVM_VHT_SRAT:
    case IGVM_VHT_MADT:
    case IGVM_VHT_DEVICE_TREE:
    case IGVM_VHT_MMIO_RANGES:
    case IGVM_VHT_MEMORY_MAP:
    case IGVM_VHT_COMMAND_LINE:
    case IGVM_VHT_ENVIRONMENT_INFO_PARAMETER:
    case IGVM_VHT_SLIT:
    case IGVM_VHT_PPTT: {
        IGVM_VHS_PARAMETER *vhs = (IGVM_VHS_PARAMETER *)vh_data;
        igvm_dump_parameter(vhs);
        break;
    }
    case IGVM_VHT_SNP_ID_BLOCK: {
        IGVM_VHS_SNP_ID_BLOCK *vhs = (IGVM_VHS_SNP_ID_BLOCK *)vh_data;
        printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
        printf("  AuthorKeyEnabled: %02X\n", vhs->author_key_enabled);
        printf("  Reserved: %02X%02X%02X\n", vhs->reserved[0],
               vhs->reserved[1], vhs->reserved[2]);
        printf("  Ld:\n");
        hexdump(vhs->ld, 32, 16, 0);
        printf("  FamilyId:\n");
        hexdump(vhs->ld, 16, 16, 0);
        printf("  ImageId:\n");
        hexdump(vhs->ld, 16, 16, 0);
        printf("  Version: %08X\n", vhs->version);
        printf("  GuestSvn: %08X\n", vhs->guest_svn);
        printf("  IdKeyAlgorithm: %08X\n", vhs->id_key_algorithm);
        printf("  AuthorKeyAlgorithm: %08X\n",
               vhs->author_key_algorithm);
        break;
    }
    case IGVM_VHT_ERROR_RANGE: {
        IGVM_VHS_ERROR_RANGE *vhs =
            (IGVM_VHS_ERROR_RANGE *)vh_data;
        printf("  GPA: %016lX\n", vhs->gpa);
        printf("  CompatibilityMask: %08X\n", vhs->compatibility_mask);
        printf("  SizeBytes: %08X\n", vhs->size_bytes);
        break;
    }
    default:
        break;
    }
    printf("\n");
}

static void igvm_dump_fixed_header(IGVM_FIXED_HEADER *header)
{
    printf("IGVM_FIXED_HEADER:\n");
    printf("  Magic: 0x%08X\n", header->magic);
    printf("  FormatVersion: 0x%08X\n", header->format_version);
    printf("  VariableHeaderOffset: 0x%08X\n",
           header->variable_header_offset);
    printf("  VariableHeaderSize: 0x%08X\n", header->variable_header_size);
    printf("  TotalFileSize: 0x%08X\n", header->total_file_size);
    printf("  Checksum: 0x%08X\n", header->checksum);
    printf("\n");
}

static int dump_igvm(uint8_t* igvm_buf, unsigned long igvm_length)
{
    IgvmHandle igvm;
    if ((igvm = igvm_new_from_binary(igvm_buf, igvm_length)) < 0) {
        printf("Failed to parse IGVM file. Error code: %ld\n", igvm);
        return 1;
    }

    for (long section = 0; section <= IGVM_HEADER_SECTION_DIRECTIVE; ++section) {
        int32_t count = igvm_header_count(igvm, (IgvmHeaderSection)section);
        printf("----------------------------------------------------------\n"
               "%s count = %ld\n\n",
               section_name[section], count);
        
        for (long i = 0; i < count; ++i) {
            IgvmVariableHeaderType typ = igvm_get_header_type(igvm, section, i);
            if (typ > 0) {
                IgvmHandle header_handle;
                IgvmHandle header_data;
                
                header_handle = igvm_get_header(igvm, section, i);
                if (header_handle < 0) {
                    printf("Invalid header (%ld)\n", header_handle);
                    return 1;
                }
                igvm_dump_variable_header((IGVM_VHS_VARIABLE_HEADER*)igvm_get_buffer(igvm, header_handle));
                igvm_free_buffer(igvm, header_handle);

                /* Do the same for any associated file data */
                header_data = igvm_get_header_data(igvm, section, i);
                if (header_data > 0) {
                    uint32_t filedata_length = igvm_get_buffer_size(igvm, header_data);
                    printf("Got %u bytes of file data:\n", filedata_length);
                    hexdump(igvm_get_buffer(igvm, header_data), (filedata_length > hex_context) ? hex_context : filedata_length, 32, 0);
                    igvm_free_buffer(igvm, header_data);
                }
            }
        }
    }

    igvm_free(igvm);
    return 0;
}

static int parse_args(int argc, char **argv) {
    int i;
    for (i = 1; i < argc; ++i) {
        if (argv[i][0] != '-') {
            if (filename != NULL) {
                printf("Invalid command line\n");
                return 1;
            }
            filename = argv[i];
        }
        else if (strcmp(argv[i], "--hex") == 0 || strcmp(argv[i], "-h") == 0) {
            if ((i + 1) == argc) {
                printf("Value missing for --hex\n");
                return 1;
            }
            ++i;
            hex_context = atoi(argv[i]);
        }
        else {
            printf("Invalid argument: %s\n", argv[i]);
            return 1;
        }
    }
    if (!filename) {
        printf("Filename not provided\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    FILE *fp;
    unsigned long length;
    uint8_t *igvm_buf = NULL;
    int ret;

    if (parse_args(argc, argv)) {
        printf("Usage: dump_igvm [--hex|-h bytes] igvm_file\n");
        printf("       --hex bytes specifies how many bytes of "
               "each file data section to dump as hex. Defaults "
               "to dumping the entire section.\n");
        return 1;
    }

    fp = fopen(filename, "rb");
    if (!fp) {
        printf("Could not open file\n");
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    length = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    igvm_buf = (uint8_t *)malloc(length);
    if (!igvm_buf) {
        fclose(fp);
        printf("Could not allocate buffer to read file\n");
        return 1;
    }
    if (fread(igvm_buf, 1, length, fp) != length) {
        fclose(fp);
        free(igvm_buf);
        printf("Failed to read file\n");
        return 1;
    }
    fclose(fp);

    ret = dump_igvm(igvm_buf, length);

    free(igvm_buf);
    return ret;
}