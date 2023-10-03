#include <CUnit/CUnit.h>
#include <CUnit/TestRun.h>
#include <stdio.h>
#include "../include/igvm.h"
#include <CUnit/Basic.h>

static const char *filename = NULL;
static uint8_t* igvm_buf;
static uint32_t igvm_buf_length;
static uint8_t invalid_igvm_buf[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

/* These values must match the test data prodcued by the test_data executable */
#define TEST_DATA_NUM_PLATFORM				1
#define TEST_DATA_NUM_INITIALIZATION		2
#define TEST_DATA_NUM_DIRECTIVE				11


void test_valid_igvm(void) {
	IgvmHandle igvm;
	igvm = igvm_new_from_binary(igvm_buf, igvm_buf_length);
	CU_ASSERT(igvm > 0);
	igvm_free(igvm);
}

void test_invalid_fixed_header(void) {
	IgvmHandle igvm;
	CU_ASSERT_EQUAL(igvm_new_from_binary(invalid_igvm_buf, sizeof(invalid_igvm_buf)), IGVMAPI_INVALID_FIXED_HEADER);
}

void test_header_counts(void) {
	IgvmHandle igvm;
	igvm = igvm_new_from_binary(igvm_buf, igvm_buf_length);
	CU_ASSERT(igvm > 0);

	CU_ASSERT_EQUAL(igvm_header_count(igvm, HEADER_SECTION_PLATFORM), 1);
	CU_ASSERT_EQUAL(igvm_header_count(igvm, HEADER_SECTION_INITIALIZATION), 2);
	CU_ASSERT_EQUAL(igvm_header_count(igvm, HEADER_SECTION_DIRECTIVE), 11);

	igvm_free(igvm);
}

void test_platform_header(void) {
	IgvmHandle igvm;
	IGVM_VHS_VARIABLE_HEADER *header;
	IGVM_VHS_SUPPORTED_PLATFORM *platform;
	IgvmHandle data;

	igvm = igvm_new_from_binary(igvm_buf, igvm_buf_length);
	CU_ASSERT(igvm > 0);
	data = igvm_get_header(igvm, HEADER_SECTION_PLATFORM, 0);
	CU_ASSERT(data > 0);

	header = (IGVM_VHS_VARIABLE_HEADER *)igvm_get_buffer(igvm, data);
	CU_ASSERT_EQUAL(header->typ, IGVM_VHT_SUPPORTED_PLATFORM);
	CU_ASSERT_EQUAL(header->length, sizeof(IGVM_VHS_SUPPORTED_PLATFORM));

	platform = (IGVM_VHS_SUPPORTED_PLATFORM *)(igvm_get_buffer(igvm, data) + sizeof(IGVM_VHS_VARIABLE_HEADER));
	CU_ASSERT_EQUAL(platform->platform_type, VSM_ISOLATION);
	CU_ASSERT_EQUAL(platform->compatibility_mask, 1);
	CU_ASSERT_EQUAL(platform->platform_version, 1);
	CU_ASSERT_EQUAL(platform->highest_vtl, 0);
	CU_ASSERT_EQUAL(platform->shared_gpa_boundary, 0);

	igvm_free_buffer(igvm, data);
	igvm_free(igvm);
}

void test_initialization_header(void) {
	IgvmHandle igvm;
	IGVM_VHS_VARIABLE_HEADER *header;
	IGVM_VHS_GUEST_POLICY *policy;
	IgvmHandle data;

	igvm = igvm_new_from_binary(igvm_buf, igvm_buf_length);
	CU_ASSERT(igvm > 0);
	data = igvm_get_header(igvm, HEADER_SECTION_INITIALIZATION, 0);
	CU_ASSERT(data > 0);

	/* First entry */
	header = (IGVM_VHS_VARIABLE_HEADER *)igvm_get_buffer(igvm, data);
	CU_ASSERT_EQUAL(header->typ, IGVM_VHT_GUEST_POLICY);
	CU_ASSERT_EQUAL(header->length, sizeof(IGVM_VHS_GUEST_POLICY));

	policy = (IGVM_VHS_GUEST_POLICY *)(igvm_get_buffer(igvm, data) + sizeof(IGVM_VHS_VARIABLE_HEADER));
	CU_ASSERT_EQUAL(policy->policy, 0x30000);
	CU_ASSERT_EQUAL(policy->compatibility_mask, 1);
	CU_ASSERT_EQUAL(policy->reserved, 0);
	igvm_free_buffer(igvm, data);

	/* Second entry */
	data = igvm_get_header(igvm, HEADER_SECTION_INITIALIZATION, 1);
	CU_ASSERT(data > 0);

	header = (IGVM_VHS_VARIABLE_HEADER *)igvm_get_buffer(igvm, data);
	CU_ASSERT_EQUAL(header->typ, IGVM_VHT_GUEST_POLICY);
	CU_ASSERT_EQUAL(header->length, sizeof(IGVM_VHS_GUEST_POLICY));

	policy = (IGVM_VHS_GUEST_POLICY *)(igvm_get_buffer(igvm, data) + sizeof(IGVM_VHS_VARIABLE_HEADER));
	CU_ASSERT_EQUAL(policy->policy, 0x30000);
	CU_ASSERT_EQUAL(policy->compatibility_mask, 2);
	CU_ASSERT_EQUAL(policy->reserved, 0);
	igvm_free_buffer(igvm, data);

	igvm_free(igvm);
}

void test_directive_header(void) {
	IgvmHandle igvm;
	IGVM_VHS_VARIABLE_HEADER *header;
	IGVM_VHS_PAGE_DATA *page;
	IGVM_VHS_PARAMETER_AREA *param_area;
	IGVM_VHS_PARAMETER* param;
	IGVM_VHS_PARAMETER_INSERT* ins;
	IgvmHandle data;

	igvm = igvm_new_from_binary(igvm_buf, igvm_buf_length);
	CU_ASSERT(igvm > 0);
	data = igvm_get_header(igvm, HEADER_SECTION_DIRECTIVE, 1);
	CU_ASSERT(data > 0);

	header = (IGVM_VHS_VARIABLE_HEADER *)igvm_get_buffer(igvm, data);
	CU_ASSERT_EQUAL(header->typ, IGVM_VHT_PAGE_DATA);
	CU_ASSERT_EQUAL(header->length, sizeof(IGVM_VHS_PAGE_DATA));
	page = (IGVM_VHS_PAGE_DATA *)(igvm_get_buffer(igvm, data) + sizeof(IGVM_VHS_VARIABLE_HEADER));
	CU_ASSERT_EQUAL(page->data_type, NORMAL);
	CU_ASSERT_EQUAL(page->compatibility_mask, 1);
	CU_ASSERT_EQUAL(page->file_offset, 0);
	CU_ASSERT_EQUAL(page->flags.is_2mb_page, 0);
	CU_ASSERT_EQUAL(page->flags.unmeasured, 0);
	CU_ASSERT_EQUAL(page->flags.reserved, 0);
	CU_ASSERT_EQUAL(page->gpa, 0x1000);
	CU_ASSERT_EQUAL(page->reserved, 0);
	igvm_free_buffer(igvm, data);

	data = igvm_get_header(igvm, HEADER_SECTION_DIRECTIVE, 8);
	header = (IGVM_VHS_VARIABLE_HEADER *)igvm_get_buffer(igvm, data);
	CU_ASSERT_EQUAL(header->typ, IGVM_VHT_PARAMETER_AREA);
	CU_ASSERT_EQUAL(header->length, sizeof(IGVM_VHS_PARAMETER_AREA));
	param_area = (IGVM_VHS_PARAMETER_AREA *)(igvm_get_buffer(igvm, data) + sizeof(IGVM_VHS_VARIABLE_HEADER));
	CU_ASSERT_EQUAL(param_area->parameter_area_index, 0);
	CU_ASSERT_EQUAL(param_area->file_offset, 0);
	CU_ASSERT_EQUAL(param_area->number_of_bytes, 0x1000);
	igvm_free_buffer(igvm, data);

	data = igvm_get_header(igvm, HEADER_SECTION_DIRECTIVE, 9);
	CU_ASSERT(data > 0);
	header = (IGVM_VHS_VARIABLE_HEADER *)igvm_get_buffer(igvm, data);
	CU_ASSERT_EQUAL(header->typ, IGVM_VHT_VP_COUNT_PARAMETER);
	CU_ASSERT_EQUAL(header->length, sizeof(IGVM_VHS_PARAMETER));
	param = (IGVM_VHS_PARAMETER *)(igvm_get_buffer(igvm, data) + sizeof(IGVM_VHS_VARIABLE_HEADER));
	CU_ASSERT_EQUAL(param->parameter_area_index, 0);
	CU_ASSERT_EQUAL(param->byte_offset, 0);
	igvm_free_buffer(igvm, data);

	data = igvm_get_header(igvm, HEADER_SECTION_DIRECTIVE, 10);
	CU_ASSERT(data > 0);
	header = (IGVM_VHS_VARIABLE_HEADER *)igvm_get_buffer(igvm, data);
	CU_ASSERT_EQUAL(header->typ, IGVM_VHT_PARAMETER_INSERT);
	CU_ASSERT_EQUAL(header->length, sizeof(IGVM_VHS_PARAMETER_INSERT));
	ins = (IGVM_VHS_PARAMETER_INSERT *)(igvm_get_buffer(igvm, data) + sizeof(IGVM_VHS_VARIABLE_HEADER));
	CU_ASSERT_EQUAL(ins->parameter_area_index, 0);
	CU_ASSERT_EQUAL(ins->compatibility_mask, 1);
	CU_ASSERT_EQUAL(ins->gpa, 0x14000);
	igvm_free_buffer(igvm, data);

	igvm_free(igvm);
}

void test_associated_data(void) {
	IgvmHandle igvm;
	uint32_t data_length = 0;
	uint32_t i;
	int all_same = 1;
	IgvmHandle data;

	igvm = igvm_new_from_binary(igvm_buf, igvm_buf_length);
	CU_ASSERT(igvm > 0);
	data = igvm_get_header_data(igvm, HEADER_SECTION_DIRECTIVE, 3);
	CU_ASSERT(data > 0);
	
	data_length = igvm_get_buffer_size(igvm, data);
	CU_ASSERT_EQUAL(data_length, 0x1000);
	for (i = 0; i < data_length; ++i) {
		if (igvm_get_buffer(igvm, data)[i] != 4) {
			all_same = 0;
			break;
		}
	}
	CU_ASSERT_EQUAL(all_same, 1);

	igvm_free_buffer(igvm, data);
	igvm_free(igvm);
}

void test_no_associated_data(void) {
	IgvmHandle igvm;
	uint32_t data_length = 0;

	igvm = igvm_new_from_binary(igvm_buf, igvm_buf_length);
	CU_ASSERT(igvm > 0);
	CU_ASSERT_EQUAL(igvm_get_header_data(igvm, HEADER_SECTION_DIRECTIVE, 9), IGVMAPI_NO_DATA);

	igvm_free(igvm);
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
	int failed = 0;

	if (parse_args(argc, argv)) {
		return 1;
	}

	fp = fopen(filename, "rb");
	if (!fp) {
		printf("Could not open file\n");
		return 1;
	}
	fseek(fp, 0, SEEK_END);
	igvm_buf_length = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	igvm_buf = (uint8_t *)malloc(igvm_buf_length);
	if (!igvm_buf) {
		fclose(fp);
		printf("Could not allocate buffer to read file\n");
		return 1;
	}
	if (fread(igvm_buf, 1, igvm_buf_length, fp) != igvm_buf_length) {
		fclose(fp);
		free(igvm_buf);
		printf("Failed to read file\n");
		return 1;
	}
	fclose(fp);

	CU_pSuite suite = NULL;
	if (CU_initialize_registry() != CUE_SUCCESS) {
		return -1;
	}

	suite = CU_add_suite("igvm", NULL, NULL);
	if (!suite) {
		return -1;
	}

	CU_add_test(suite, "Parse valid IGVM file", test_valid_igvm);
	CU_add_test(suite, "Parse invalid fixed header", test_invalid_fixed_header);
	CU_add_test(suite, "Check header counting", test_header_counts);
	CU_add_test(suite, "Test for a valid platform header", test_platform_header);
	CU_add_test(suite, "Test for valid initialization headers", test_initialization_header);
	CU_add_test(suite, "Test for valid directive headers", test_directive_header);
	CU_add_test(suite, "Test for valid associated data", test_associated_data);
	CU_add_test(suite, "Test for no associated data", test_no_associated_data);

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	failed = CU_get_number_of_tests_failed();
	CU_cleanup_registry();
	free(igvm_buf);

	return (failed > 0) ? 1 : 0;
}