// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

//! Implementation of a tool that generates a simple IGVM file that is used
//! to generate test data for the C API unit tests.

use std::env;
use std::fs::File;
use std::io::Write;

use igvm::IgvmDirectiveHeader;
use igvm::IgvmFile;
use igvm::IgvmInitializationHeader;
use igvm::IgvmPlatformHeader;
use igvm::IgvmRevision;
use igvm_defs::IgvmPageDataFlags;
use igvm_defs::IgvmPageDataType;
use igvm_defs::IgvmPlatformType;
use igvm_defs::IGVM_VHS_PARAMETER;
use igvm_defs::IGVM_VHS_PARAMETER_INSERT;
use igvm_defs::IGVM_VHS_SUPPORTED_PLATFORM;
use igvm_defs::PAGE_SIZE_4K;

fn new_platform(compatibility_mask: u32, platform_type: IgvmPlatformType) -> IgvmPlatformHeader {
    IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask,
        highest_vtl: 0,
        platform_type,
        platform_version: 1,
        shared_gpa_boundary: 0,
    })
}

fn new_guest_policy(policy: u64, compatibility_mask: u32) -> IgvmInitializationHeader {
    IgvmInitializationHeader::GuestPolicy {
        policy,
        compatibility_mask,
    }
}

fn new_page_data(page: u64, compatibility_mask: u32, data: &[u8]) -> IgvmDirectiveHeader {
    IgvmDirectiveHeader::PageData {
        gpa: page * PAGE_SIZE_4K,
        compatibility_mask,
        flags: IgvmPageDataFlags::new(),
        data_type: IgvmPageDataType::NORMAL,
        data: data.to_vec(),
    }
}

fn new_parameter_area(index: u32) -> IgvmDirectiveHeader {
    IgvmDirectiveHeader::ParameterArea {
        number_of_bytes: 4096,
        parameter_area_index: index,
        initial_data: vec![],
    }
}

fn new_parameter_usage(index: u32) -> IgvmDirectiveHeader {
    IgvmDirectiveHeader::VpCount(IGVM_VHS_PARAMETER {
        parameter_area_index: index,
        byte_offset: 0,
    })
}

fn new_parameter_insert(page: u64, index: u32, mask: u32) -> IgvmDirectiveHeader {
    IgvmDirectiveHeader::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
        gpa: page * PAGE_SIZE_4K,
        parameter_area_index: index,
        compatibility_mask: mask,
    })
}

fn create_basic(filename: &String) {
    let data1 = vec![1; PAGE_SIZE_4K as usize];
    let data2 = vec![2; PAGE_SIZE_4K as usize];
    let data3 = vec![3; PAGE_SIZE_4K as usize];
    let data4 = vec![4; PAGE_SIZE_4K as usize];
    let file = IgvmFile::new(
        IgvmRevision::V1,
        vec![new_platform(0x1, IgvmPlatformType::VSM_ISOLATION)],
        vec![new_guest_policy(0x30000, 1), new_guest_policy(0x30000, 2)],
        vec![
            new_page_data(0, 1, &data1),
            new_page_data(1, 1, &data2),
            new_page_data(2, 1, &data3),
            new_page_data(4, 1, &data4),
            new_page_data(10, 1, &data1),
            new_page_data(11, 1, &data2),
            new_page_data(12, 1, &data3),
            new_page_data(14, 1, &data4),
            new_parameter_area(0),
            new_parameter_usage(0),
            new_parameter_insert(20, 0, 1),
        ],
    )
    .expect("Failed to create file");
    let mut binary_file = Vec::new();
    file.serialize(&mut binary_file).unwrap();

    let mut file = File::create(filename).expect("Could not open file");
    file.write_all(binary_file.as_slice())
        .expect("Failed to write file");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: test_data igvm_filename");
        return;
    }
    create_basic(&args[1]);
}
