// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! AMD SEV-SNP launch measurement (launch digest) calculation.
//!
//! Computes the launch digest by iterating IGVM directive headers and chaining
//! SHA-384 hashes through `SnpPageInfo` structures, matching the SNP firmware's
//! measurement algorithm.

use super::MeasurementError;
use super::SHA_384_OUTPUT_SIZE;
use crate::IgvmDirectiveHeader;
use crate::IgvmInitializationHeader;
use igvm_defs::IgvmPageDataType;
use igvm_defs::PAGE_SIZE_4K;
use sha2::Digest;
use sha2::Sha384;
use std::collections::HashMap;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

const PAGE_SIZE_4K_USIZE: usize = PAGE_SIZE_4K as usize;

// Local type definitions matching the AMD SEV-SNP firmware ABI.

/// SNP page type constants.
mod snp_page_type {
    pub const NORMAL: u8 = 0x1;
    pub const VMSA: u8 = 0x2;
    pub const UNMEASURED: u8 = 0x4;
    pub const SECRETS: u8 = 0x5;
    pub const CPUID: u8 = 0x6;
}

/// Structure used by SNP firmware to chain page measurements.
///
/// See AMD SEV-SNP firmware ABI specification Sec. 7.3 (SNP_LAUNCH_UPDATE).
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
struct SnpPageInfo {
    digest_current: [u8; 48],
    contents: [u8; 48],
    length: u16,
    page_type: u8,
    imi_page_bit: u8,
    lower_vmpl_permissions: u32,
    gpa: u64,
}

/// Compute the SNP launch digest from IGVM headers.
///
/// Iterates all initialization and directive headers for the given
/// compatibility mask, computing the chained SHA-384 measurement that
/// the SNP firmware would produce during `SNP_LAUNCH_UPDATE`.
///
/// The IGVM file must contain an [`IgvmInitializationHeader::GuestPolicy`]
/// matching `compatibility_mask`; otherwise [`MeasurementError::MissingGuestPolicy`]
/// is returned. The policy itself does not affect the returned digest.
pub fn generate_snp_measurement(
    initialization_headers: &[IgvmInitializationHeader],
    directive_headers: &[IgvmDirectiveHeader],
    compatibility_mask: u32,
) -> Result<[u8; SHA_384_OUTPUT_SIZE], MeasurementError> {
    let mut parameter_area_table = HashMap::new();
    let mut launch_digest = [0u8; SHA_384_OUTPUT_SIZE];

    // Pre-compute hash of zero page (used when file does not carry data)
    let zero_page = [0u8; PAGE_SIZE_4K_USIZE];
    let zero_digest: [u8; SHA_384_OUTPUT_SIZE] = {
        let mut h = Sha384::new();
        h.update(zero_page);
        h.finalize().into()
    };

    let mut padding_vec = vec![0u8; PAGE_SIZE_4K_USIZE];

    let mut measure_page =
        |page_type: u8, gpa: u64, page_data: Option<&[u8]>| -> Result<(), MeasurementError> {
            let hash_contents: [u8; SHA_384_OUTPUT_SIZE] = match page_data {
                Some(data) => match data.len() {
                    0 => zero_digest,
                    len if len < PAGE_SIZE_4K_USIZE => {
                        padding_vec.fill(0);
                        padding_vec[..len].copy_from_slice(data);
                        let mut h = Sha384::new();
                        h.update(&padding_vec);
                        h.finalize().into()
                    }
                    PAGE_SIZE_4K_USIZE => {
                        let mut h = Sha384::new();
                        h.update(data);
                        h.finalize().into()
                    }
                    len => return Err(MeasurementError::UnsupportedPageSize(len)),
                },
                None => [0u8; SHA_384_OUTPUT_SIZE],
            };

            let info = SnpPageInfo {
                digest_current: launch_digest,
                contents: hash_contents,
                length: size_of::<SnpPageInfo>() as u16,
                page_type,
                imi_page_bit: 0,
                lower_vmpl_permissions: 0,
                gpa,
            };

            let mut h = Sha384::new();
            h.update(info.as_bytes());
            launch_digest = h.finalize().into();
            Ok(())
        };

    // Validate that the file carries an SNP guest policy. The policy itself
    // does not affect the launch digest, but a malformed file without one
    // would be unusable downstream.
    let _policy = initialization_headers
        .iter()
        .find_map(|h| {
            if let IgvmInitializationHeader::GuestPolicy {
                policy,
                compatibility_mask: mask,
            } = h
            {
                if mask & compatibility_mask == compatibility_mask {
                    return Some(*policy);
                }
            }
            None
        })
        .ok_or(MeasurementError::MissingGuestPolicy)?;

    // Iterate directive headers
    for header in directive_headers {
        if header
            .compatibility_mask()
            .map(|mask| mask & compatibility_mask != compatibility_mask)
            .unwrap_or(false)
        {
            continue;
        }

        match header {
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index,
                initial_data: _,
            } => {
                parameter_area_table.insert(*parameter_area_index, *number_of_bytes);
            }
            IgvmDirectiveHeader::PageData {
                gpa,
                flags,
                data_type,
                data,
                ..
            } => {
                if flags.shared() {
                    continue;
                }

                let (page_type, data) = match *data_type {
                    IgvmPageDataType::SECRETS => (snp_page_type::SECRETS, None),
                    IgvmPageDataType::CPUID_DATA | IgvmPageDataType::CPUID_XF => {
                        (snp_page_type::CPUID, None)
                    }
                    _ => {
                        if flags.unmeasured() {
                            (snp_page_type::UNMEASURED, None)
                        } else {
                            (snp_page_type::NORMAL, Some(data.as_slice()))
                        }
                    }
                };

                measure_page(page_type, *gpa, data)?;
            }
            IgvmDirectiveHeader::ParameterInsert(param) => {
                let parameter_area_size = parameter_area_table
                    .get(&param.parameter_area_index)
                    .ok_or(MeasurementError::InvalidParameterAreaIndex(
                        param.parameter_area_index,
                    ))?;

                for gpa in (param.gpa..param.gpa + *parameter_area_size).step_by(PAGE_SIZE_4K_USIZE)
                {
                    measure_page(snp_page_type::UNMEASURED, gpa, None)?;
                }
            }
            IgvmDirectiveHeader::SnpVpContext { gpa, vmsa, .. } => {
                let vmsa_bytes = vmsa.as_ref().as_bytes();
                measure_page(snp_page_type::VMSA, *gpa, Some(vmsa_bytes))?;
            }
            _ => {}
        }
    }

    Ok(launch_digest)
}
