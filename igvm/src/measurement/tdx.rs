// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Intel TDX launch measurement (MRTD) calculation.
//!
//! Computes the MRTD by iterating IGVM directive headers and hashing
//! `MEM.PAGE.ADD` and `MR.EXTEND` operations, matching the TDX module's
//! measurement algorithm.

use super::MeasurementError;
use super::SHA_384_OUTPUT_SIZE;
use crate::IgvmDirectiveHeader;
use igvm_defs::PAGE_SIZE_4K;
use sha2::Digest;
use sha2::Sha384;
use std::collections::HashMap;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

const PAGE_SIZE_4K_USIZE: usize = PAGE_SIZE_4K as usize;
const TDX_EXTEND_CHUNK_SIZE: usize = 256;

/// Structure for measuring a page addition to the TD.
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
struct TdxPageAdd {
    /// `MEM.PAGE.ADD` operation identifier.
    operation: [u8; 16],
    /// Guest physical address (page-aligned).
    gpa: u64,
    /// Reserved, must be zero.
    mbz: [u8; 104],
}

/// Structure for measuring a 256-byte data chunk.
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
struct TdxMrExtend {
    /// `MR.EXTEND` operation identifier.
    operation: [u8; 16],
    /// Guest physical address (256-byte aligned).
    gpa: u64,
    /// Reserved, must be zero.
    mbz: [u8; 104],
    /// 256 bytes of data to measure.
    data: [u8; TDX_EXTEND_CHUNK_SIZE],
}

/// Compute the TDX MRTD from IGVM directive headers.
///
/// Iterates all directive headers for the given compatibility mask,
/// computing the running SHA-384 hash of `MEM.PAGE.ADD` and `MR.EXTEND`
/// operations that the TDX module would perform during `TDH.MR.FINALIZE`.
pub fn generate_tdx_measurement(
    directive_headers: &[IgvmDirectiveHeader],
    compatibility_mask: u32,
) -> Result<[u8; SHA_384_OUTPUT_SIZE], MeasurementError> {
    let mut parameter_area_table = HashMap::new();
    let mut padding_vec = vec![0u8; PAGE_SIZE_4K_USIZE];
    let mut hasher = Sha384::new();

    let mut measure_page = |gpa: u64, page_data: Option<&[u8]>| -> Result<(), MeasurementError> {
        // Measure the page being added.
        let page_add = TdxPageAdd {
            operation: *b"MEM.PAGE.ADD\0\0\0\0",
            gpa,
            mbz: [0; 104],
        };
        hasher.update(page_add.as_bytes());

        // Possibly measure the page contents in 256-byte chunks.
        if let Some(data) = page_data {
            let data = match data.len() {
                0 => None,
                PAGE_SIZE_4K_USIZE => Some(data),
                len if len < PAGE_SIZE_4K_USIZE => {
                    padding_vec.fill(0);
                    padding_vec[..len].copy_from_slice(data);
                    Some(padding_vec.as_slice())
                }
                len => return Err(MeasurementError::UnsupportedPageSize(len)),
            };

            for offset in (0..PAGE_SIZE_4K).step_by(TDX_EXTEND_CHUNK_SIZE) {
                let mut mr_extend = TdxMrExtend {
                    operation: *b"MR.EXTEND\0\0\0\0\0\0\0",
                    gpa: gpa + offset,
                    mbz: [0; 104],
                    data: [0; TDX_EXTEND_CHUNK_SIZE],
                };

                if let Some(data) = data {
                    mr_extend.data.copy_from_slice(
                        &data[offset as usize..offset as usize + TDX_EXTEND_CHUNK_SIZE],
                    );
                }
                hasher.update(mr_extend.as_bytes());
            }
        }
        Ok(())
    };

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
                gpa, flags, data, ..
            } => {
                if flags.shared() {
                    continue;
                }

                let data = if flags.unmeasured() {
                    None
                } else {
                    Some(data.as_slice())
                };

                measure_page(*gpa, data)?;
            }
            IgvmDirectiveHeader::ParameterInsert(param) => {
                let parameter_area_size = parameter_area_table
                    .get(&param.parameter_area_index)
                    .ok_or(MeasurementError::InvalidParameterAreaIndex(
                        param.parameter_area_index,
                    ))?;

                for gpa in (param.gpa..param.gpa + *parameter_area_size).step_by(PAGE_SIZE_4K_USIZE)
                {
                    measure_page(gpa, None)?;
                }
            }
            _ => {}
        }
    }

    Ok(hasher.finalize().into())
}
