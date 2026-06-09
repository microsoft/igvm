// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Microsoft VBS launch measurement (boot digest) calculation.
//!
//! Computes the VBS boot measurement digest by iterating IGVM directive
//! headers and hashing page chunks and VP register state using SHA-256,
//! matching the VBS measurement protocol.
//!

#![expect(non_camel_case_types)]

use super::MeasurementError;
use super::SHA_256_OUTPUT_SIZE;
use crate::IgvmDirectiveHeader;
use bitfield_struct::bitfield;
use igvm_defs::IgvmPageDataType;
use igvm_defs::VbsVpContextRegister;
use igvm_defs::PAGE_SIZE_4K;
use open_enum::open_enum;
use sha2::Digest;
use sha2::Sha256;
use static_assertions::const_assert;
use std::collections::HashMap;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

const PAGE_SIZE_4K_USIZE: usize = PAGE_SIZE_4K as usize;

/// Full chunk size for VBS measurement (chunk header + page data).
const VBS_VP_CHUNK_SIZE_BYTES: usize = PAGE_SIZE_4K_USIZE + size_of::<VpGpaPageChunk>();

/// Acceptance flag indicating a GPA page is readable.
const VM_GPA_PAGE_READABLE: u64 = 0x1;
/// Acceptance flag indicating a GPA page is writable.
const VM_GPA_PAGE_WRITABLE: u64 = 0x2;

/// Chunk that is measured to generate digest. These consist of a 16 byte header
/// followed by data. This needs c style alignment to generate a consistent
/// measurement. Defined by the following struct in C:
/// ``` ignore
/// typedef struct _VBS_VM_BOOT_MEASUREMENT_CHUNK
/// {
///     UINT32 ByteCount;
///     VBS_VM_BOOT_MEASUREMENT_CHUNK_TYPE Type;
///     UINT64 Reserved;
///
///     union
///     {
///         VBS_VM_BOOT_MEASUREMENT_CHUNK_VP_REGISTER VpRegister;
///         VBS_VM_BOOT_MEASUREMENT_CHUNK_VP_VTL_ENABLED VpVtlEnabled;
///         VBS_VM_BOOT_MEASUREMENT_CHUNK_GPA_PAGE GpaPage;
///     } u;
/// } VBS_VM_BOOT_MEASUREMENT_CHUNK, *PVBS_VM_BOOT_MEASUREMENT_CHUNK;
/// ```
///
/// Structure describing the chunk to be measured.
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout)]
struct VbsChunkHeader {
    /// The full size to be measured
    byte_count: u32,
    chunk_type: BootMeasurementType,
    reserved: u64,
}

/// Structure describing the register being measured. Will be padded to
/// [`VBS_VP_CHUNK_SIZE_BYTES`] when hashed to generate digest.
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout)]
struct VbsRegisterChunk {
    header: VbsChunkHeader,
    reserved: u32,
    vtl: u8,
    reserved2: u8,
    reserved3: u16,
    reserved4: u32,
    name: u32,
    value: [u8; 16],
}
const_assert!(size_of::<VbsRegisterChunk>() <= VBS_VP_CHUNK_SIZE_BYTES);

/// Structure describing the page to be measured.
/// Page data is hashed after struct to generate digest, if not a full page,
/// measurable data will be padded to [`VBS_VP_CHUNK_SIZE_BYTES`].
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout)]
struct VpGpaPageChunk {
    header: VbsChunkHeader,
    metadata: u64,
    page_number: u64,
}

#[open_enum]
#[derive(IntoBytes, Immutable, KnownLayout, Clone, Copy)]
#[repr(u32)]
enum BootMeasurementType {
    VP_REGISTER = 0,
    VP_VTL_ENABLED = 1,
    VP_GPA_PAGE = 2,
}

/// Flags indicating read and write acceptance of a GPA Page and whether it is
/// to be measured in the digest.
#[bitfield(u64)]
struct VBS_VM_GPA_PAGE_BOOT_METADATA {
    #[bits(2)]
    acceptance: u64,
    #[bits(1)]
    data_unmeasured: bool,
    #[bits(61)]
    reserved: u64,
}

/// Compute the VBS boot measurement digest from IGVM directive headers.
///
/// Iterates all directive headers for the given compatibility mask, computing
/// the chained SHA-256 measurement that VBS firmware would produce.
pub fn generate_vbs_measurement(
    directive_headers: &[IgvmDirectiveHeader],
    compatibility_mask: u32,
) -> Result<[u8; SHA_256_OUTPUT_SIZE], MeasurementError> {
    let mut digest = VbsDigestor::new();
    let mut parameter_area_table = HashMap::new();
    let mut bsp_regs: Vec<Vec<VbsVpContextRegister>> = Vec::new();

    for header in directive_headers {
        // Skip headers that have compatibility masks that do not match vbs.
        if header
            .compatibility_mask()
            .map(|mask| mask & compatibility_mask != compatibility_mask)
            .unwrap_or(false)
        {
            continue;
        }

        match header {
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask: _,
                flags,
                data_type,
                data,
            } => {
                assert_eq!(*data_type, IgvmPageDataType::NORMAL);

                // Skip shared pages.
                if flags.shared() {
                    continue;
                }

                let boot_metadata = VBS_VM_GPA_PAGE_BOOT_METADATA::new()
                    .with_acceptance(0)
                    .with_data_unmeasured(flags.unmeasured());
                digest.record_gpa_page(gpa / PAGE_SIZE_4K, 1, boot_metadata, data);
            }
            IgvmDirectiveHeader::ParameterInsert(param) => {
                let page_metadata = VBS_VM_GPA_PAGE_BOOT_METADATA::new()
                    .with_acceptance(0)
                    .with_data_unmeasured(true);
                let parameter_area_size = parameter_area_table
                    .get(&param.parameter_area_index)
                    .ok_or(MeasurementError::InvalidParameterAreaIndex(
                        param.parameter_area_index,
                    ))?;
                digest.record_gpa_page(
                    param.gpa / PAGE_SIZE_4K,
                    parameter_area_size / PAGE_SIZE_4K,
                    page_metadata,
                    &[],
                );
            }
            IgvmDirectiveHeader::X64VbsVpContext {
                vtl,
                registers,
                compatibility_mask: _,
            } => {
                // The VBS measurement format requires the cpu context to be
                // measured last; collect now and apply at the end.
                let vtl_registers: Vec<VbsVpContextRegister> = registers
                    .iter()
                    .map(|r| r.into_vbs_vp_context_reg(*vtl))
                    .collect();
                bsp_regs.push(vtl_registers);
            }
            IgvmDirectiveHeader::AArch64VbsVpContext {
                vtl,
                registers,
                compatibility_mask: _,
            } => {
                // The VBS measurement format requires the cpu context to be
                // measured last; collect now and apply at the end.
                let vtl_registers: Vec<VbsVpContextRegister> = registers
                    .iter()
                    .map(|r| r.into_vbs_vp_context_reg(*vtl))
                    .collect();
                bsp_regs.push(vtl_registers);
            }
            IgvmDirectiveHeader::ErrorRange {
                gpa,
                compatibility_mask: _,
                size_bytes,
            } => {
                let page_metadata = VBS_VM_GPA_PAGE_BOOT_METADATA::new()
                    .with_acceptance(VM_GPA_PAGE_READABLE | VM_GPA_PAGE_WRITABLE)
                    .with_data_unmeasured(true);
                digest.record_gpa_page(
                    *gpa / PAGE_SIZE_4K,
                    (*size_bytes as u64).div_ceil(PAGE_SIZE_4K),
                    page_metadata,
                    &[],
                );
            }
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index,
                initial_data: _,
            } => {
                if parameter_area_table.contains_key(parameter_area_index) {
                    return Err(MeasurementError::InvalidParameterAreaIndex(
                        *parameter_area_index,
                    ));
                }
                parameter_area_table.insert(*parameter_area_index, *number_of_bytes);
            }
            _ => {}
        }
    }

    // Measure all registers in each VTL as last step in measurement.
    for set in bsp_regs {
        for reg in set {
            digest.record_vp_register(reg);
        }
    }

    Ok(digest.finish_digest())
}

struct VbsDigestor {
    digest: [u8; SHA_256_OUTPUT_SIZE],
}

impl VbsDigestor {
    fn new() -> Self {
        Self {
            digest: [0; SHA_256_OUTPUT_SIZE],
        }
    }

    fn record_gpa_page(
        &mut self,
        gpa_page_base: u64,
        page_count: u64,
        page_metadata: VBS_VM_GPA_PAGE_BOOT_METADATA,
        mut data: &[u8],
    ) {
        for page in 0..page_count {
            let import_data_len: usize = match page_metadata.data_unmeasured() {
                true => 0,
                false => std::cmp::min(PAGE_SIZE_4K_USIZE, data.len()),
            };
            let (import_data, data_remaining) = data.split_at(import_data_len);
            data = data_remaining;

            // If page is under 4K bytes, pad to full length which will be
            // hashed with page and chunk data.
            let padding = vec![0u8; PAGE_SIZE_4K_USIZE - import_data.len()];
            let page_number = gpa_page_base + page;
            let chunk = VpGpaPageChunk {
                header: VbsChunkHeader {
                    byte_count: VBS_VP_CHUNK_SIZE_BYTES as u32,
                    chunk_type: BootMeasurementType::VP_GPA_PAGE,
                    reserved: 0,
                },
                metadata: page_metadata.into(),
                page_number,
            };
            self.create_record_entry(&[chunk.as_bytes(), import_data, &padding]);
        }
    }

    fn record_vp_register(&mut self, reg: VbsVpContextRegister) {
        let chunk = VbsRegisterChunk {
            header: VbsChunkHeader {
                byte_count: size_of::<VbsRegisterChunk>() as u32,
                chunk_type: BootMeasurementType::VP_REGISTER,
                reserved: 0,
            },
            reserved: 0,
            vtl: reg.vtl,
            reserved2: 0,
            reserved3: 0,
            reserved4: 0,
            name: reg.register_name.into(),
            value: reg.register_value,
        };
        self.create_record_entry(&[chunk.as_bytes()]);
    }

    fn create_record_entry(&mut self, chunks: &[&[u8]]) {
        let mut hasher = Sha256::new();
        hasher.update(self.digest.as_slice());
        for chunk in chunks {
            hasher.update(chunk);
        }
        self.digest = hasher.finalize().into();
    }

    fn finish_digest(&self) -> [u8; SHA_256_OUTPUT_SIZE] {
        self.digest
    }
}
