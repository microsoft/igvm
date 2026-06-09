// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Launch measurement calculation for CVM platforms.
//!
//! Computes platform-specific launch digests from an IGVM file's headers,
//! matching the measurement algorithms used by the hardware/firmware:
//!
//! - **AMD SEV-SNP**: Iterates page data, chaining SHA-384 hashes through
//!   `SnpPageInfo` structures per the AMD SEV-SNP firmware ABI.
//! - **Intel TDX**: Computes MRTD by hashing `MEM.PAGE.ADD` and `MR.EXTEND`
//!   operations per the Intel TDX module specification.
//! - **Microsoft VBS**: Computes a SHA-256 boot measurement digest by hashing
//!   page chunks and VP register state per the VBS measurement protocol.

mod snp;
mod tdx;
mod vbs;

pub use snp::generate_snp_measurement;
pub use tdx::generate_tdx_measurement;
pub use vbs::generate_vbs_measurement;

pub(crate) const SHA_256_OUTPUT_SIZE: usize = 32;
pub(crate) const SHA_384_OUTPUT_SIZE: usize = 48;

/// Errors from measurement calculation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MeasurementError {
    /// A parameter area index referenced by a ParameterInsert was not found.
    #[error("invalid parameter area index {0}")]
    InvalidParameterAreaIndex(u32),
    /// No guest policy found in initialization headers (SNP only).
    #[error("no SNP guest policy found in initialization headers")]
    MissingGuestPolicy,
    /// Page data larger than 4K is not supported.
    #[error("unsupported page data size: {0} bytes")]
    UnsupportedPageSize(usize),
}
