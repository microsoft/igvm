// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Launch measurement CoRIM profile.
//!
//! This module implements the IGVM launch measurement CoRIM profile
//! (`tag:microsoft.com,2026:launch-measurement/v1`), which produces
//! CoRIM documents containing a launch measurement reference value and
//! an SVN endorsement for supported CVM platforms.
//!
//! # Two-stage builder
//!
//! The user-facing API is a two-stage builder:
//!
//! 1. **Stage 1 -- populate measurements.** Construct a [`LaunchMeasurement`]
//!    via [`LaunchMeasurement::for_platform`], then mark each profile-defined
//!    measurement as populated via
//!    [`set_measurement`](LaunchMeasurement::set_measurement). The digest
//!    bytes are taken from the IGVM file's auto-computed launch measurement
//!    at serialization time. Every populated measurement becomes a
//!    reference-value in the CoRIM.
//!
//! 2. **Stage 2 -- define endorsement policy.** Call
//!    [`endorse`](LaunchMeasurement::endorse) to start a [`CesTripleBuilder`]
//!    for a given SVN, then select which populated measurements participate
//!    in the CES triple via [`with`](CesTripleBuilder::with). Finalize with
//!    [`finish`](CesTripleBuilder::finish) to obtain a [`CesTriple`].
//!
//! Finally, call [`build`](LaunchMeasurement::build) to consume the
//! endorsement and produce a [`CorimTemplate`](crate::CorimTemplate) ready
//! for [`IgvmSerializer::add_corim`](crate::IgvmSerializer::add_corim).
//!
//! # Future: caller-supplied digests
//!
//! When future CoRIM profiles need caller-supplied digest bytes (e.g., for
//! TDX RTMRs or runtime-extended measurements), a `DigestSource`-like type
//! should be introduced at the [`crate::corim`] module level so it can be
//! shared across profiles, rather than re-introduced here.

pub(crate) mod builder;
pub mod profile;

use std::collections::HashSet;

pub use igvm_defs::IgvmPlatformType;

use crate::CorimTemplate;

/// Fixed namespace UUID for deterministic CoMID tag-id derivation.
///
/// `tag-id = UUIDv5(TAG_ID_NAMESPACE, "{vendor}/{model}")`
pub const TAG_ID_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([
    0x85, 0xf3, 0xf1, 0xc2, 0x22, 0xa8, 0x44, 0x1e, 0xa1, 0xb9, 0xbc, 0xcf, 0xb6, 0x3e, 0xd5, 0xf7,
]);

// -- Profile catalog ----------------------------------------------------

/// Internal record describing a platform's profile-defined measurement layout.
pub(crate) struct PlatformInfo {
    pub vendor: &'static str,
    pub model: &'static str,
    pub mkey: &'static str,
    pub digest_alg: i64,
    pub digest_len: usize,
}

/// Named Information Hash Algorithm ID for SHA-256 (RFC 6920).
const NI_SHA256: i64 = 1;
/// Named Information Hash Algorithm ID for SHA-384 (RFC 6920).
const NI_SHA384: i64 = 7;

/// Canonical list of supported platforms.
pub(crate) fn known_platforms() -> &'static [PlatformInfo] {
    &[
        PlatformInfo {
            vendor: "Intel",
            model: "TDX",
            mkey: "MRTD",
            digest_alg: NI_SHA384,
            digest_len: 48,
        },
        PlatformInfo {
            vendor: "AMD",
            model: "SEV-SNP",
            mkey: "MEASUREMENT",
            digest_alg: NI_SHA384,
            digest_len: 48,
        },
        PlatformInfo {
            vendor: "Microsoft",
            model: "VBS",
            mkey: "MEASUREMENT",
            digest_alg: NI_SHA256,
            digest_len: 32,
        },
    ]
}

fn platform_info(platform: IgvmPlatformType) -> Option<&'static PlatformInfo> {
    let (vendor, model) = match platform {
        IgvmPlatformType::TDX => ("Intel", "TDX"),
        IgvmPlatformType::SEV_SNP => ("AMD", "SEV-SNP"),
        IgvmPlatformType::VSM_ISOLATION => ("Microsoft", "VBS"),
        _ => return None,
    };
    known_platforms()
        .iter()
        .find(|p| p.vendor == vendor && p.model == model)
}

/// Look up the `(mkey, digest_alg, digest_len)` tuple for a profile-defined
/// measurement on the given platform.
///
/// Returns `None` if the platform is not supported by this profile, or if
/// the measurement kind has no mapping for that platform.
pub fn measurement_info(
    platform: IgvmPlatformType,
    kind: MeasurementKind,
) -> Option<(&'static str, i64, usize)> {
    let info = platform_info(platform)?;
    match kind {
        MeasurementKind::Launch => Some((info.mkey, info.digest_alg, info.digest_len)),
    }
}

// -- Public types -------------------------------------------------------

/// Identifies a profile-defined measurement.
///
/// The exact CBOR `mkey` text and hash algorithm are determined by the
/// profile and the target platform. Today only [`Self::Launch`] is
/// supported; future variants (e.g., `Rtmr(u8)` for TDX) can be added
/// without breaking existing callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum MeasurementKind {
    /// The platform's primary launch measurement.
    ///
    /// - **TDX**: MRTD (SHA-384)
    /// - **SEV-SNP**: launch digest (SHA-384)
    /// - **VBS**: boot measurement digest (SHA-256)
    Launch,
}

/// Errors from launch measurement CoRIM generation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The platform type is not supported for CoRIM launch measurements.
    #[error(
        "unsupported platform type {0:?}: only SEV_SNP, TDX, and \
         VSM_ISOLATION are supported for CoRIM launch measurements"
    )]
    UnsupportedPlatform(IgvmPlatformType),
    /// The measurement kind is not defined for this platform.
    #[error("measurement {kind:?} is not defined for platform {platform:?}")]
    UnsupportedMeasurement {
        /// The platform that was queried.
        platform: IgvmPlatformType,
        /// The measurement kind that was rejected.
        kind: MeasurementKind,
    },
    /// A CES triple referenced a measurement that was not populated in
    /// stage 1 (via [`LaunchMeasurement::set_measurement`]).
    #[error(
        "measurement {kind:?} is not populated; call \
         LaunchMeasurement::set_measurement first"
    )]
    MeasurementNotPopulated {
        /// The kind that was referenced but not populated.
        kind: MeasurementKind,
    },
    /// The same measurement kind was selected twice in a single CES triple.
    #[error("measurement {kind:?} already selected in this CES triple")]
    DuplicateSelection {
        /// The duplicated kind.
        kind: MeasurementKind,
    },
    /// A CES triple was finalized with an empty selection.
    #[error("CES triple must select at least one measurement")]
    EmptySelection,
    /// CoRIM building or encoding failed.
    #[error("CoRIM build failed")]
    Build(#[source] Box<dyn std::error::Error + Send + Sync>),
}

// -- Stage 1: LaunchMeasurement -----------------------------------------

/// Profile-driven endorsement under construction.
///
/// Constructed via [`for_platform`](Self::for_platform). Populate
/// measurements with [`set_measurement`](Self::set_measurement), then
/// build CES triples via [`endorse`](Self::endorse). Finalize with
/// [`build`](Self::build) to produce a [`CorimTemplate`].
#[derive(Debug, Clone)]
pub struct LaunchMeasurement {
    platform: IgvmPlatformType,
    measurements: HashSet<MeasurementKind>,
    triples: Vec<CesTriple>,
}

impl LaunchMeasurement {
    /// Start a new launch measurement endorsement for the given platform.
    ///
    /// Returns [`Error::UnsupportedPlatform`] if the platform is not one
    /// the profile supports.
    pub fn for_platform(platform: IgvmPlatformType) -> Result<Self, Error> {
        if platform_info(platform).is_none() {
            return Err(Error::UnsupportedPlatform(platform));
        }
        Ok(Self {
            platform,
            measurements: HashSet::new(),
            triples: Vec::new(),
        })
    }

    /// The platform this endorsement targets.
    pub fn platform(&self) -> IgvmPlatformType {
        self.platform
    }

    /// Mark a profile-defined measurement as populated.
    ///
    /// Each call is idempotent for the same `kind`. All populated
    /// measurements are emitted as reference-values in the final CoRIM
    /// document, with digest bytes taken from the IGVM file's
    /// auto-computed launch measurement at serialization time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedMeasurement`] if `kind` is not defined
    /// for the platform.
    pub fn set_measurement(&mut self, kind: MeasurementKind) -> Result<&mut Self, Error> {
        if measurement_info(self.platform, kind).is_none() {
            return Err(Error::UnsupportedMeasurement {
                platform: self.platform,
                kind,
            });
        }
        self.measurements.insert(kind);
        Ok(self)
    }

    /// Returns the measurement kinds populated so far.
    pub fn populated_measurements(&self) -> impl Iterator<Item = MeasurementKind> + '_ {
        self.measurements.iter().copied()
    }

    /// Returns `true` if `kind` has been populated.
    pub fn is_populated(&self, kind: MeasurementKind) -> bool {
        self.measurements.contains(&kind)
    }

    /// Start a Stage-2 CES triple builder that endorses `svn` when its
    /// selected measurements all match.
    pub fn endorse(&mut self, svn: u64) -> CesTripleBuilder<'_> {
        CesTripleBuilder {
            endorsement: self,
            svn,
            selected: Vec::new(),
        }
    }

    /// Returns the CES triples accumulated so far.
    pub fn triples(&self) -> &[CesTriple] {
        &self.triples
    }

    /// Consume this endorsement and wrap it in a [`CorimTemplate`] ready
    /// for [`IgvmSerializer::add_corim`](crate::IgvmSerializer::add_corim).
    pub fn build(self) -> CorimTemplate {
        CorimTemplate::LaunchMeasurement(self)
    }

    /// Private accessor used by the serializer to enumerate populated
    /// measurement kinds.
    pub(crate) fn measurement_kinds(&self) -> &HashSet<MeasurementKind> {
        &self.measurements
    }
}

// -- Stage 2: CesTripleBuilder ------------------------------------------

/// Builder for a single conditional-endorsement-series triple.
///
/// Created by [`LaunchMeasurement::endorse`]. The lifetime ties the
/// builder to its parent endorsement so that [`with`](Self::with) can
/// validate selected measurements against the populated catalog.
#[derive(Debug)]
pub struct CesTripleBuilder<'a> {
    endorsement: &'a mut LaunchMeasurement,
    svn: u64,
    selected: Vec<MeasurementKind>,
}

impl CesTripleBuilder<'_> {
    /// Add a populated measurement to this CES triple's selection.
    ///
    /// # Errors
    ///
    /// - [`Error::MeasurementNotPopulated`] if `kind` was not populated
    ///   in stage 1 via [`LaunchMeasurement::set_measurement`].
    /// - [`Error::DuplicateSelection`] if `kind` is already in this
    ///   triple's selection.
    pub fn with(mut self, kind: MeasurementKind) -> Result<Self, Error> {
        if !self.endorsement.measurements.contains(&kind) {
            return Err(Error::MeasurementNotPopulated { kind });
        }
        if self.selected.contains(&kind) {
            return Err(Error::DuplicateSelection { kind });
        }
        self.selected.push(kind);
        Ok(self)
    }

    /// Finalize this CES triple and append it to the parent endorsement.
    ///
    /// Returns [`Error::EmptySelection`] if no measurements were selected.
    pub fn finish(self) -> Result<(), Error> {
        if self.selected.is_empty() {
            return Err(Error::EmptySelection);
        }
        self.endorsement.triples.push(CesTriple {
            svn: self.svn,
            selected: self.selected,
        });
        Ok(())
    }
}

// -- Finalized CES triple record ----------------------------------------

/// A finalized conditional-endorsement-series triple.
///
/// Produced by [`CesTripleBuilder::finish`] and owned by its parent
/// [`LaunchMeasurement`].
#[derive(Debug, Clone)]
pub struct CesTriple {
    svn: u64,
    selected: Vec<MeasurementKind>,
}

impl CesTriple {
    /// The SVN this triple endorses.
    pub fn svn(&self) -> u64 {
        self.svn
    }

    /// The measurement kinds selected for this CES triple, in the order
    /// they were added.
    pub fn selected_measurements(&self) -> &[MeasurementKind] {
        &self.selected
    }
}
