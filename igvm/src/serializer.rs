// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! IGVM file serializer with support for computing launch measurements
//! and attaching CoRIM documents before writing to binary format.
//!
//! [`IgvmSerializer`] borrows an immutable [`IgvmFile`] and provides a
//! builder-style API for enriching the output with per-platform launch
//! measurements and CoRIM documents, without mutating the original file.
//!
//! # Example
//!
//! ```rust,no_run
//! use igvm::corim::launch_measurement::LaunchMeasurement;
//! use igvm::corim::launch_measurement::MeasurementKind;
//! use igvm::IgvmFile;
//! use igvm::IgvmSerializer;
//! use igvm_defs::IgvmPlatformType;
//!
//! # fn example(file: &IgvmFile) -> Result<(), igvm::Error> {
//! // Construction eagerly computes the launch measurement for every
//! // measurable platform header in the file.
//! let mut serializer = IgvmSerializer::new(file)?;
//!
//! // Inspect the SNP measurement (already cached from `new`).
//! if let Some(m) = serializer.measurement_for(IgvmPlatformType::SEV_SNP) {
//!     println!("SNP digest: {}", hex::encode(&m.digest));
//! }
//!
//! // Stage 1: populate the launch measurement.
//! let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::SEV_SNP)?;
//! le.set_measurement(MeasurementKind::Launch)?;
//!
//! // Stage 2: build a CES triple that endorses SVN 1 when the launch
//! //          measurement matches.
//! le.endorse(1).with(MeasurementKind::Launch)?.finish()?;
//!
//! serializer.add_corim(IgvmPlatformType::SEV_SNP, le.build())?;
//!
//! // Serialize to binary
//! let mut output = Vec::new();
//! serializer.serialize(&mut output)?;
//! # Ok(())
//! # }
//! ```

use crate::CorimTemplate;
use crate::Error;
use crate::IgvmFile;
use crate::IgvmInitializationHeader;
use crate::IgvmPlatformHeader;
use igvm_defs::IgvmPlatformType;

/// A per-platform launch measurement computed from an IGVM file's headers.
#[derive(Debug, Clone)]
pub struct IgvmPlatformMeasurement {
    /// The platform type this measurement was computed for.
    pub platform: IgvmPlatformType,
    /// The compatibility mask associated with this platform.
    pub compatibility_mask: u32,
    /// The raw launch measurement digest bytes.
    ///
    /// Length depends on the platform:
    /// - SEV-SNP: 48 bytes (SHA-384)
    /// - TDX: 48 bytes (SHA-384)
    /// - VBS: 32 bytes (SHA-256)
    pub digest: Vec<u8>,
}

/// Serializer that borrows an [`IgvmFile`] and enriches the output with
/// computed measurements and CoRIM documents.
///
/// The underlying [`IgvmFile`] is never mutated. Additional initialization
/// headers (CoRIM documents) are accumulated in the serializer and merged
/// into the output during [`serialize`](IgvmSerializer::serialize).
#[derive(Debug)]
pub struct IgvmSerializer<'a> {
    file: &'a IgvmFile,
    measurements: Vec<IgvmPlatformMeasurement>,
    extra_init_headers: Vec<IgvmInitializationHeader>,
}

impl<'a> IgvmSerializer<'a> {
    /// Create a new serializer for the given IGVM file.
    ///
    /// During construction, the launch measurement is computed for every
    /// platform header in the file whose platform type has a measurement
    /// profile defined by this crate (currently SEV-SNP, TDX, and VBS).
    /// Platform headers with no measurement profile (e.g.,
    /// [`IgvmPlatformType::NATIVE`], [`IgvmPlatformType::SEV`],
    /// [`IgvmPlatformType::SEV_ES`]) are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MeasurementFailed`] if measurement computation
    /// fails for any of the file's measurable platforms (e.g., SEV-SNP
    /// without a [`IgvmInitializationHeader::GuestPolicy`] header).
    pub fn new(file: &'a IgvmFile) -> Result<Self, Error> {
        let mut serializer = Self {
            file,
            measurements: Vec::new(),
            extra_init_headers: Vec::new(),
        };

        // Eagerly compute the launch measurement for every supported
        // platform present in the file.
        let platforms: Vec<IgvmPlatformType> = file
            .platforms()
            .iter()
            .filter_map(|h| match h {
                IgvmPlatformHeader::SupportedPlatform(info)
                    if Self::is_measurable(info.platform_type) =>
                {
                    Some(info.platform_type)
                }
                _ => None,
            })
            .collect();
        for platform in platforms {
            serializer.compute_measurement(platform)?;
        }

        Ok(serializer)
    }

    /// Returns `true` if this crate's measurement profile knows how to
    /// hash an IGVM file for the given platform type.
    fn is_measurable(platform: IgvmPlatformType) -> bool {
        matches!(
            platform,
            IgvmPlatformType::SEV_SNP | IgvmPlatformType::TDX | IgvmPlatformType::VSM_ISOLATION
        )
    }

    /// Get a reference to the underlying IGVM file.
    pub fn file(&self) -> &IgvmFile {
        self.file
    }

    /// Get all launch measurements computed for this file.
    ///
    /// One entry is present for every measurable platform header in the
    /// file (see [`new`](Self::new)).
    pub fn measurements(&self) -> &[IgvmPlatformMeasurement] {
        &self.measurements
    }

    /// Get the launch measurement for a specific platform, if the file
    /// has a corresponding measurable platform header.
    pub fn measurement_for(&self, platform: IgvmPlatformType) -> Option<&IgvmPlatformMeasurement> {
        self.measurements.iter().find(|m| m.platform == platform)
    }

    /// Get the raw CoRIM document bytes attached for the given platform,
    /// if one was previously added via [`add_corim`](Self::add_corim).
    ///
    /// Returns `None` if the file has no platform header for `platform`,
    /// or if no CoRIM has been attached for it yet.
    #[cfg(feature = "corim")]
    #[cfg_attr(docsrs, doc(cfg(feature = "corim")))]
    pub fn corim_for(&self, platform: IgvmPlatformType) -> Option<&[u8]> {
        let compatibility_mask = self.lookup_compatibility_mask(platform).ok()?;
        self.extra_init_headers.iter().find_map(|h| match h {
            IgvmInitializationHeader::CorimDocument {
                compatibility_mask: mask,
                document,
            } if *mask == compatibility_mask => Some(document.as_slice()),
            _ => None,
        })
    }

    /// Look up the compatibility mask for a platform type from the file's
    /// platform headers.
    fn lookup_compatibility_mask(&self, platform: IgvmPlatformType) -> Result<u32, Error> {
        self.file
            .platforms()
            .iter()
            .find_map(|h| match h {
                IgvmPlatformHeader::SupportedPlatform(info) if info.platform_type == platform => {
                    Some(info.compatibility_mask)
                }
                _ => None,
            })
            .ok_or_else(|| {
                Error::MeasurementFailed(format!("no platform header found for {platform:?}"))
            })
    }

    /// Internal: compute the launch measurement for a specific platform
    /// and append it to the cache. Called eagerly from
    /// [`new`](Self::new) for every measurable platform header.
    #[cfg(feature = "corim")]
    fn compute_measurement(&mut self, platform: IgvmPlatformType) -> Result<(), Error> {
        debug_assert!(
            !self.measurements.iter().any(|m| m.platform == platform),
            "compute_measurement called twice for {platform:?}"
        );

        let compatibility_mask = self.lookup_compatibility_mask(platform)?;

        let digest = match platform {
            IgvmPlatformType::SEV_SNP => crate::measurement::generate_snp_measurement(
                self.file.initializations(),
                self.file.directives(),
                compatibility_mask,
            )
            .map_err(|e| Error::MeasurementFailed(e.to_string()))?
            .to_vec(),
            IgvmPlatformType::TDX => crate::measurement::generate_tdx_measurement(
                self.file.directives(),
                compatibility_mask,
            )
            .map_err(|e| Error::MeasurementFailed(e.to_string()))?
            .to_vec(),
            IgvmPlatformType::VSM_ISOLATION => crate::measurement::generate_vbs_measurement(
                self.file.directives(),
                compatibility_mask,
            )
            .map_err(|e| Error::MeasurementFailed(e.to_string()))?
            .to_vec(),
            _ => {
                return Err(Error::MeasurementFailed(format!(
                    "unsupported platform type for measurement: {platform:?}"
                )))
            }
        };

        self.measurements.push(IgvmPlatformMeasurement {
            platform,
            compatibility_mask,
            digest,
        });

        Ok(())
    }

    /// Attach a CoRIM endorsement for the given platform.
    ///
    /// The generated CoRIM document will be included as an
    /// [`IgvmInitializationHeader::CorimDocument`] in the serialized output.
    /// On success, the raw CoRIM bytes that were attached are returned.
    ///
    /// For [`CorimTemplate::LaunchMeasurement`], populated measurements
    /// take their digest bytes from the launch measurement computed at
    /// construction time (see [`new`](Self::new)).
    ///
    /// # Arguments
    ///
    /// * `platform` -- The target platform type. Must match a platform header
    ///   in the file, and must match the platform of the
    ///   [`LaunchMeasurement`](crate::corim::launch_measurement::LaunchMeasurement)
    ///   in the template.
    /// * `template` -- The CoRIM template to instantiate. See
    ///   [`CorimTemplate`] for the supported variants.
    #[cfg(feature = "corim")]
    #[cfg_attr(docsrs, doc(cfg(feature = "corim")))]
    pub fn add_corim(
        &mut self,
        platform: IgvmPlatformType,
        template: CorimTemplate,
    ) -> Result<&[u8], Error> {
        let compatibility_mask = self.lookup_compatibility_mask(platform)?;

        let corim_bytes = match template {
            CorimTemplate::LaunchMeasurement(le) => {
                if le.platform() != platform {
                    return Err(Error::CorimGeneration(format!(
                        "LaunchMeasurement targets {:?} but add_corim was \
                         called with {platform:?}",
                        le.platform()
                    )));
                }

                self.build_launch_measurement_corim(le)?
            }
            CorimTemplate::Architectural => {
                return Err(Error::CorimGeneration(
                    "Architectural CoRIM template is not yet implemented".into(),
                ));
            }
            CorimTemplate::Custom(_) => {
                return Err(Error::CorimGeneration(
                    "Custom CoRIM template is not yet implemented".into(),
                ));
            }
        };

        self.extra_init_headers
            .push(IgvmInitializationHeader::CorimDocument {
                compatibility_mask,
                document: corim_bytes,
            });

        match self.extra_init_headers.last() {
            Some(IgvmInitializationHeader::CorimDocument { document, .. }) => Ok(document),
            _ => unreachable!("just pushed a CorimDocument"),
        }
    }

    /// Resolve a [`LaunchMeasurement`]'s populated measurements and CES
    /// triples into the internal builder form, then build the CoRIM bytes.
    #[cfg(feature = "corim")]
    fn build_launch_measurement_corim(
        &self,
        le: crate::corim::launch_measurement::LaunchMeasurement,
    ) -> Result<Vec<u8>, Error> {
        use crate::corim::launch_measurement::builder::ResolvedMeasurement;
        use crate::corim::launch_measurement::measurement_info;

        let platform = le.platform();
        // The measurement was computed eagerly during `IgvmSerializer::new`
        // for every measurable platform header in the file. The caller of
        // `add_corim` already validated `le.platform() == platform`, and
        // `LaunchMeasurement::for_platform` only succeeds for measurable
        // platforms -- so the measurement must be present.
        let cached = self.measurement_for(platform).ok_or_else(|| {
            Error::CorimGeneration(format!("no platform header found for {platform:?}"))
        })?;

        // The current launch-measurement builder emits exactly one
        // reference value and one CES triple, all bound to the same
        // measurement. Enforce that shape here rather than silently
        // picking one entry from `measurement_kinds()` (a `HashSet` with
        // unspecified iteration order).
        if le.measurement_kinds().len() != 1 {
            return Err(Error::CorimGeneration(format!(
                "LaunchMeasurement requires exactly one populated measurement, got {}",
                le.measurement_kinds().len()
            )));
        }
        let kind = *le
            .measurement_kinds()
            .iter()
            .next()
            .expect("checked len == 1 above");

        if le.triples().len() != 1 {
            return Err(Error::CorimGeneration(format!(
                "LaunchMeasurement requires exactly one CES triple, got {}",
                le.triples().len()
            )));
        }
        let triple = &le.triples()[0];

        if triple.selected_measurements() != [kind] {
            return Err(Error::CorimGeneration(format!(
                "CES triple selection {:?} does not match the populated \
                 measurement {kind:?}",
                triple.selected_measurements()
            )));
        }

        let (mkey, digest_alg, _len) =
            measurement_info(platform, kind).expect("kind validated by set_measurement");
        let resolved = ResolvedMeasurement {
            mkey: mkey.to_string(),
            digest_alg,
            digest: cached.digest.clone(),
        };

        crate::corim::launch_measurement::builder::build_corim_bytes(
            platform,
            &resolved,
            triple.svn(),
        )
        .map_err(|e| Error::CorimGeneration(e.to_string()))
    }

    /// Serialize the IGVM file to binary format, including any CoRIM
    /// documents that were added via [`add_corim`](Self::add_corim).
    ///
    /// This produces the same binary format as [`IgvmFile::serialize`],
    /// but with additional initialization headers appended.
    pub fn serialize(&self, output: &mut Vec<u8>) -> Result<(), Error> {
        if self.extra_init_headers.is_empty() {
            // Fast path: nothing added, delegate directly.
            self.file.serialize(output)
        } else {
            // Clone the file and append the extra init headers so that
            // the original IgvmFile::serialize handles all the work.
            let mut file = self.file.clone();
            file.initializations_mut()
                .extend(self.extra_init_headers.iter().cloned());
            file.serialize(output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hv_defs::Vtl;
    use crate::registers::X86Register;
    use crate::Arch;
    use crate::CorimTemplate;
    use crate::IgvmInitializationHeader;
    use crate::IgvmPlatformHeader;
    use crate::IgvmRevision;
    use igvm_defs::IgvmPageDataFlags;
    use igvm_defs::IgvmPageDataType;
    use igvm_defs::IgvmPlatformType;
    use igvm_defs::IGVM_VHS_SUPPORTED_PLATFORM;
    use igvm_defs::PAGE_SIZE_4K;

    fn new_platform(mask: u32, platform_type: IgvmPlatformType) -> IgvmPlatformHeader {
        IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
            compatibility_mask: mask,
            highest_vtl: 0,
            platform_type,
            platform_version: 1,
            shared_gpa_boundary: 0,
        })
    }

    fn new_page_data(page: u64, mask: u32, data: &[u8]) -> crate::IgvmDirectiveHeader {
        crate::IgvmDirectiveHeader::PageData {
            gpa: page * PAGE_SIZE_4K,
            compatibility_mask: mask,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: data.to_vec(),
        }
    }

    /// Build a minimal VBS IgvmFile with some page data and VP context.
    fn make_vbs_file() -> IgvmFile {
        IgvmFile::new(
            IgvmRevision::V2 {
                arch: Arch::X64,
                page_size: PAGE_SIZE_4K as u32,
            },
            vec![new_platform(0x1, IgvmPlatformType::VSM_ISOLATION)],
            vec![],
            vec![
                new_page_data(0, 1, &[0xAA; PAGE_SIZE_4K as usize]),
                new_page_data(1, 1, &[0xBB; PAGE_SIZE_4K as usize]),
                crate::IgvmDirectiveHeader::X64VbsVpContext {
                    vtl: Vtl::Vtl0,
                    registers: vec![X86Register::Rip(0x1000)],
                    compatibility_mask: 0x1,
                },
            ],
        )
        .unwrap()
    }

    /// Build a minimal SNP IgvmFile with a guest policy and page data.
    fn make_snp_file() -> IgvmFile {
        IgvmFile::new(
            IgvmRevision::V1,
            vec![new_platform(0x1, IgvmPlatformType::SEV_SNP)],
            vec![IgvmInitializationHeader::GuestPolicy {
                policy: 0x30000,
                compatibility_mask: 0x1,
            }],
            vec![
                new_page_data(0, 1, &[0xCC; PAGE_SIZE_4K as usize]),
                new_page_data(1, 1, &[0xDD; PAGE_SIZE_4K as usize]),
            ],
        )
        .unwrap()
    }

    /// Build a minimal TDX IgvmFile with page data.
    fn make_tdx_file() -> IgvmFile {
        IgvmFile::new(
            IgvmRevision::V1,
            vec![new_platform(0x1, IgvmPlatformType::TDX)],
            vec![],
            vec![
                new_page_data(0, 1, &[0xEE; PAGE_SIZE_4K as usize]),
                new_page_data(1, 1, &[0xFF; PAGE_SIZE_4K as usize]),
            ],
        )
        .unwrap()
    }

    // -- Basic serializer tests --------------------------------------

    #[test]
    fn serialize_without_corim_matches_file_serialize() {
        let file = make_vbs_file();

        // Serialize via IgvmFile::serialize
        let mut direct = Vec::new();
        file.serialize(&mut direct).unwrap();

        // Serialize via IgvmSerializer (no CoRIM added)
        let serializer = IgvmSerializer::new(&file).unwrap();
        let mut via_builder = Vec::new();
        serializer.serialize(&mut via_builder).unwrap();

        assert_eq!(direct, via_builder);
    }

    #[test]
    fn serialize_without_corim_roundtrips() {
        let file = make_snp_file();

        let serializer = IgvmSerializer::new(&file).unwrap();
        let mut output = Vec::new();
        serializer.serialize(&mut output).unwrap();

        let deserialized = IgvmFile::new_from_binary(&output, None).unwrap();
        assert_eq!(file.platforms(), deserialized.platforms());
        assert_eq!(file.directives().len(), deserialized.directives().len());
    }

    // -- Measurement tests -------------------------------------------

    #[test]
    fn vbs_measurement_computed_eagerly() {
        let file = make_vbs_file();
        let serializer = IgvmSerializer::new(&file).unwrap();

        let m = serializer
            .measurement_for(IgvmPlatformType::VSM_ISOLATION)
            .expect("VBS measurement should be computed eagerly");
        assert_eq!(m.platform, IgvmPlatformType::VSM_ISOLATION);
        assert_eq!(m.compatibility_mask, 0x1);
        assert_eq!(m.digest.len(), 32); // SHA-256
    }

    #[test]
    fn snp_measurement_computed_eagerly() {
        let file = make_snp_file();
        let serializer = IgvmSerializer::new(&file).unwrap();

        let m = serializer
            .measurement_for(IgvmPlatformType::SEV_SNP)
            .expect("SNP measurement should be computed eagerly");
        assert_eq!(m.platform, IgvmPlatformType::SEV_SNP);
        assert_eq!(m.digest.len(), 48); // SHA-384
    }

    #[test]
    fn tdx_measurement_computed_eagerly() {
        let file = make_tdx_file();
        let serializer = IgvmSerializer::new(&file).unwrap();

        let m = serializer
            .measurement_for(IgvmPlatformType::TDX)
            .expect("TDX measurement should be computed eagerly");
        assert_eq!(m.platform, IgvmPlatformType::TDX);
        assert_eq!(m.digest.len(), 48); // SHA-384
    }

    #[test]
    fn measurement_for_returns_none_for_absent_platform() {
        // File has SNP only; querying TDX should return None.
        let file = make_snp_file();
        let serializer = IgvmSerializer::new(&file).unwrap();
        assert!(serializer.measurement_for(IgvmPlatformType::TDX).is_none());
    }

    #[test]
    fn unmeasurable_platform_skipped() {
        // NATIVE has no measurement profile in this crate. A file containing
        // only a NATIVE platform header should construct cleanly with an
        // empty measurements list.
        let file = IgvmFile::new(
            IgvmRevision::V1,
            vec![new_platform(0x1, IgvmPlatformType::NATIVE)],
            vec![],
            vec![new_page_data(0, 1, &[0xAA; PAGE_SIZE_4K as usize])],
        )
        .unwrap();
        let serializer = IgvmSerializer::new(&file).unwrap();
        assert!(serializer.measurements().is_empty());
        assert!(serializer
            .measurement_for(IgvmPlatformType::NATIVE)
            .is_none());
    }

    #[test]
    fn snp_missing_guest_policy_fails_construction() {
        // SNP measurement requires a GuestPolicy initialization header.
        // Build a file without one and verify `IgvmSerializer::new` fails.
        let file = IgvmFile::new(
            IgvmRevision::V1,
            vec![new_platform(0x1, IgvmPlatformType::SEV_SNP)],
            vec![], // no GuestPolicy
            vec![new_page_data(0, 1, &[0xAA; PAGE_SIZE_4K as usize])],
        )
        .unwrap();
        let err = IgvmSerializer::new(&file).unwrap_err();
        assert!(matches!(err, Error::MeasurementFailed(_)), "got: {err:?}");
    }

    // -- CoRIM integration tests -------------------------------------

    /// Helper: build a `CorimTemplate::LaunchMeasurement` with a single
    /// CES triple binding the launch measurement -> svn.
    fn launch_measurement_template(platform: IgvmPlatformType, svn: u64) -> CorimTemplate {
        use crate::corim::launch_measurement::LaunchMeasurement;
        use crate::corim::launch_measurement::MeasurementKind;
        let mut le = LaunchMeasurement::for_platform(platform).unwrap();
        le.set_measurement(MeasurementKind::Launch).unwrap();
        le.endorse(svn)
            .with(MeasurementKind::Launch)
            .unwrap()
            .finish()
            .unwrap();
        le.build()
    }

    #[test]
    fn add_corim_produces_larger_output() {
        let file = make_snp_file();

        // Serialize without CoRIM
        let mut without = Vec::new();
        file.serialize(&mut without).unwrap();

        // Serialize with CoRIM
        let mut serializer = IgvmSerializer::new(&file).unwrap();
        serializer
            .add_corim(
                IgvmPlatformType::SEV_SNP,
                launch_measurement_template(IgvmPlatformType::SEV_SNP, 1),
            )
            .unwrap();
        let mut with = Vec::new();
        serializer.serialize(&mut with).unwrap();

        // Output with CoRIM should be larger (has the CorimDocument init header)
        assert!(with.len() > without.len());
    }

    #[test]
    fn add_corim_uses_eager_measurement() {
        let file = make_tdx_file();
        let mut serializer = IgvmSerializer::new(&file).unwrap();

        // Measurement was computed eagerly during construction.
        assert!(serializer.measurement_for(IgvmPlatformType::TDX).is_some());
        assert_eq!(serializer.measurements().len(), 1);

        // add_corim should reuse the cached measurement.
        serializer
            .add_corim(
                IgvmPlatformType::TDX,
                launch_measurement_template(IgvmPlatformType::TDX, 5),
            )
            .unwrap();

        assert_eq!(serializer.measurements().len(), 1);
    }

    #[test]
    fn add_corim_output_roundtrips() {
        let file = make_snp_file();
        let mut serializer = IgvmSerializer::new(&file).unwrap();
        serializer
            .add_corim(
                IgvmPlatformType::SEV_SNP,
                launch_measurement_template(IgvmPlatformType::SEV_SNP, 42),
            )
            .unwrap();

        let mut output = Vec::new();
        serializer.serialize(&mut output).unwrap();

        // Should parse back successfully and contain a CorimDocument
        let deserialized = IgvmFile::new_from_binary(&output, None).unwrap();
        let has_corim = deserialized
            .initializations()
            .iter()
            .any(|h| matches!(h, IgvmInitializationHeader::CorimDocument { .. }));
        assert!(has_corim);
    }

    #[test]
    fn file_not_mutated_after_add_corim() {
        let file = make_snp_file();
        let init_count_before = file.initializations().len();

        let mut serializer = IgvmSerializer::new(&file).unwrap();
        serializer
            .add_corim(
                IgvmPlatformType::SEV_SNP,
                launch_measurement_template(IgvmPlatformType::SEV_SNP, 1),
            )
            .unwrap();

        // The original file should not have been mutated
        assert_eq!(file.initializations().len(), init_count_before);
    }

    // -- Two-stage builder tests -------------------------------------

    #[test]
    fn launch_measurement_unsupported_platform() {
        use crate::corim::launch_measurement::Error as LeError;
        use crate::corim::launch_measurement::LaunchMeasurement;
        let err = LaunchMeasurement::for_platform(IgvmPlatformType::NATIVE).unwrap_err();
        assert!(matches!(err, LeError::UnsupportedPlatform(_)));
    }

    #[test]
    fn launch_measurement_select_unpopulated_rejected() {
        use crate::corim::launch_measurement::Error as LeError;
        use crate::corim::launch_measurement::LaunchMeasurement;
        use crate::corim::launch_measurement::MeasurementKind;
        let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::SEV_SNP).unwrap();
        let err = le.endorse(1).with(MeasurementKind::Launch).unwrap_err();
        assert!(matches!(err, LeError::MeasurementNotPopulated { .. }));
    }

    #[test]
    fn launch_measurement_duplicate_selection_rejected() {
        use crate::corim::launch_measurement::Error as LeError;
        use crate::corim::launch_measurement::LaunchMeasurement;
        use crate::corim::launch_measurement::MeasurementKind;
        let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::SEV_SNP).unwrap();
        le.set_measurement(MeasurementKind::Launch).unwrap();
        let err = le
            .endorse(1)
            .with(MeasurementKind::Launch)
            .unwrap()
            .with(MeasurementKind::Launch)
            .unwrap_err();
        assert!(matches!(err, LeError::DuplicateSelection { .. }));
    }

    #[test]
    fn launch_measurement_empty_selection_rejected() {
        use crate::corim::launch_measurement::Error as LeError;
        use crate::corim::launch_measurement::LaunchMeasurement;
        use crate::corim::launch_measurement::MeasurementKind;
        let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::SEV_SNP).unwrap();
        le.set_measurement(MeasurementKind::Launch).unwrap();
        let err = le.endorse(1).finish().unwrap_err();
        assert!(matches!(err, LeError::EmptySelection));
    }

    #[test]
    fn add_corim_platform_mismatch_rejected() {
        let file = make_snp_file();
        let mut serializer = IgvmSerializer::new(&file).unwrap();
        // LaunchMeasurement targets TDX but we call add_corim with SEV_SNP.
        let template = launch_measurement_template(IgvmPlatformType::TDX, 1);
        let err = serializer
            .add_corim(IgvmPlatformType::SEV_SNP, template)
            .unwrap_err();
        assert!(err.to_string().contains("targets"));
    }

    #[test]
    fn add_corim_no_ces_triple_rejected() {
        use crate::corim::launch_measurement::LaunchMeasurement;
        use crate::corim::launch_measurement::MeasurementKind;
        let file = make_snp_file();
        let mut serializer = IgvmSerializer::new(&file).unwrap();

        // Populate a measurement but never call `endorse(...).finish()`.
        let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::SEV_SNP).unwrap();
        le.set_measurement(MeasurementKind::Launch).unwrap();

        let err = serializer
            .add_corim(IgvmPlatformType::SEV_SNP, le.build())
            .unwrap_err();
        assert!(err.to_string().contains("got 0"), "got: {err}");
    }

    #[test]
    fn add_corim_multiple_ces_triples_rejected() {
        use crate::corim::launch_measurement::LaunchMeasurement;
        use crate::corim::launch_measurement::MeasurementKind;
        let file = make_snp_file();
        let mut serializer = IgvmSerializer::new(&file).unwrap();

        let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::SEV_SNP).unwrap();
        le.set_measurement(MeasurementKind::Launch).unwrap();
        // Two CES triples in one endorsement.
        le.endorse(1)
            .with(MeasurementKind::Launch)
            .unwrap()
            .finish()
            .unwrap();
        le.endorse(2)
            .with(MeasurementKind::Launch)
            .unwrap()
            .finish()
            .unwrap();

        let err = serializer
            .add_corim(IgvmPlatformType::SEV_SNP, le.build())
            .unwrap_err();
        assert!(err.to_string().contains("got 2"), "got: {err}");
    }

    #[test]
    fn measurement_deterministic() {
        let file = make_vbs_file();

        let s1 = IgvmSerializer::new(&file).unwrap();
        let m1 = s1
            .measurement_for(IgvmPlatformType::VSM_ISOLATION)
            .unwrap()
            .digest
            .clone();

        let s2 = IgvmSerializer::new(&file).unwrap();
        let m2 = s2
            .measurement_for(IgvmPlatformType::VSM_ISOLATION)
            .unwrap()
            .digest
            .clone();

        assert_eq!(m1, m2);
    }
}
