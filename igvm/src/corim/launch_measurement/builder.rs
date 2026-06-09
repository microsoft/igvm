// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! CoRIM launch-measurement builder.

use corim::builder::ComidBuilder;
use corim::builder::CorimBuilder;
use corim::types::common::MeasuredElement;
use corim::types::common::TagIdChoice;
use corim::types::corim::CorimId;
use corim::types::corim::ProfileChoice;
use corim::types::environment::ClassMap;
use corim::types::environment::EnvironmentMap;
use corim::types::measurement::Digest;
use corim::types::measurement::MeasurementMap;
use corim::types::measurement::MeasurementValuesMap;
use corim::types::measurement::SvnChoice;
use corim::types::triples::ConditionalSeriesRecord;
use igvm_defs::IgvmPlatformType;
use uuid::Uuid;

use super::platform_info;
use super::profile::PROFILE_URI;
use super::Error;
use super::TAG_ID_NAMESPACE;

// `ResolvedMeasurement` is intentionally profile-specific. When a second
// profile arrives, common shape -- e.g., `(mkey, digest_alg, digest)` --
// can be promoted to `crate::corim` if duplication justifies it.

/// A measurement resolved by the serializer, ready for CBOR encoding.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedMeasurement {
    pub mkey: String,
    pub digest_alg: i64,
    pub digest: Vec<u8>,
}

/// Build a complete CoRIM launch measurement endorsement as tag-501-wrapped CBOR bytes.
///
/// Emits a single reference-values triple containing the measurement,
/// plus a single CES triple that selects on that measurement and
/// endorses `svn`.
pub(crate) fn build_corim_bytes(
    platform: IgvmPlatformType,
    measurement: &ResolvedMeasurement,
    svn: u64,
) -> Result<Vec<u8>, Error> {
    let info = platform_info(platform).expect("platform validated by LaunchMeasurement");

    let env = EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some(info.vendor.into()),
            model: Some(info.model.into()),
            layer: None,
            index: None,
        }),
        instance: None,
        group: None,
    };

    let tag_id = Uuid::new_v5(
        &TAG_ID_NAMESPACE,
        format!("{}/{}", info.vendor, info.model).as_bytes(),
    )
    .to_string();

    let ref_meas = build_measurement_map(measurement);

    // CES selection: same measurement-map as the reference value.
    let ces_selection = ref_meas.clone();

    let ces_addition = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            svn: Some(SvnChoice::ExactValue(svn)),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    };

    // Declare the platform env once in the builder's catalog so the
    // reference triple and the CES condition share it by ref. The
    // `_for` builder methods resolve the ref to one inline env at
    // `build()` time, and `strict_links(true)` promotes any drift
    // between catalog-anchored envs into a build-time error.
    let mut comid_builder = ComidBuilder::new(TagIdChoice::Text(tag_id));
    let env_ref = comid_builder
        .declare_env("platform", env)
        .map_err(|e| Error::Build(Box::new(e)))?;

    let comid = comid_builder
        .add_reference_triple_for(&env_ref, vec![ref_meas])
        .add_conditional_endorsement_series_for(
            &env_ref,
            Vec::new(),
            None,
            vec![ConditionalSeriesRecord::new(
                vec![ces_selection],
                vec![ces_addition],
            )],
        )
        .strict_links(true)
        .build()
        .map_err(|e| Error::Build(Box::new(e)))?;

    // Build CoRIM with profile URI
    let corim_id = format!("{}/{}/launch-measurement", info.vendor, info.model);
    CorimBuilder::new(CorimId::Text(corim_id))
        .set_profile(ProfileChoice::Uri(PROFILE_URI.into()))
        .add_comid_tag(comid)
        .map_err(|e| Error::Build(Box::new(e)))?
        .build_bytes()
        .map_err(|e| Error::Build(Box::new(e)))
}

fn build_measurement_map(m: &ResolvedMeasurement) -> MeasurementMap {
    MeasurementMap {
        mkey: Some(MeasuredElement::Text(m.mkey.clone())),
        mval: MeasurementValuesMap {
            digests: Some(vec![Digest::new(m.digest_alg, m.digest.clone())]),
            ..MeasurementValuesMap::default()
        },
        authorized_by: None,
    }
}

#[cfg(test)]
mod tests {
    use igvm_defs::IgvmPlatformType;

    use crate::corim::launch_measurement::Error;
    use crate::corim::launch_measurement::LaunchMeasurement;
    use crate::corim::launch_measurement::MeasurementKind;

    fn build_and_decode(
        le: LaunchMeasurement,
    ) -> (
        corim::types::corim::CorimMap,
        Vec<corim::types::comid::ComidTag>,
    ) {
        // Tests use a fixed digest in place of the IGVM file's
        // auto-computed launch measurement.
        let platform = le.platform();
        let kind = *le.measurement_kinds().iter().next().unwrap();
        let (mkey, alg, len) = super::super::measurement_info(platform, kind).unwrap();
        let measurement = super::ResolvedMeasurement {
            mkey: mkey.to_string(),
            digest_alg: alg,
            digest: vec![0xAA; len],
        };

        let svn = le.triples()[0].svn();

        let bytes = super::build_corim_bytes(platform, &measurement, svn).unwrap();
        corim::validate::decode_and_validate_at(&bytes, 0).unwrap()
    }

    #[test]
    fn amd_sev_snp_round_trip() {
        let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::SEV_SNP).unwrap();
        le.set_measurement(MeasurementKind::Launch).unwrap();
        le.endorse(1)
            .with(MeasurementKind::Launch)
            .unwrap()
            .finish()
            .unwrap();

        let (corim, comids) = build_and_decode(le);
        assert_eq!(corim.id.to_string(), "AMD/SEV-SNP/launch-measurement");
        assert_eq!(comids.len(), 1);
        let tag_id = comids[0].tag_identity.tag_id.to_string();
        assert_eq!(tag_id, "77e8061e-4634-5e53-a848-d1d09e996843");
    }

    #[test]
    fn intel_tdx_round_trip() {
        let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::TDX).unwrap();
        le.set_measurement(MeasurementKind::Launch).unwrap();
        le.endorse(5)
            .with(MeasurementKind::Launch)
            .unwrap()
            .finish()
            .unwrap();

        let (corim, _) = build_and_decode(le);
        assert_eq!(corim.id.to_string(), "Intel/TDX/launch-measurement");
    }

    #[test]
    fn microsoft_vbs_round_trip() {
        let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::VSM_ISOLATION).unwrap();
        le.set_measurement(MeasurementKind::Launch).unwrap();
        le.endorse(2)
            .with(MeasurementKind::Launch)
            .unwrap()
            .finish()
            .unwrap();

        let (corim, _) = build_and_decode(le);
        assert_eq!(corim.id.to_string(), "Microsoft/VBS/launch-measurement");
    }

    #[test]
    fn unsupported_platform_rejected() {
        let err = LaunchMeasurement::for_platform(IgvmPlatformType::NATIVE).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedPlatform(IgvmPlatformType::NATIVE)),
            "got: {err:?}"
        );
    }

    #[test]
    fn select_unpopulated_kind_rejected() {
        let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::SEV_SNP).unwrap();
        let err = le.endorse(1).with(MeasurementKind::Launch).unwrap_err();
        assert!(matches!(err, Error::MeasurementNotPopulated { .. }));
    }

    #[test]
    fn duplicate_selection_rejected() {
        let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::SEV_SNP).unwrap();
        le.set_measurement(MeasurementKind::Launch).unwrap();
        let err = le
            .endorse(1)
            .with(MeasurementKind::Launch)
            .unwrap()
            .with(MeasurementKind::Launch)
            .unwrap_err();
        assert!(matches!(err, Error::DuplicateSelection { .. }));
    }

    #[test]
    fn empty_selection_rejected() {
        let mut le = LaunchMeasurement::for_platform(IgvmPlatformType::SEV_SNP).unwrap();
        le.set_measurement(MeasurementKind::Launch).unwrap();
        let err = le.endorse(1).finish().unwrap_err();
        assert!(matches!(err, Error::EmptySelection));
    }
}
