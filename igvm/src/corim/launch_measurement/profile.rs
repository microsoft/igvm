// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Launch Measurement CoRIM Profile.
//!
//! This module defines the CoRIM profile for launch measurements per
//! draft-ietf-rats-corim-10 Sec. 4.1.4. A profile constrains the base CoRIM
//! CDDL to a specific use case without changing the schema.
//!
//! # Profile URI
//!
//! ```text
//! tag:microsoft.com,2026:launch-measurement/v1
//! ```
//!
//! # Semantics
//!
//! A CoRIM conforming to this profile carries exactly **one CoMID tag** with
//! the following structure:
//!
//! ## Environment (`class-map`)
//!
//! The Target Environment is identified by `vendor` (key 1) and `model`
//! (key 2) in the `class-map`. No `instance` or `group` is used -- this is
//! a class-level endorsement that applies to all instances of the platform.
//!
//! Registered vendor/model pairs:
//!
//! | IgvmPlatformType | Vendor        | Model       | Digest Algorithm | Digest Length |
//! |------------------|---------------|-------------|------------------|---------------|
//! | TDX              | `"Intel"`     | `"TDX"`     | SHA-384 (7)      | 48 bytes      |
//! | SEV-SNP          | `"AMD"`       | `"SEV-SNP"` | SHA-384 (7)      | 48 bytes      |
//! | VSM_ISOLATION    | `"Microsoft"` | `"VBS"`     | SHA-256 (1)      | 32 bytes      |
//!
//! ## Tag Identity (`tag-identity-map`)
//!
//! The `tag-id` is derived deterministically via UUIDv5 and encoded as a
//! **lowercase** hyphenated string per RFC 9562 Sec. 4:
//!
//! ```text
//! tag-id = lowercase(UUIDv5("85f3f1c2-22a8-441e-a1b9-bccfb63ed5f7", "{vendor}/{model}"))
//! ```
//!
//! Validators MUST compare tag-ids **case-insensitively** for interoperability.
//!
//! ## Triples
//!
//! ### Required: `reference-triples` (key 0)
//!
//! Exactly one `reference-triple-record` containing:
//! - `environment`: `{ class: { vendor, model } }`
//! - `measurements`: one `measurement-map` with:
//!   - `mkey`: text string identifying the evidence field (e.g., `"MRTD"` for TDX, `"MEASUREMENT"` for SEV-SNP and VBS)
//!   - `mval.digests`: one `[alg-id, hash-bytes]` pair
//!
//! ### Required: `conditional-endorsement-series-triples` (key 8)
//!
//! Exactly one `conditional-endorsement-series-triple-record` containing:
//! - `condition`: the same environment, with an empty `claims-list`
//! - `series`: one entry mapping the digest to an exact SVN (`#6.552(uint)`)
//!
//! ## Constraints
//!
//! - The CoRIM MUST include the profile URI (`corim-map` key 3) set to
//!   [`PROFILE_URI`]. Documents without the profile field MUST be rejected.
//! - The CoRIM MUST contain exactly one CoMID tag (`#6.506`).
//! - The CoMID `tag-id` MUST equal the lowercase string form of
//!   `UUIDv5(TAG_ID_NAMESPACE, "{vendor}/{model}")` per RFC 9562 Sec. 4.
//!   Validators MUST compare tag-ids case-insensitively.
//! - The CoMID MUST contain both `reference-triples` and
//!   `conditional-endorsement-series-triples`.
//! - Only exact SVN (`#6.552`) is permitted. Minimum SVN (`#6.553`) and
//!   untagged integers MUST be rejected.
//! - The vendor/model MUST match one of the registered platform pairs.
//! - The digest algorithm and length MUST match the platform's expected values.
//! - CBOR deterministic encoding SHOULD be used for map keys (already
//!   ensured by emitting integer keys in ascending order).

/// The profile URI for launch measurement CoRIM documents.
///
/// This URI is set in `corim-map` key 3 (`profile`) and signals to a
/// verifier that the document conforms to the constraints above.
///
/// Format follows the tag URI scheme (RFC 4151):
/// `tag:<authority>,<date>:<specific>`
pub const PROFILE_URI: &str = "tag:microsoft.com,2026:launch-measurement/v1";
