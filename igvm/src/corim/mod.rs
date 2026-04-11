// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! CoRIM (Concise Reference Integrity Manifest) support for IGVM.
//!
//! This module provides CoRIM document generation for IGVM attestation.
//!
//! Built on top of the [`corim`](https://github.com/Azure/corim) crate
//! for typed CoRIM/CoMID structures, CBOR encoding, and structural
//! validation per draft-ietf-rats-corim-10.
//!
//! # Modules
//!
//! - [`launch_measurement`] -- The launch measurement profile

pub mod launch_measurement;

// Re-export launch_measurement types for convenience.
pub use launch_measurement::Error;
