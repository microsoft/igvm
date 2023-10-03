// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

//! Provides an alternative interface for using the IGVM crate that
//! is suitable for calling from C.

#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::ptr::null;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::{Error, IgvmFile};
use open_enum::open_enum;

pub const IGVMAPI_OK: i32 = 0;
pub const IGVMAPI_INVALID_PARAMETER: i32 = -1;
pub const IGVMAPI_NO_DATA: i32 = -2;
pub const IGVMAPI_INVALID_FILE: i32 = -3;
pub const IGVMAPI_INVALID_HANDLE: i32 = -4;
pub const IGVMAPI_NO_PLATFORM_HEADERS: i32 = -5;
pub const IGVMAPI_FILE_DATA_SECTION_TOO_LARGE: i32 = -6;
pub const IGVMAPI_VARIABLE_HEADER_SECTION_TOO_LARGE: i32 = -7;
pub const IGVMAPI_TOTAL_FILE_SIZE_TOO_LARGE: i32 = -8;
pub const IGVMAPI_INVALID_BINARY_PLATFORM_HEADER: i32 = -9;
pub const IGVMAPI_INVALID_BINARY_INITIALIZATION_HEADER: i32 = -10;
pub const IGVMAPI_INVALID_BINARY_DIRECTIVE_HEADER: i32 = -11;
pub const IGVMAPI_MULTIPLE_PLATFORM_HEADERS_WITH_SAME_ISOLATION: i32 = -12;
pub const IGVMAPI_INVALID_PARAMETER_AREA_INDEX: i32 = -13;
pub const IGVMAPI_INVALID_PLATFORM_TYPE: i32 = -14;
pub const IGVMAPI_NO_FREE_COMPATIBILITY_MASKS: i32 = -15;
pub const IGVMAPI_INVALID_FIXED_HEADER: i32 = -16;
pub const IGVMAPI_INVALID_BINARY_VARIABLE_HEADER_SECTION: i32 = -17;
pub const IGVMAPI_INVALID_CHECKSUM: i32 = -18;
pub const IGVMAPI_MULTIPLE_PAGE_TABLE_RELOCATION_HEADERS: i32 = -19;
pub const IGVMAPI_RELOCATION_REGIONS_OVERLAP: i32 = -20;
pub const IGVMAPI_PARAMETER_INSERT_INSIDE_PAGE_TABLE_REGION: i32 = -21;
pub const IGVMAPI_NO_MATCHING_VP_CONTEXT: i32 = -22;
pub const IGVMAPI_PLATFORM_ARCH_UNSUPPORTED: i32 = -23;
pub const IGVMAPI_INVALID_HEADER_ARCH: i32 = -24;
pub const IGVMAPI_UNSUPPORTED_PAGE_SIZE: i32 = -25;
pub const IGVMAPI_INVALID_FIXED_HEADER_ARCH: i32 = -26;
pub const IGVMAPI_MERGE_REVISION: i32 = -27;

type IgvmHandle = i32;

struct IgvmFileInstance {
    file: IgvmFile,
    buffers: BTreeMap<IgvmHandle, Vec<u8>>,
}

static IGVM_HANDLES: OnceLock<Mutex<BTreeMap<IgvmHandle, IgvmFileInstance>>> = OnceLock::new();
static IGVM_HANDLE_FACTORY: OnceLock<AtomicI32> = OnceLock::new();

#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IgvmHeaderSection {
    HEADER_SECTION_PLATFORM,
    HEADER_SECTION_INITIALIZATION,
    HEADER_SECTION_DIRECTIVE,
}

struct IgvmFileHandleLock<'a> {
    lock: MutexGuard<'a, BTreeMap<i32, IgvmFileInstance>>,
    handle: IgvmHandle,
}

impl<'a> IgvmFileHandleLock<'a> {
    pub fn new(handle: IgvmHandle) -> Result<Self, i32> {
        let lock = IGVM_HANDLES
            .get()
            .ok_or(IGVMAPI_INVALID_HANDLE)?
            .lock()
            .unwrap();

        Ok(IgvmFileHandleLock { lock, handle })
    }

    pub fn get(&self) -> Result<&IgvmFileInstance, i32> {
        self.lock.get(&self.handle).ok_or(IGVMAPI_INVALID_HANDLE)
    }

    pub fn get_mut(&mut self) -> Result<&mut IgvmFileInstance, i32> {
        self.lock
            .get_mut(&self.handle)
            .ok_or(IGVMAPI_INVALID_HANDLE)
    }
}

fn new_handle() -> i32 {
    IGVM_HANDLE_FACTORY
        .get_or_init(|| AtomicI32::new(1))
        .fetch_add(1, Ordering::Relaxed)
}

fn translate_error(error: Error) -> i32 {
    match error {
        Error::NoPlatformHeaders => IGVMAPI_NO_PLATFORM_HEADERS,
        Error::FileDataSectionTooLarge => IGVMAPI_FILE_DATA_SECTION_TOO_LARGE,
        Error::VariableHeaderSectionTooLarge => IGVMAPI_VARIABLE_HEADER_SECTION_TOO_LARGE,
        Error::TotalFileSizeTooLarge => IGVMAPI_TOTAL_FILE_SIZE_TOO_LARGE,
        Error::InvalidBinaryPlatformHeader(_) => IGVMAPI_INVALID_BINARY_PLATFORM_HEADER,
        Error::InvalidBinaryInitializationHeader(_) => IGVMAPI_INVALID_BINARY_INITIALIZATION_HEADER,
        Error::InvalidBinaryDirectiveHeader(_) => IGVMAPI_INVALID_BINARY_DIRECTIVE_HEADER,
        Error::MultiplePlatformHeadersWithSameIsolation => {
            IGVMAPI_MULTIPLE_PLATFORM_HEADERS_WITH_SAME_ISOLATION
        }
        Error::InvalidParameterAreaIndex => IGVMAPI_INVALID_PARAMETER_AREA_INDEX,
        Error::InvalidPlatformType => IGVMAPI_INVALID_PLATFORM_TYPE,
        Error::NoFreeCompatibilityMasks => IGVMAPI_NO_FREE_COMPATIBILITY_MASKS,
        Error::InvalidFixedHeader => IGVMAPI_INVALID_FIXED_HEADER,
        Error::InvalidBinaryVariableHeaderSection => IGVMAPI_INVALID_BINARY_VARIABLE_HEADER_SECTION,
        Error::InvalidChecksum {
            expected: _,
            header_value: _,
        } => IGVMAPI_INVALID_CHECKSUM,
        Error::MultiplePageTableRelocationHeaders => IGVMAPI_MULTIPLE_PAGE_TABLE_RELOCATION_HEADERS,
        Error::RelocationRegionsOverlap => IGVMAPI_RELOCATION_REGIONS_OVERLAP,
        Error::ParameterInsertInsidePageTableRegion => {
            IGVMAPI_PARAMETER_INSERT_INSIDE_PAGE_TABLE_REGION
        }
        Error::NoMatchingVpContext => IGVMAPI_NO_MATCHING_VP_CONTEXT,
        Error::PlatformArchUnsupported {
            arch: _,
            platform: _,
        } => IGVMAPI_PLATFORM_ARCH_UNSUPPORTED,
        Error::InvalidHeaderArch {
            arch: _,
            header_type: _,
        } => IGVMAPI_INVALID_HEADER_ARCH,
        Error::UnsupportedPageSize(_) => IGVMAPI_UNSUPPORTED_PAGE_SIZE,
        Error::InvalidFixedHeaderArch(_) => IGVMAPI_INVALID_FIXED_HEADER_ARCH,
        Error::MergeRevision => IGVMAPI_MERGE_REVISION,
    }
}

fn igvm_create(file: IgvmFile) -> IgvmHandle {
    let handle = new_handle();
    let mut m = IGVM_HANDLES
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap();
    m.insert(
        handle,
        IgvmFileInstance {
            file,
            buffers: BTreeMap::new(),
        },
    );
    handle
}

/// Returns a pointer to the array of bytes in a buffer.
fn get_buffer(igvm_handle: IgvmHandle, buffer_handle: IgvmHandle) -> Result<*const u8, i32> {
    let handle_lock = IgvmFileHandleLock::new(igvm_handle)?;
    let igvm = handle_lock.get()?;
    Ok(igvm
        .buffers
        .get(&buffer_handle)
        .ok_or(IGVMAPI_INVALID_HANDLE)?
        .as_ptr())
}

/// Returns the size of a buffer.
fn get_buffer_size(igvm_handle: IgvmHandle, buffer_handle: IgvmHandle) -> Result<i32, i32> {
    let handle_lock = IgvmFileHandleLock::new(igvm_handle)?;
    let igvm = handle_lock.get()?;
    Ok(igvm
        .buffers
        .get(&buffer_handle)
        .ok_or(IGVMAPI_INVALID_HANDLE)?
        .len() as i32)
}

/// Frees a buffer.
fn free_buffer(igvm_handle: IgvmHandle, buffer_handle: IgvmHandle) -> Result<(), i32> {
    let mut handle_lock = IgvmFileHandleLock::new(igvm_handle)?;
    let igvm = handle_lock.get_mut()?;
    igvm.buffers.remove(&buffer_handle);
    Ok(())
}

/// Get the count of headers for a particular section in a previously parsed
/// IGVM file.
fn header_count(handle: IgvmHandle, section: IgvmHeaderSection) -> Result<i32, i32> {
    let mut handle_lock = IgvmFileHandleLock::new(handle)?;
    let igvm = handle_lock.get_mut()?;
    match section {
        IgvmHeaderSection::HEADER_SECTION_PLATFORM => Ok(igvm.file.platform_headers.len() as i32),
        IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => {
            Ok(igvm.file.initialization_headers.len() as i32)
        }
        IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => Ok(igvm.file.directive_headers.len() as i32),
        _ => Err(IGVMAPI_INVALID_PARAMETER),
    }
}

/// Get the header type for the entry with the given index for a particular
/// section in a previously parsed IGVM file.
fn get_header_type(handle: IgvmHandle, section: IgvmHeaderSection, index: u32) -> Result<i32, i32> {
    let mut handle_lock = IgvmFileHandleLock::new(handle)?;
    let igvm = handle_lock.get_mut()?;
    match section {
        IgvmHeaderSection::HEADER_SECTION_PLATFORM => Ok(igvm
            .file
            .platform_headers
            .get(index as usize)
            .ok_or(IGVMAPI_INVALID_PARAMETER)?
            .header_type()
            .0 as i32),
        IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => Ok(igvm
            .file
            .initialization_headers
            .get(index as usize)
            .ok_or(IGVMAPI_INVALID_PARAMETER)?
            .header_type()
            .0 as i32),
        IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => Ok(igvm
            .file
            .directive_headers
            .get(index as usize)
            .ok_or(IGVMAPI_INVALID_PARAMETER)?
            .header_type()
            .0 as i32),
        _ => Err(IGVMAPI_INVALID_PARAMETER),
    }
}

/// Prepare a buffer containing the header data in binary form for the entry
/// with the given index for a particular section in a previously parsed IGVM
/// file.
fn get_header(
    handle: IgvmHandle,
    section: IgvmHeaderSection,
    index: u32,
) -> Result<IgvmHandle, i32> {
    let mut header_binary = Vec::<u8>::new();

    let mut handle_lock = IgvmFileHandleLock::new(handle)?;
    let igvm = handle_lock.get_mut()?;

    match section {
        IgvmHeaderSection::HEADER_SECTION_PLATFORM => {
            igvm.file
                .platform_headers
                .get(index as usize)
                .ok_or(IGVMAPI_INVALID_PARAMETER)?
                .write_binary_header(&mut header_binary)
                .map_err(|_| IGVMAPI_INVALID_FILE)?;
        }
        IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => {
            igvm.file
                .initialization_headers
                .get(index as usize)
                .ok_or(IGVMAPI_INVALID_PARAMETER)?
                .write_binary_header(&mut header_binary)
                .map_err(|_| IGVMAPI_INVALID_FILE)?;
        }
        IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => {
            igvm.file
                .directive_headers
                .get(index as usize)
                .ok_or(IGVMAPI_INVALID_PARAMETER)?
                .write_binary_header(0, &mut header_binary, &mut Vec::<u8>::new())
                .map_err(|_| IGVMAPI_INVALID_FILE)?;
        }
        _ => {
            return Err(IGVMAPI_INVALID_PARAMETER);
        }
    }
    let header_handle = new_handle();
    igvm.buffers.insert(header_handle, header_binary);
    Ok(header_handle)
}

/// Prepare a buffer containing the associated file data in binary form for the
/// entry with the given index for a particular section in a previously parsed
/// IGVM file.
fn get_header_data(
    handle: IgvmHandle,
    section: IgvmHeaderSection,
    index: u32,
) -> Result<IgvmHandle, i32> {
    let mut handle_lock = IgvmFileHandleLock::new(handle)?;
    let igvm = handle_lock.get_mut()?;
    let mut header_data = Vec::<u8>::new();

    if section == IgvmHeaderSection::HEADER_SECTION_DIRECTIVE {
        let header = igvm
            .file
            .directive_headers
            .get(index as usize)
            .ok_or(IGVMAPI_INVALID_PARAMETER)?;
        header
            .write_binary_header(0, &mut Vec::<u8>::new(), &mut header_data)
            .map_err(|_| IGVMAPI_INVALID_FILE)?;
    } else {
        return Err(IGVMAPI_INVALID_PARAMETER);
    }
    if header_data.is_empty() {
        Err(IGVMAPI_NO_DATA)
    } else {
        let header_data_handle = new_handle();
        igvm.buffers.insert(header_data_handle, header_data);
        Ok(header_data_handle)
    }
}

/// Returns a pointer to the array of bytes in a buffer.
///
/// # Safety
///
/// The caller must ensure that the buffer handle remains valid for the duration
/// of accessing the data pointed to by the raw pointer returned by this
/// function. This requires that the `buffer_handle` is not freed with a call to
/// [`igvm_free_buffer()`] and that the `igvm_handle` is not freed with a call
/// to [`igvm_free()`].
///
/// Invalid handles are handled within this function and result in a return
/// value of `null()`. The caller must check the result before using the array.
#[no_mangle]
pub unsafe extern "C" fn igvm_get_buffer(
    igvm_handle: IgvmHandle,
    buffer_handle: IgvmHandle,
) -> *const u8 {
    match get_buffer(igvm_handle, buffer_handle) {
        Ok(p) => p,
        Err(_) => null(),
    }
}

/// Returns the size of a buffer.
///
/// If either handle is invalid or if there is an error then the return value will
/// be IGVMAPI_INVALID_HANDLE
#[no_mangle]
pub extern "C" fn igvm_get_buffer_size(igvm_handle: IgvmHandle, buffer_handle: IgvmHandle) -> i32 {
    match get_buffer_size(igvm_handle, buffer_handle) {
        Ok(len) => len,
        Err(e) => e,
    }
}

/// Frees a buffer.
///
/// If either handle is invalid then the function has no effect.
#[no_mangle]
pub extern "C" fn igvm_free_buffer(igvm_handle: IgvmHandle, buffer_handle: IgvmHandle) {
    let _ = free_buffer(igvm_handle, buffer_handle);
}

/// Parse a binary array containing an IGVM file. The contents of the file are
/// validated and, if valid, a handle is returned to represent the file. This
/// handle must be freed with a call to igvm_free().
///
/// If any error occurs then the returned handle will be less than zero and will
/// match one of the IGVMAPI error codes.
///
/// # Safety
///
/// The function assumes that there are at least `len` valid bytes of memory
/// starting at the address pointed to by `data`. If this is violated then this
/// will result in undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn igvm_new_from_binary(data: *const u8, len: u32) -> IgvmHandle {
    // SAFETY: Caller guarantees that the data ptr is an array with at least len bytes of memory.
    let file_data = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let result = IgvmFile::new_from_binary(file_data, None);

    match result {
        Ok(file) => igvm_create(file),
        Err(e) => translate_error(e),
    }
}

/// Free a handle that was created with a prevoius call to
/// [`igvm_new_from_binary()`].
#[no_mangle]
pub extern "C" fn igvm_free(handle: IgvmHandle) {
    if let Some(handles) = IGVM_HANDLES.get() {
        let _ = handles.lock().unwrap().remove(&handle);
    }
}

/// Get the count of headers for a particular section in a previously parsed
/// IGVM file.
///
/// If any error occurs then the returned value will be less than zero and will
/// match one of the IGVMAPI error codes.
#[no_mangle]
pub extern "C" fn igvm_header_count(handle: IgvmHandle, section: IgvmHeaderSection) -> i32 {
    header_count(handle, section)
        .or_else(|e| Ok(e) as Result<i32, i32>)
        .unwrap()
}

/// Get the header type for the entry with the given index for a particular
/// section in a previously parsed IGVM file.
///
/// If any error occurs then the returned value will be less than zero and will
/// match one of the IGVMAPI error codes.
#[no_mangle]
pub extern "C" fn igvm_get_header_type(
    handle: IgvmHandle,
    section: IgvmHeaderSection,
    index: u32,
) -> i32 {
    get_header_type(handle, section, index)
        .or_else(|e| Ok(e) as Result<i32, i32>)
        .unwrap()
}

/// Prepare a buffer containing the header data in binary form for the entry
/// with the given index for a particular section in a previously parsed IGVM
/// file.
///
/// The buffer containing the data is returned via a handle from this function.
/// The handle can be used to access a raw pointer to the data and to query its
/// size. The buffer handle remains valid until it is closed with a call to
/// [`igvm_free_buffer()`] or the parsed file handle is closed with a call to
/// [`igvm_free()`].
///
/// If any error occurs then the returned value will be less than zero and will
/// match one of the IGVMAPI error codes.
#[no_mangle]
pub extern "C" fn igvm_get_header(
    handle: IgvmHandle,
    section: IgvmHeaderSection,
    index: u32,
) -> IgvmHandle {
    get_header(handle, section, index)
        .or_else(|e| Ok(e) as Result<IgvmHandle, i32>)
        .unwrap()
}

/// Prepare a buffer containing the associated file data in binary form for the
/// entry with the given index for a particular section in a previously parsed
/// IGVM file.
///
/// The buffer containing the data is returned via a handle from this function.
/// The handle can be used to access a raw pointer to the data and to query its
/// size. The buffer handle remains valid until it is closed with a call to
/// [`igvm_free_buffer()`] or the parsed file handle is closed with a call to
/// [`igvm_free()`].
///
/// If any error occurs then the returned value will be less than zero and will
/// match one of the IGVMAPI error codes.
#[no_mangle]
pub extern "C" fn igvm_get_header_data(
    handle: IgvmHandle,
    section: IgvmHeaderSection,
    index: u32,
) -> IgvmHandle {
    get_header_data(handle, section, index)
        .or_else(|e| Ok(e) as Result<IgvmHandle, i32>)
        .unwrap()
}
