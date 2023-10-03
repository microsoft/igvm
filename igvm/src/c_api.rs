// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

//! Provides an alternative interface for using the IGVM crate that
//! is suitable for calling from C.

// UNSAFETY: This module requires the use of 'unsafe' as it implements
// extern "C" functions for providing a C API.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::ptr::null;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::OnceLock;

use crate::{Error, IgvmFile};
use open_enum::open_enum;

/// An enumeration of the possible results that can be returned from C API
/// functions. Some of the extern "C" functions return a positive value
/// representing a handle or a count on success, or an IgvmResult value on
/// error. Therefore all error values must be negative.
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum IgvmResult {
    IGVMAPI_OK = 0,
    IGVMAPI_INVALID_PARAMETER = -1,
    IGVMAPI_NO_DATA = -2,
    IGVMAPI_INVALID_FILE = -3,
    IGVMAPI_INVALID_HANDLE = -4,
    IGVMAPI_NO_PLATFORM_HEADERS = -5,
    IGVMAPI_FILE_DATA_SECTION_TOO_LARGE = -6,
    IGVMAPI_VARIABLE_HEADER_SECTION_TOO_LARGE = -7,
    IGVMAPI_TOTAL_FILE_SIZE_TOO_LARGE = -8,
    IGVMAPI_INVALID_BINARY_PLATFORM_HEADER = -9,
    IGVMAPI_INVALID_BINARY_INITIALIZATION_HEADER = -10,
    IGVMAPI_INVALID_BINARY_DIRECTIVE_HEADER = -11,
    IGVMAPI_MULTIPLE_PLATFORM_HEADERS_WITH_SAME_ISOLATION = -12,
    IGVMAPI_INVALID_PARAMETER_AREA_INDEX = -13,
    IGVMAPI_INVALID_PLATFORM_TYPE = -14,
    IGVMAPI_NO_FREE_COMPATIBILITY_MASKS = -15,
    IGVMAPI_INVALID_FIXED_HEADER = -16,
    IGVMAPI_INVALID_BINARY_VARIABLE_HEADER_SECTION = -17,
    IGVMAPI_INVALID_CHECKSUM = -18,
    IGVMAPI_MULTIPLE_PAGE_TABLE_RELOCATION_HEADERS = -19,
    IGVMAPI_RELOCATION_REGIONS_OVERLAP = -20,
    IGVMAPI_PARAMETER_INSERT_INSIDE_PAGE_TABLE_REGION = -21,
    IGVMAPI_NO_MATCHING_VP_CONTEXT = -22,
    IGVMAPI_PLATFORM_ARCH_UNSUPPORTED = -23,
    IGVMAPI_INVALID_HEADER_ARCH = -24,
    IGVMAPI_UNSUPPORTED_PAGE_SIZE = -25,
    IGVMAPI_INVALID_FIXED_HEADER_ARCH = -26,
    IGVMAPI_MERGE_REVISION = -27,
}

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
    pub fn new(handle: IgvmHandle) -> Result<Self, IgvmResult> {
        let lock = IGVM_HANDLES
            .get()
            .ok_or(IgvmResult::IGVMAPI_INVALID_HANDLE)?
            .lock()
            .unwrap();

        Ok(IgvmFileHandleLock { lock, handle })
    }

    pub fn get(&self) -> Result<&IgvmFileInstance, IgvmResult> {
        self.lock
            .get(&self.handle)
            .ok_or(IgvmResult::IGVMAPI_INVALID_HANDLE)
    }

    pub fn get_mut(&mut self) -> Result<&mut IgvmFileInstance, IgvmResult> {
        self.lock
            .get_mut(&self.handle)
            .ok_or(IgvmResult::IGVMAPI_INVALID_HANDLE)
    }
}

fn new_handle() -> i32 {
    IGVM_HANDLE_FACTORY
        .get_or_init(|| AtomicI32::new(1))
        .fetch_add(1, Ordering::Relaxed)
}

fn translate_error(error: Error) -> IgvmResult {
    match error {
        Error::NoPlatformHeaders => IgvmResult::IGVMAPI_NO_PLATFORM_HEADERS,
        Error::FileDataSectionTooLarge => IgvmResult::IGVMAPI_FILE_DATA_SECTION_TOO_LARGE,
        Error::VariableHeaderSectionTooLarge => {
            IgvmResult::IGVMAPI_VARIABLE_HEADER_SECTION_TOO_LARGE
        }
        Error::TotalFileSizeTooLarge => IgvmResult::IGVMAPI_TOTAL_FILE_SIZE_TOO_LARGE,
        Error::InvalidBinaryPlatformHeader(_) => IgvmResult::IGVMAPI_INVALID_BINARY_PLATFORM_HEADER,
        Error::InvalidBinaryInitializationHeader(_) => {
            IgvmResult::IGVMAPI_INVALID_BINARY_INITIALIZATION_HEADER
        }
        Error::InvalidBinaryDirectiveHeader(_) => {
            IgvmResult::IGVMAPI_INVALID_BINARY_DIRECTIVE_HEADER
        }
        Error::MultiplePlatformHeadersWithSameIsolation => {
            IgvmResult::IGVMAPI_MULTIPLE_PLATFORM_HEADERS_WITH_SAME_ISOLATION
        }
        Error::InvalidParameterAreaIndex => IgvmResult::IGVMAPI_INVALID_PARAMETER_AREA_INDEX,
        Error::InvalidPlatformType => IgvmResult::IGVMAPI_INVALID_PLATFORM_TYPE,
        Error::NoFreeCompatibilityMasks => IgvmResult::IGVMAPI_NO_FREE_COMPATIBILITY_MASKS,
        Error::InvalidFixedHeader => IgvmResult::IGVMAPI_INVALID_FIXED_HEADER,
        Error::InvalidBinaryVariableHeaderSection => {
            IgvmResult::IGVMAPI_INVALID_BINARY_VARIABLE_HEADER_SECTION
        }
        Error::InvalidChecksum {
            expected: _,
            header_value: _,
        } => IgvmResult::IGVMAPI_INVALID_CHECKSUM,
        Error::MultiplePageTableRelocationHeaders => {
            IgvmResult::IGVMAPI_MULTIPLE_PAGE_TABLE_RELOCATION_HEADERS
        }
        Error::RelocationRegionsOverlap => IgvmResult::IGVMAPI_RELOCATION_REGIONS_OVERLAP,
        Error::ParameterInsertInsidePageTableRegion => {
            IgvmResult::IGVMAPI_PARAMETER_INSERT_INSIDE_PAGE_TABLE_REGION
        }
        Error::NoMatchingVpContext => IgvmResult::IGVMAPI_NO_MATCHING_VP_CONTEXT,
        Error::PlatformArchUnsupported {
            arch: _,
            platform: _,
        } => IgvmResult::IGVMAPI_PLATFORM_ARCH_UNSUPPORTED,
        Error::InvalidHeaderArch {
            arch: _,
            header_type: _,
        } => IgvmResult::IGVMAPI_INVALID_HEADER_ARCH,
        Error::UnsupportedPageSize(_) => IgvmResult::IGVMAPI_UNSUPPORTED_PAGE_SIZE,
        Error::InvalidFixedHeaderArch(_) => IgvmResult::IGVMAPI_INVALID_FIXED_HEADER_ARCH,
        Error::MergeRevision => IgvmResult::IGVMAPI_MERGE_REVISION,
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
fn get_buffer(igvm_handle: IgvmHandle, buffer_handle: IgvmHandle) -> Result<*const u8, IgvmResult> {
    let handle_lock = IgvmFileHandleLock::new(igvm_handle)?;
    let igvm = handle_lock.get()?;
    Ok(igvm
        .buffers
        .get(&buffer_handle)
        .ok_or(IgvmResult::IGVMAPI_INVALID_HANDLE)?
        .as_ptr())
}

/// Returns the size of a buffer.
fn get_buffer_size(igvm_handle: IgvmHandle, buffer_handle: IgvmHandle) -> Result<i32, IgvmResult> {
    let handle_lock = IgvmFileHandleLock::new(igvm_handle)?;
    let igvm = handle_lock.get()?;
    Ok(igvm
        .buffers
        .get(&buffer_handle)
        .ok_or(IgvmResult::IGVMAPI_INVALID_HANDLE)?
        .len() as i32)
}

/// Frees a buffer.
fn free_buffer(igvm_handle: IgvmHandle, buffer_handle: IgvmHandle) -> Result<(), IgvmResult> {
    let mut handle_lock = IgvmFileHandleLock::new(igvm_handle)?;
    let igvm = handle_lock.get_mut()?;
    igvm.buffers.remove(&buffer_handle);
    Ok(())
}

/// Get the count of headers for a particular section in a previously parsed
/// IGVM file.
fn header_count(handle: IgvmHandle, section: IgvmHeaderSection) -> Result<i32, IgvmResult> {
    let mut handle_lock = IgvmFileHandleLock::new(handle)?;
    let igvm = handle_lock.get_mut()?;
    match section {
        IgvmHeaderSection::HEADER_SECTION_PLATFORM => Ok(igvm.file.platform_headers.len() as i32),
        IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => {
            Ok(igvm.file.initialization_headers.len() as i32)
        }
        IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => Ok(igvm.file.directive_headers.len() as i32),
        _ => Err(IgvmResult::IGVMAPI_INVALID_PARAMETER),
    }
}

/// Get the header type for the entry with the given index for a particular
/// section in a previously parsed IGVM file.
fn get_header_type(
    handle: IgvmHandle,
    section: IgvmHeaderSection,
    index: u32,
) -> Result<i32, IgvmResult> {
    let mut handle_lock = IgvmFileHandleLock::new(handle)?;
    let igvm = handle_lock.get_mut()?;
    match section {
        IgvmHeaderSection::HEADER_SECTION_PLATFORM => Ok(igvm
            .file
            .platform_headers
            .get(index as usize)
            .ok_or(IgvmResult::IGVMAPI_INVALID_PARAMETER)?
            .header_type()
            .0 as i32),
        IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => Ok(igvm
            .file
            .initialization_headers
            .get(index as usize)
            .ok_or(IgvmResult::IGVMAPI_INVALID_PARAMETER)?
            .header_type()
            .0 as i32),
        IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => Ok(igvm
            .file
            .directive_headers
            .get(index as usize)
            .ok_or(IgvmResult::IGVMAPI_INVALID_PARAMETER)?
            .header_type()
            .0 as i32),
        _ => Err(IgvmResult::IGVMAPI_INVALID_PARAMETER),
    }
}

/// Prepare a buffer containing the header data in binary form for the entry
/// with the given index for a particular section in a previously parsed IGVM
/// file.
fn get_header(
    handle: IgvmHandle,
    section: IgvmHeaderSection,
    index: u32,
) -> Result<IgvmHandle, IgvmResult> {
    let mut header_binary = Vec::<u8>::new();

    let mut handle_lock = IgvmFileHandleLock::new(handle)?;
    let igvm = handle_lock.get_mut()?;

    match section {
        IgvmHeaderSection::HEADER_SECTION_PLATFORM => {
            igvm.file
                .platform_headers
                .get(index as usize)
                .ok_or(IgvmResult::IGVMAPI_INVALID_PARAMETER)?
                .write_binary_header(&mut header_binary)
                .map_err(|_| IgvmResult::IGVMAPI_INVALID_FILE)?;
        }
        IgvmHeaderSection::HEADER_SECTION_INITIALIZATION => {
            igvm.file
                .initialization_headers
                .get(index as usize)
                .ok_or(IgvmResult::IGVMAPI_INVALID_PARAMETER)?
                .write_binary_header(&mut header_binary)
                .map_err(|_| IgvmResult::IGVMAPI_INVALID_FILE)?;
        }
        IgvmHeaderSection::HEADER_SECTION_DIRECTIVE => {
            igvm.file
                .directive_headers
                .get(index as usize)
                .ok_or(IgvmResult::IGVMAPI_INVALID_PARAMETER)?
                .write_binary_header(0, &mut header_binary, &mut Vec::<u8>::new())
                .map_err(|_| IgvmResult::IGVMAPI_INVALID_FILE)?;
        }
        _ => {
            return Err(IgvmResult::IGVMAPI_INVALID_PARAMETER);
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
) -> Result<IgvmHandle, IgvmResult> {
    let mut handle_lock = IgvmFileHandleLock::new(handle)?;
    let igvm = handle_lock.get_mut()?;
    let mut header_data = Vec::<u8>::new();

    if section == IgvmHeaderSection::HEADER_SECTION_DIRECTIVE {
        let header = igvm
            .file
            .directive_headers
            .get(index as usize)
            .ok_or(IgvmResult::IGVMAPI_INVALID_PARAMETER)?;
        header
            .write_binary_header(0, &mut Vec::<u8>::new(), &mut header_data)
            .map_err(|_| IgvmResult::IGVMAPI_INVALID_FILE)?;
    } else {
        return Err(IgvmResult::IGVMAPI_INVALID_PARAMETER);
    }
    if header_data.is_empty() {
        Err(IgvmResult::IGVMAPI_NO_DATA)
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
        Err(e) => e.0,
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
        Err(e) => translate_error(e).0,
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
        .or_else(|e| Ok(e.0) as Result<i32, i32>)
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
        .or_else(|e| Ok(e.0) as Result<i32, i32>)
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
        .or_else(|e| Ok(e.0) as Result<IgvmHandle, i32>)
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
        .or_else(|e| Ok(e.0) as Result<IgvmHandle, i32>)
        .unwrap()
}
