#![allow(dead_code)]

use std::os::raw::{c_uchar, c_void};
use std::ptr;
use std::slice;
use std::mem;

#[repr(C)]
#[derive(PartialEq, Eq, Debug)]
pub enum FileResult {
    Ok = 0,
    ErrorMallocFailed,
    ErrorOverflow,
    ErrorInvalidArgument,
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct UNFE {
    pub identifier: [u8; 4],
    pub version: u8,
    pub file_size: u32,
    pub header_offset: u32,
    pub header_size: u32,
    pub payload_offset: u32,
    pub payload_size: u32,
    pub meta_offset: u32,
    pub meta_size: u32,
    pub reserved: [u8; 31],
    pub checksum: u32,
}

pub struct UnfeFile {
    ptr: *mut u8,
    len: usize,
}

impl UnfeFile {
    pub fn main_header(&self) -> &UNFE {
        unsafe { &*(self.ptr as *const UNFE) }
    }

    pub fn header_data(&self) -> &[u8] {
        let header = self.main_header();
        if header.header_size == 0 {
            return &[];
        }
        unsafe {
            slice::from_raw_parts(
                self.ptr.add(header.header_offset as usize),
                header.header_size as usize,
            )
        }
    }

    pub fn payload_data(&self) -> &[u8] {
        let header = self.main_header();
        if header.payload_size == 0 {
            return &[];
        }
        unsafe {
            slice::from_raw_parts(
                self.ptr.add(header.payload_offset as usize),
                header.payload_size as usize,
            )
        }
    }

    pub fn meta_data(&self) -> &[u8] {
        let header = self.main_header();
        if header.meta_size == 0 {
            return &[];
        }
        unsafe {
            slice::from_raw_parts(
                self.ptr.add(header.meta_offset as usize),
                header.meta_size as usize,
            )
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for UnfeFile {
    fn drop(&mut self) {
        unsafe { free_file(self.ptr) };
    }
}

unsafe extern "C" {
    fn make_file(
        header_data: *const c_uchar,
        header_len: usize,
        payload_data: *const c_uchar,
        payload_len: usize,
        meta_data: *const c_uchar,
        meta_len: usize,
        out_file: *mut *mut c_uchar,
    ) -> FileResult;

    fn free_file(file: *mut c_uchar);

    fn is_unfe_file(file_buffer: *const c_uchar, buffer_len: usize) -> bool;

    fn get_info(file_buffer: *const c_uchar) -> UNFE;

    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, offset: usize) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}

pub fn create_unfe_file(
    header: &[u8],
    payload: &[u8],
    meta: &[u8],
) -> Result<UnfeFile, FileResult> {
    let mut out_ptr: *mut c_uchar = ptr::null_mut();

    #[allow(unused_assignments)]
    let mut file_len = 0;

    let result = unsafe {
        make_file(
            header.as_ptr(), header.len(),
            payload.as_ptr(), payload.len(),
            meta.as_ptr(), meta.len(),
            &mut out_ptr,
        )
    };

    if result == FileResult::Ok && !out_ptr.is_null() {
        let file_header = unsafe { &*(out_ptr as *const UNFE) };
        file_len = file_header.file_size as usize;
        
        Ok(UnfeFile { ptr: out_ptr, len: file_len })
    } else {
        Err(result)
    }
}

pub fn is_unfe(data: &[u8]) -> bool {
    unsafe { is_unfe_file(data.as_ptr(), data.len()) }
}

pub fn get_unfe_info(data: &[u8]) -> UNFE {
    unsafe { get_info(data.as_ptr()) }
}

const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const PROT_EXEC: i32 = 0x4;
const MAP_PRIVATE: i32 = 0x02;
const MAP_ANONYMOUS: i32 = 0x20;

pub unsafe fn run_bytes(code: &[u8]) -> i64 {
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            code.len(),
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if ptr.is_null() {
        panic!("mmap failed!");
    }

    unsafe {
        ptr::copy_nonoverlapping(code.as_ptr(), ptr as *mut u8, code.len());
    }

    let func: extern "C" fn() -> i64 = unsafe { mem::transmute(ptr) };
    let res = func();
    unsafe {
        munmap(ptr, code.len());
    }

    res
}