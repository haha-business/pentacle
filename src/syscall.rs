// Copyright (c) iliana destroyer of worlds <iliana@buttslol.net>
// SPDX-License-Identifier: MIT

// syscall returns a c_long but memfd_create(2) and fcntl(2) are documented as returning c_int. The
// values are truncated here instead of using TryFrom.
#![allow(clippy::cast_possible_truncation)]

use libc::{
    c_char, c_int, c_long, c_uint, syscall, SYS_fcntl, SYS_memfd_create, F_ADD_SEALS, F_GET_SEALS,
};
use log::trace;
use std::ffi::CStr;
use std::fs::File;
use std::io::{Error, Result};
use std::os::unix::io::{AsRawFd, FromRawFd};

pub(crate) fn memfd_create(name: &CStr, flags: c_uint) -> Result<File> {
    let name: *const c_char = name.as_ptr();
    let retval = unsafe { syscall(SYS_memfd_create, name, flags) };
    trace!("memfd_create({:?}, {}) = {}", name, flags, retval);
    check_syscall(retval)?;
    Ok(unsafe { File::from_raw_fd(retval as c_int) })
}

pub(crate) fn fcntl_get_seals(file: &File) -> c_int {
    let fd: c_int = file.as_raw_fd();
    let flag: c_int = F_GET_SEALS;
    let retval = unsafe { syscall(SYS_fcntl, fd, flag) };
    trace!("fcntl({}, {}) = {}", fd, flag, retval);
    // the single caller of fcntl_get_seals (crate::is_sealed_inner) doesn't pass an error up and
    // just compares two values, so let's not bother checking the error response.
    retval as c_int
}

pub(crate) fn fcntl_add_seals(file: &File, arg: c_int) -> Result<()> {
    let fd: c_int = file.as_raw_fd();
    let flag: c_int = F_ADD_SEALS;
    let retval = unsafe { syscall(SYS_fcntl, fd, flag, arg) };
    trace!("fcntl({}, {}, {}) = {}", fd, flag, arg, retval);
    check_syscall(retval)
}

fn check_syscall(retval: c_long) -> Result<()> {
    if retval < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}
