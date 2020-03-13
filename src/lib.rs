// Copyright (c) 2019 iliana destroyer of worlds <iliana@buttslol.net>
// SPDX-License-Identifier: MIT

//! pentacle is a library for executing programs as sealed anonymous files on Linux, using
//! `memfd_create(2)`.
//!
//! This is useful for executing programs that execute untrusted programs with root permissions, or
//! ensuring a cryptographically-verified program is not tampered with after verification but
//! before execution.
//!
//! The library provides [a wrapper around `Command`][`SealedCommand`] as well as two helper
//! functions for programs that execute sealed versions of themselves.
//!
//! ```
//! fn main() {
//!     pentacle::ensure_sealed().unwrap();
//!
//!     // The rest of your code
//! }
//! ```

#![deny(
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unstable_features
)]
#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::needless_doctest_main)]

#[cfg(not(any(target_os = "linux", target_os = "android")))]
compile_error!("pentacle only works on linux or android");

mod syscall;

use crate::syscall::{fcntl_add_seals, fcntl_get_seals, memfd_create};
use libc::{F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_WRITE, MFD_ALLOW_SEALING, MFD_CLOEXEC};
use std::ffi::CStr;
use std::fmt::{self, Debug};
use std::fs::File;
use std::io::{self, Read, Result};
use std::ops::{Deref, DerefMut};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

const MEMFD_SEALS: libc::c_int = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

/// Ensure the currently running program is a sealed anonymous file.
///
/// If `/proc/self/exe` is not a sealed anonymous file, a new anonymous file is created,
/// `/proc/self/exe` is copied to it, the file is sealed, and [`CommandExt::exec`] is called. When
/// the program begins again, this function will detect `/proc/self/exe` as a sealed anonymous
/// file and return `Ok(())`.
///
/// You should call this function at the beginning of `main`. This function has the same
/// implications as [`CommandExt::exec`]: no destructors on the current stack or any other thread’s
/// stack will be run.
///
/// # Compatibility
///
/// This library is unable to set the program name (`argv[0]`), which will cause unexpected
/// behavior for multi-call binaries and other programs that use the program name.
///
/// # Errors
///
/// An error is returned if `/proc/self/exe` fails to open, `memfd_create(2)` fails, the `fcntl(2)`
/// `F_ADD_SEALS` command fails, or copying from `/proc/self/exe` to the anonymous file fails.
pub fn ensure_sealed() -> Result<()> {
    let mut file = File::open("/proc/self/exe")?;
    if is_sealed_inner(&file) {
        Ok(())
    } else {
        Err(SealedCommand::new(&mut file)?
            .args(std::env::args_os().skip(1))
            .exec())
    }
}

/// Verify whether the currently running program is a sealed anonymous file.
///
/// This function returns `false` if opening `/proc/self/exe` fails.
pub fn is_sealed() -> bool {
    File::open("/proc/self/exe")
        .map(|f| is_sealed_inner(&f))
        .unwrap_or(false)
}

fn is_sealed_inner(file: &File) -> bool {
    fcntl_get_seals(file) == MEMFD_SEALS
}

/// A [`Command`] wrapper that spawns sealed memory-backed programs.
///
/// You can use the standard [`Command`] builder methods (such as [`spawn`][`Command::spawn`] and
/// [`CommandExt::exec`]) via [`Deref` coercion][`DerefMut`].
pub struct SealedCommand {
    inner: Command,
    // we need to keep this memfd open for the lifetime of this struct
    _memfd: File,
}

impl SealedCommand {
    /// Constructs a new [`Command`] for launching the program data in `program` as a sealed
    /// memory-backed file, with the same default configuration as [`Command::new`].
    ///
    /// # Compatibility
    ///
    /// This library is unable to set the program name (`argv[0]`), which will cause unexpected
    /// behavior for multi-call binaries and other programs that use the program name.
    ///
    /// # Errors
    ///
    /// An error is returned if `memfd_create(2)` fails, the `fcntl(2)` `F_ADD_SEALS` command
    /// fails, or copying from `program` to the anonymous file fails.
    pub fn new<R: Read>(program: &mut R) -> Result<Self> {
        let memfd_name = unsafe { CStr::from_bytes_with_nul_unchecked(b"pentacle_sealed\0") };
        let mut memfd = memfd_create(memfd_name, MFD_CLOEXEC | MFD_ALLOW_SEALING)?;
        io::copy(program, &mut memfd)?;
        fcntl_add_seals(&memfd, MEMFD_SEALS)?;

        Ok(Self {
            inner: Command::new(format!("/proc/self/fd/{}", memfd.as_raw_fd())),
            _memfd: memfd,
        })
    }
}

impl Debug for SealedCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl Deref for SealedCommand {
    type Target = Command;

    fn deref(&self) -> &Command {
        &self.inner
    }
}

impl DerefMut for SealedCommand {
    fn deref_mut(&mut self) -> &mut Command {
        &mut self.inner
    }
}
