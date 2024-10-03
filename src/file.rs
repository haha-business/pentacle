// Copyright (c) iliana destroyer of worlds <iliana@buttslol.net>
// SPDX-License-Identifier: MIT

//! Lower-level functions for creating sealed anonymous files.

use std::ffi::CStr;
use std::fmt::{self, Debug, Display};
use std::fs::{File, Permissions};
use std::io::{self, Error, ErrorKind, Read};
use std::os::unix::fs::PermissionsExt as _;

use libc::{
    c_int, c_uint, EINVAL, F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK,
    F_SEAL_WRITE, MFD_ALLOW_SEALING, MFD_CLOEXEC, MFD_EXEC, MFD_NOEXEC_SEAL,
};

// SAFETY: The provided slice is nul-terminated and does not contain any interior nul bytes. On Rust
// 1.64 and later (rust-lang/rust#99977), these required invariants are checked at compile time.
//
// The ideal alternative here is to use C-string literals, introduced in Rust 1.77, but that is a
// steep MSRV bump to introduce at time of writing this comment.
const DEFAULT_MEMFD_NAME: &CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(b"pentacle_sealed\0") };

// not yet present in the libc crate
// linux: include/uapi/linux/fcntl.h
const F_SEAL_EXEC: c_int = 0x0020;

macro_rules! set_flag {
    ($flags:expr, $flag:expr, $value:expr) => {
        if $value {
            $flags |= $flag;
        } else {
            $flags &= !$flag;
        }
    };
}

macro_rules! seal {
    (
        $seal_ident:ident
        $( { $( #[ $attr:meta ] )* } )? ,
        $must_seal_ident:ident
        $( { $( #[ $must_attr:meta ] )* } )? ,
        $( ? $preflight:ident : )? $flag:expr,
        $try_to:expr,
        $default:expr
    ) => {
        #[doc = concat!("If `true`, try to ", $try_to, ".")]
        #[doc = ""]
        #[doc = "If `false`, also set"]
        #[doc = concat!("[`SealOptions::", stringify!($must_seal_ident), "`]")]
        #[doc = "to `false`."]
        #[doc = ""]
        #[doc = concat!("This flag is `", $default, "` by default.")]
        $($( #[ $attr ] )*)?
        pub const fn $seal_ident(mut self, $seal_ident: bool) -> SealOptions<'a> {
            if true $( && self.$preflight() )? {
                set_flag!(self.seal_flags, $flag, $seal_ident);
            }
            if !$seal_ident {
                self.must_seal_flags &= !$flag;
            }
            self
        }

        #[doc = "If `true`, also set"]
        #[doc = concat!("[`SealOptions::", stringify!($seal_ident), "`] to `true`")]
        #[doc = "and ensure it is successful when [`SealOptions::seal`] is called."]
        #[doc = ""]
        #[doc = concat!("This flag is `", $default, "` by default.")]
        $($( #[ $must_attr ] )*)?
        pub const fn $must_seal_ident(mut self, $must_seal_ident: bool) -> SealOptions<'a> {
            if $must_seal_ident {
                self.seal_flags |= $flag;
            }
            set_flag!(self.must_seal_flags, $flag, $must_seal_ident);
            self
        }
    };
}

/// Options for creating a sealed anonymous file.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct SealOptions<'a> {
    memfd_name: &'a CStr,
    memfd_flags: c_uint,
    seal_flags: c_int,
    must_seal_flags: c_int,
}

impl<'a> SealOptions<'a> {
    /// Create a default set of options ready for configuration.
    ///
    /// This is equivalent to:
    /// ```
    /// # use pentacle::SealOptions;
    /// # let result =
    /// SealOptions::new()
    ///     .close_on_exec(true)
    ///     .memfd_name(c"pentacle_sealed")
    ///     .must_seal_seals(true)
    ///     .must_seal_shrinking(true)
    ///     .must_seal_growing(true)
    ///     .must_seal_writing(true)
    ///     .seal_future_writing(false)
    ///     .seal_executable(false);
    /// # assert_eq!(result, SealOptions::new());
    /// ```
    pub const fn new() -> SealOptions<'a> {
        SealOptions {
            memfd_name: DEFAULT_MEMFD_NAME,
            memfd_flags: MFD_ALLOW_SEALING | MFD_CLOEXEC,
            seal_flags: F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE,
            must_seal_flags: F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE,
        }
    }

    /// Sets the close-on-exec (`CLOEXEC`) flag for the new file.
    ///
    /// When a child process is created, the child normally inherits any open file descriptors.
    /// Setting the close-on-exec flag will cause this file descriptor to automatically be closed
    /// instead.
    ///
    /// This flag is `true` by default, matching the behavior of [`std::fs`].
    pub const fn close_on_exec(mut self, close_on_exec: bool) -> SealOptions<'a> {
        set_flag!(self.memfd_flags, MFD_CLOEXEC, close_on_exec);
        self
    }

    /// Sets whether the resulting file must have or not have execute permission set.
    ///
    /// If set, the OS is explicitly asked to set the execute permission when `exec` is
    /// `true`, or unset the execute permission when `exec` is `false`. If the OS refuses,
    /// [`SealOptions::create`] tries to set or unset the execute permission, and returns an error
    /// if it fails.
    ///
    /// Calling this function enables the equivalent of calling [`SealOptions::seal_executable`]
    /// with `true` for implementation reasons.
    ///
    /// This flag is neither `true` nor `false` by default; instead behavior is delegated to the
    /// OS's default behavior.
    ///
    /// # Context
    ///
    /// The original `memfd_create(2)` implementation on Linux creates anonymous files with the
    /// executable permission set. Later in Linux 6.3, programs and system administrators were
    /// given tools to control this (see also <https://lwn.net/Articles/918106/>):
    ///
    /// - Setting the sysctl `vm.memfd_noexec = 1` disables creating executable anonymous files
    ///   unless the program requests it with `MFD_EXEC`.
    /// - Setting the sysctl `vm.memfd_noexec = 2` disables the ability to create executable
    ///   anonymous files altogether, and `MFD_NOEXEC_SEAL` _must_ be used.
    /// - Calling `memfd_create(2)` with `MFD_NOEXEC_SEAL` enables the `F_SEAL_EXEC` seal.
    ///
    /// Linux prior to 6.3 is unaware of `MFD_EXEC` and `F_SEAL_EXEC`. If `memfd_create(2)` sets
    /// `errno` to `EINVAL`, this library retries the call without possibly-unknown flags, and the
    /// permission bits of the memfd are adjusted depending on this setting.
    pub const fn executable(mut self, executable: bool) -> SealOptions<'a> {
        self.memfd_flags = self.memfd_flags & !MFD_EXEC & !MFD_NOEXEC_SEAL
            | if executable {
                MFD_EXEC
            } else {
                MFD_NOEXEC_SEAL
            };
        self.seal_flags |= F_SEAL_EXEC;
        self
    }

    const fn is_executable_set(&self) -> bool {
        self.memfd_flags & (MFD_EXEC | MFD_NOEXEC_SEAL) != 0
    }

    /// Set a name for the file for debugging purposes.
    ///
    /// On Linux, this name is displayed as the target of the symlink in `/proc/self/fd/`.
    ///
    /// The default name is `pentacle_sealed`.
    pub const fn memfd_name(mut self, name: &'a CStr) -> SealOptions<'a> {
        self.memfd_name = name;
        self
    }

    seal!(
        seal_seals,
        must_seal_seals,
        F_SEAL_SEAL,
        "prevent further seals from being set on this file",
        true
    );
    seal!(
        seal_shrinking,
        must_seal_shrinking,
        F_SEAL_SHRINK,
        "prevent shrinking this file",
        true
    );
    seal!(
        seal_growing,
        must_seal_growing,
        F_SEAL_GROW,
        "prevent growing this file",
        true
    );
    seal!(
        seal_writing,
        must_seal_writing,
        F_SEAL_WRITE,
        "prevent writing to this file",
        true
    );
    seal!(
        seal_future_writing {
            #[doc = ""]
            #[doc = "This requires at least Linux 5.1."]
        },
        must_seal_future_writing {
            #[doc = ""]
            #[doc = "This requires at least Linux 5.1."]
        },
        F_SEAL_FUTURE_WRITE,
        "prevent directly writing to this file or creating new writable mappings, \
            but allow writes to existing writable mappings",
        false
    );
    seal!(
        seal_executable {
            #[doc = ""]
            #[doc = "If [`SealOptions::executable`] has already been called,"]
            #[doc = "this function does nothing."]
            #[doc = ""]
            #[doc = "This requires at least Linux 6.3."]
        },
        must_seal_executable {
            #[doc = ""]
            #[doc = "This requires at least Linux 6.3."]
        },
        ? seal_executable_preflight : F_SEAL_EXEC,
        "prevent modifying the executable permission of the file",
        false
    );

    const fn seal_executable_preflight(&self) -> bool {
        !self.is_executable_set()
    }

    /// Create an anonymous file, copy the contents of `reader` to it, and seal it.
    ///
    /// This is equivalent to:
    /// ```
    /// # let options = pentacle::SealOptions::new();
    /// # let reader: &mut &[u8] = &mut &[][..];
    /// let mut file = options.create()?;
    /// std::io::copy(reader, &mut file)?;
    /// options.seal(&mut file)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// This method returns an error when any of [`SealOptions::create`], [`std::io::copy`], or
    /// [`SealOptions::seal`] fail.
    pub fn copy_and_seal<R: Read>(&self, reader: &mut R) -> Result<File, Error> {
        let mut file = self.create()?;
        io::copy(reader, &mut file)?;
        self.seal(&mut file)?;
        Ok(file)
    }

    /// Create an unsealed anonymous file with these options.
    ///
    /// It is the caller's responsibility to seal this file after writing with
    /// [`SealOptions::seal`]. If possible, avoid using this function and prefer
    /// [`SealOptions::copy_and_seal`].
    ///
    /// # Errors
    ///
    /// This method returns an error when:
    /// - `memfd_create(2)` fails
    /// - `SealOptions::executable` was set but permissions cannot be changed as required
    pub fn create(&self) -> Result<File, Error> {
        let file = match crate::syscall::memfd_create(self.memfd_name, self.memfd_flags) {
            Ok(file) => file,
            Err(err) if err.raw_os_error() == Some(EINVAL) && self.is_executable_set() => {
                // Linux prior to 6.3 will not know about `MFD_EXEC` or `MFD_NOEXEC_SEAL`,
                // and returns `EINVAL` when it gets unknown flag bits. Retry without the
                // possibly-unknown flag, and then attempt to set the appropriate permissions.
                //
                // (If `vm.memfd_noexec = 2`, we won't hit this branch because the OS returns
                // EACCES.)
                crate::syscall::memfd_create(
                    self.memfd_name,
                    self.memfd_flags & !MFD_EXEC & !MFD_NOEXEC_SEAL,
                )?
            }
            Err(err) => return Err(err),
        };

        if self.is_executable_set() {
            let permissions = file.metadata()?.permissions();
            let new_permissions =
                Permissions::from_mode(if self.memfd_flags & MFD_NOEXEC_SEAL != 0 {
                    permissions.mode() & !0o111
                } else if self.memfd_flags & MFD_EXEC != 0 {
                    permissions.mode() | 0o111
                } else {
                    return Ok(file);
                });
            if permissions != new_permissions {
                file.set_permissions(new_permissions)?;
            }
        }

        Ok(file)
    }

    /// Seal an anonymous file with these options.
    ///
    /// This should be called on a file created with [`SealOptions::create`]. Attempting to use
    /// this method on other files will likely fail.
    ///
    /// # Errors
    ///
    /// This method returns an error when:
    /// - the `fcntl(2)` `F_ADD_SEALS` command fails (other than `EINVAL`)
    /// - the `fcntl(2)` `F_GET_SEALS` command fails
    /// - if any required seals are not present (in this case,
    ///   [`Error::source`][`std::error::Error::source`] will be [`MustSealError`])
    pub fn seal(&self, file: &mut File) -> Result<(), Error> {
        // Set seals in groups, based on how recently the seal was added to Linux. Ignore `EINVAL`;
        // we'll verify against `self.must_seal_flags`.
        for group in [
            F_SEAL_EXEC,                                              // Linux 6.3
            F_SEAL_FUTURE_WRITE,                                      // Linux 5.1
            F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE, // Linux 3.17
        ] {
            match crate::syscall::fcntl_add_seals(file, self.seal_flags & group) {
                Ok(()) => {}
                Err(err) if err.raw_os_error() == Some(EINVAL) => {}
                Err(err) => return Err(err),
            }
        }

        if self.is_sealed_inner(file)? {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                MustSealError { _priv: () },
            ))
        }
    }

    /// Check if `file` is sealed as required by these options.
    ///
    /// If the file doesn't support sealing (or `fcntl(2)` otherwise returns an error), this method
    /// returns `false`.
    pub fn is_sealed(&self, file: &File) -> bool {
        self.is_sealed_inner(file).unwrap_or(false)
    }

    fn is_sealed_inner(&self, file: &File) -> Result<bool, Error> {
        Ok(crate::syscall::fcntl_get_seals(file)? & self.must_seal_flags == self.must_seal_flags)
    }
}

impl<'a> Default for SealOptions<'a> {
    fn default() -> SealOptions<'a> {
        SealOptions::new()
    }
}

/// The [`Error::source`][`std::error::Error::source`] returned by [`SealOptions::seal`] if required
/// seals are not present.
#[allow(missing_copy_implementations)]
pub struct MustSealError {
    _priv: (),
}

impl Debug for MustSealError {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MustSealError").finish_non_exhaustive()
    }
}

impl Display for MustSealError {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "some required seals are not present")
    }
}

impl std::error::Error for MustSealError {}

#[cfg(test)]
mod test {
    use std::ffi::CString;
    use std::os::unix::fs::PermissionsExt as _;

    use super::{
        c_int, SealOptions, DEFAULT_MEMFD_NAME, F_SEAL_EXEC, F_SEAL_FUTURE_WRITE, F_SEAL_GROW,
        F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_WRITE, MFD_ALLOW_SEALING, MFD_CLOEXEC, MFD_EXEC,
        MFD_NOEXEC_SEAL,
    };

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn new() {
        let options = SealOptions {
            memfd_name: &CString::new("asdf").unwrap(),
            memfd_flags: MFD_ALLOW_SEALING,
            seal_flags: 0,
            must_seal_flags: 0,
        };
        assert_eq!(
            options
                .close_on_exec(true)
                .memfd_name(DEFAULT_MEMFD_NAME)
                .must_seal_seals(true)
                .must_seal_shrinking(true)
                .must_seal_growing(true)
                .must_seal_writing(true)
                .seal_future_writing(false)
                .seal_executable(false),
            SealOptions::new()
        );
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn flags() {
        const ALL_SEALS: c_int = F_SEAL_SEAL
            | F_SEAL_SHRINK
            | F_SEAL_GROW
            | F_SEAL_WRITE
            | F_SEAL_FUTURE_WRITE
            | F_SEAL_EXEC;

        let mut options = SealOptions::new();
        assert_eq!(options.memfd_flags & MFD_ALLOW_SEALING, MFD_ALLOW_SEALING);

        assert_eq!(options.memfd_flags & MFD_CLOEXEC, MFD_CLOEXEC);
        options = options.close_on_exec(false);
        assert_eq!(options.memfd_flags & MFD_CLOEXEC, 0);
        options = options.close_on_exec(true);
        assert_eq!(options.memfd_flags & MFD_CLOEXEC, MFD_CLOEXEC);

        assert_eq!(
            options.seal_flags & ALL_SEALS,
            ALL_SEALS & !F_SEAL_FUTURE_WRITE & !F_SEAL_EXEC
        );
        assert_eq!(
            options.must_seal_flags & ALL_SEALS,
            ALL_SEALS & !F_SEAL_FUTURE_WRITE & !F_SEAL_EXEC
        );
        options = options
            .must_seal_future_writing(true)
            .must_seal_executable(true);
        assert_eq!(options.seal_flags & ALL_SEALS, ALL_SEALS);
        assert_eq!(options.must_seal_flags & ALL_SEALS, ALL_SEALS);
        // `seal_*(false)` unsets `must_seal_*`
        options = options
            .seal_seals(false)
            .seal_shrinking(false)
            .seal_growing(false)
            .seal_writing(false)
            .seal_future_writing(false)
            .seal_executable(false);
        assert_eq!(options.seal_flags & ALL_SEALS, 0);
        assert_eq!(options.must_seal_flags & ALL_SEALS, 0);
        // `seal_*(true)` does not set `must_seal_*`
        options = options
            .seal_seals(true)
            .seal_shrinking(true)
            .seal_growing(true)
            .seal_writing(true)
            .seal_future_writing(true)
            .seal_executable(true);
        assert_eq!(options.seal_flags & ALL_SEALS, ALL_SEALS);
        assert_eq!(options.must_seal_flags & ALL_SEALS, 0);
        // `must_seal_*(true)` sets `seal_*`
        options = options
            .seal_seals(false)
            .seal_shrinking(false)
            .seal_growing(false)
            .seal_writing(false)
            .seal_future_writing(false)
            .seal_executable(false);
        assert_eq!(options.seal_flags & ALL_SEALS, 0);
        assert_eq!(options.must_seal_flags & ALL_SEALS, 0);
        options = options
            .must_seal_seals(true)
            .must_seal_shrinking(true)
            .must_seal_growing(true)
            .must_seal_writing(true)
            .must_seal_future_writing(true)
            .must_seal_executable(true);
        assert_eq!(options.seal_flags & ALL_SEALS, ALL_SEALS);
        assert_eq!(options.must_seal_flags & ALL_SEALS, ALL_SEALS);
        // `must_seal_*(false)` does not unset `seal_*`
        options = options
            .must_seal_seals(false)
            .must_seal_shrinking(false)
            .must_seal_growing(false)
            .must_seal_writing(false)
            .must_seal_future_writing(false)
            .must_seal_executable(false);
        assert_eq!(options.seal_flags & ALL_SEALS, ALL_SEALS);
        assert_eq!(options.must_seal_flags & ALL_SEALS, 0);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn execute_flags() {
        let mut options = SealOptions::new();
        assert_eq!(options.seal_flags & F_SEAL_EXEC, 0);
        options = options.seal_executable(true);
        assert_eq!(options.seal_flags & F_SEAL_EXEC, F_SEAL_EXEC);
        options = options.seal_executable(false);
        assert_eq!(options.seal_flags & F_SEAL_EXEC, 0);

        for _ in 0..2 {
            options = options.executable(true);
            assert_eq!(options.memfd_flags & (MFD_EXEC | MFD_NOEXEC_SEAL), MFD_EXEC);
            assert_eq!(options.seal_flags & F_SEAL_EXEC, F_SEAL_EXEC);
            // no-op once `executable` is called
            options = options.seal_executable(false);
            assert_eq!(options.seal_flags & F_SEAL_EXEC, F_SEAL_EXEC);

            options = options.executable(false);
            assert_eq!(
                options.memfd_flags & (MFD_EXEC | MFD_NOEXEC_SEAL),
                MFD_NOEXEC_SEAL
            );
            assert_eq!(options.seal_flags & F_SEAL_EXEC, F_SEAL_EXEC);
            // no-op once `executable` is called
            options = options.seal_executable(false);
            assert_eq!(options.seal_flags & F_SEAL_EXEC, F_SEAL_EXEC);
        }

        assert_eq!(options.must_seal_flags & F_SEAL_EXEC, 0);
        options = options.must_seal_executable(true);
        assert_eq!(options.seal_flags & F_SEAL_EXEC, F_SEAL_EXEC);
        assert_eq!(options.must_seal_flags & F_SEAL_EXEC, F_SEAL_EXEC);
        options = options.seal_executable(false);
        assert_eq!(options.seal_flags & F_SEAL_EXEC, F_SEAL_EXEC);
        assert_eq!(options.must_seal_flags & F_SEAL_EXEC, 0);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn executable() {
        let file = SealOptions::new()
            .executable(false)
            .copy_and_seal(&mut &[][..])
            .unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o111, 0);

        let file = SealOptions::new()
            .executable(true)
            .copy_and_seal(&mut &[][..])
            .unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o111, 0o111);
    }
}
