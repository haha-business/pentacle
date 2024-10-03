// Copyright (c) iliana destroyer of worlds <iliana@buttslol.net>
// SPDX-License-Identifier: MIT

use std::ffi::CStr;
use std::fmt::{self, Debug};
use std::fs::File;
use std::io::Error;
use std::os::unix::io::{AsRawFd, FromRawFd};

use libc::{
    c_char, c_int, c_long, c_uint, syscall, SYS_fcntl, SYS_memfd_create, F_ADD_SEALS, F_GET_SEALS,
    F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_WRITE, MFD_ALLOW_SEALING,
    MFD_CLOEXEC, MFD_EXEC, MFD_NOEXEC_SEAL,
};

// not yet present in the libc crate
// linux: include/uapi/linux/fcntl.h
const F_SEAL_EXEC: c_int = 0x0020;

pub(crate) fn memfd_create(name: &CStr, flags: MemfdFlags) -> Result<File, Error> {
    let name: *const c_char = name.as_ptr();
    let result = SyscallResult::new(unsafe { syscall(SYS_memfd_create, name, flags.0) });
    #[cfg(feature = "log")]
    log::trace!("memfd_create({name:?}, {flags:?}) = {result:?}");
    result.0.map(|value| unsafe { File::from_raw_fd(value) })
}

pub(crate) fn fcntl_get_seals(file: &File) -> Result<SealFlags, Error> {
    let fd: c_int = file.as_raw_fd();
    let result = SyscallResult::new(unsafe { syscall(SYS_fcntl, fd, F_GET_SEALS) });
    let result = SyscallResult(result.0.map(SealFlags));
    #[cfg(feature = "log")]
    log::trace!("fcntl({fd}, F_GET_SEALS) = {result:?}");
    result.0
}

pub(crate) fn fcntl_add_seals(file: &File, arg: SealFlags) -> Result<(), Error> {
    let fd: c_int = file.as_raw_fd();
    let result = SyscallResult::new(unsafe { syscall(SYS_fcntl, fd, F_ADD_SEALS, arg.0) });
    #[cfg(feature = "log")]
    log::trace!("fcntl({fd}, F_ADD_SEALS, {arg:?}) = {result:?}");
    result.0.map(|_| ())
}

#[repr(transparent)]
struct SyscallResult<T>(Result<T, Error>);

impl SyscallResult<c_int> {
    #[inline]
    fn new(value: c_long) -> Self {
        // The `syscall` function returns c_long regardless of the actual return value of the
        // syscall. In the case of memfd_create(2) and fcntl(2), both syscalls return c_int.
        // Truncation of the return value is correct behavior on Linux; see:
        // https://github.com/rust-lang/rust/blob/56e35a5dbb37898433a43133dff0398f46d577b8/library/std/src/sys/pal/unix/weak.rs#L160-L184
        #![allow(clippy::cast_possible_truncation)]
        let value = value as c_int;

        // memfd_create(2) and fcntl(2) both return -1 on error.
        if value == -1 {
            Self(Err(Error::last_os_error()))
        } else {
            Self(Ok(value))
        }
    }
}

impl<T: Debug> Debug for SyscallResult<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Ok(value) => write!(f, "{value:?}"),
            Err(err) => write!(f, "-1 {err}"),
        }
    }
}

/// "mom, can i have bitflags?" "we have bitflags at home"
macro_rules! flags_impl {
    ($struct:ident, $type:ty, $($name:ident => $flag:ident),* $(,)?) => {
        #[derive(Copy, Clone, PartialEq)]
        #[repr(transparent)]
        #[must_use]
        pub(crate) struct $struct($type);

        impl $struct {
            $(
                pub(crate) const $name: Self = Self($flag);
            )*
            const NAMES: &'static [($type, &'static str)] = &[$(($flag, stringify!($flag))),*];
            const KNOWN: $type = 0 $(| $flag)*;

            #[inline]
            #[allow(unused)]
            pub(crate) const fn all(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            #[inline]
            #[allow(unused)]
            pub(crate) const fn any(self, other: Self) -> bool {
                self.0 & other.0 != 0
            }

            #[inline]
            #[allow(unused)]
            pub(crate) const fn only(self, other: Self) -> Self {
                Self(self.0 & other.0)
            }

            #[inline]
            pub(crate) const fn set(self, other: Self, value: bool) -> Self {
                if value {
                    Self(self.0 | other.0)
                } else {
                    Self(self.0 & !(other.0 & Self::KNOWN))
                }
            }
        }

        impl Debug for $struct {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if self.0 == 0 {
                    return write!(f, "0");
                }
                let mut remaining = *self;
                let mut first = true;
                for (flag, name) in Self::NAMES {
                    if remaining.0 & flag != 0 {
                        write!(f, "{}{name}", if first { "" } else { "|" })?;
                        remaining = remaining.set(Self(*flag), false);
                        first = false;
                    }
                }
                if remaining.0 != 0 {
                    write!(f, "{}{:#x}", if first { "" } else { "|" }, remaining.0)?;
                }
                if !first {
                    write!(f, " ({:#x})", self.0)?;
                }
                Ok(())
            }
        }
    };
}

flags_impl!(
    MemfdFlags,
    c_uint,
    CLOEXEC => MFD_CLOEXEC,
    ALLOW_SEALING => MFD_ALLOW_SEALING,
    NOEXEC_SEAL => MFD_NOEXEC_SEAL,
    EXEC => MFD_EXEC,
);

flags_impl!(
    SealFlags,
    c_int,
    SEAL => F_SEAL_SEAL,
    SHRINK => F_SEAL_SHRINK,
    GROW => F_SEAL_GROW,
    WRITE => F_SEAL_WRITE,
    FUTURE_WRITE => F_SEAL_FUTURE_WRITE,
    EXEC => F_SEAL_EXEC,
);

#[cfg(test)]
mod test {
    use super::MemfdFlags;

    #[test]
    fn flags_debug() {
        assert_eq!(format!("{:?}", MemfdFlags(0)), "0");
        assert_eq!(format!("{:?}", MemfdFlags(0x1)), "MFD_CLOEXEC (0x1)");
        assert_eq!(
            format!("{:?}", MemfdFlags(0x3)),
            "MFD_CLOEXEC|MFD_ALLOW_SEALING (0x3)"
        );
        assert_eq!(format!("{:?}", MemfdFlags(0x80)), "0x80");
        assert_eq!(format!("{:?}", MemfdFlags(0x81)), "MFD_CLOEXEC|0x80 (0x81)");
    }
}
