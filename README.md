# pentacle

pentacle is a library for executing programs as sealed anonymous files on Linux, using `memfd_create(2)`. It also has a lower-level interface for creating and sealing anonymous files with various flags.

This is useful for executing programs that execute untrusted programs with root permissions, or ensuring a cryptographically-verified program is not tampered with after verification but before execution.

This library is based on [runc's cloned_binary.c](https://github.com/opencontainers/runc/blob/master/libcontainer/nsenter/cloned_binary.c).
