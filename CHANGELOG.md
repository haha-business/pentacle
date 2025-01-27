# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2024-10-03
### Added
- `SealOptions`, an interface for directly creating and sealing anonymous files outside the context
  of executing them

### Fixed
- Creating executable anonymous files works correctly since Linux 6.3 when the sysctl
  `vm.memfd_noexec = 1` is set
- `is_sealed` correctly handles the presence of additional seals (e.g. `F_SEAL_FUTURE_WRITE` since
  Linux 5.1 or `F_SEAL_EXEC` since Linux 6.3)

### Changed
- `SealedCommand` and `execute_sealed` set `F_SEAL_EXEC` on Linux 6.3 and newer
- `log` is now an optional dependency (remains enabled by default)
- Log messages use symbolic names for syscall values
- Moved source repository to <https://github.com/haha-business/pentacle>
- Minimum supported Rust version (MSRV) now 1.59.0

## [1.0.0] - 2020-09-29
### Changed
- Set `argv[0]` to the original `argv[0]` in `ensure_sealed`
- Minimum supported Rust version (MSRV) now 1.45.0

## [0.2.0] - 2020-06-23
### Changed
- No longer set `MFD_CLOEXEC` if `#!` is detected at the beginning of a program

## [0.1.1] - 2020-03-15
### Changed
- Allow builds on Android platforms

## [0.1.0] - 2019-11-15
### Added
- Everything!

[Unreleased]: https://github.com/iliana/pentacle/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/iliana/pentacle/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/iliana/pentacle/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/iliana/pentacle/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/iliana/pentacle/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/iliana/pentacle/releases/tag/v0.1.0
