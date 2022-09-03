# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.3 (2022-09-03)
### Fixed
- MSRV issue caused by `resolver = "2"` ([#402])

[#402]: https://github.com/RustCrypto/hashes/pull/402

## 0.1.2 (2022-06-16)
### Fixed
- Incorrect computation of hash on some inputs ([#379])

[#379]: https://github.com/RustCrypto/hashes/pull/379

## 0.1.1 (2022-02-17) [YANKED]
### Fixed
- Minimal versions build ([#363])

[#363]: https://github.com/RustCrypto/hashes/pull/363

## 0.1.0 (2021-12-07) [YANKED]
### Changed
- Update to `digest` v0.10 ([#217])

[#217]: https://github.com/RustCrypto/hashes/pull/217

## 0.0.2 (2020-07-21) [YANKED]
- Fixed `Reset` implementation bug. Reduce crate size by using binary dump
of `PI` ([#300])

[#300]: https://github.com/RustCrypto/hashes/pull/300

## 0.0.1 (2020-07-18) [YANKED]
- Initial release
