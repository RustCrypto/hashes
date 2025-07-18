# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (UNRELEASED)
### Added
- `alloc` crate feature ([#678])
- `oid` crate feature and `AssociatedOid` trait implementation ([#706])

### Changed
- Edition changed to 2024 and MSRV bumped to 1.85 ([#652])
- Relax MSRV policy and allow MSRV bumps in patch releases
- Update to `digest` v0.11
- Replace type aliases with newtypes ([#678])

### Removed
- `std` crate feature ([#678])

[#652]: https://github.com/RustCrypto/hashes/pull/652
[#678]: https://github.com/RustCrypto/hashes/pull/678
[#706]: https://github.com/RustCrypto/hashes/pull/706

## 0.4.2 (2023-05-16)
### Changed
- Minor performance improvement ([#477])

[#477]: https://github.com/RustCrypto/hashes/pull/477

## 0.4.1 (2022-02-17)
### Fixed
- Minimal versions build ([#363])

[#363]: https://github.com/RustCrypto/hashes/pull/363

## 0.4.0 (2021-12-07)
### Changed
- Update to `digest` v0.10 ([#217])

[#217]: https://github.com/RustCrypto/hashes/pull/217

## 0.3.0 (2021-07-18)
### Changed
- RustCrypto SM3 release ([#249])

[#249]: https://github.com/RustCrypto/hashes/pull/249

## 0.2.0 (2020-01-23)

## 0.1.0 (2020-01-14)
