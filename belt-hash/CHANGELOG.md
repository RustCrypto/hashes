# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 (UNRELEASED)
### Added
- `alloc` crate feature ([#678])

### Changed
- Edition changed to 2024 and MSRV bumped to 1.85 ([#652])
- Relax MSRV policy and allow MSRV bumps in patch releases
- Update to `digest` v0.11
- Replace type aliases with newtypes ([#678])
- Implementation of the `SerializableState` trait ([#716])

### Removed
- `std` crate feature ([#678])

[#652]: https://github.com/RustCrypto/hashes/pull/652
[#678]: https://github.com/RustCrypto/hashes/pull/678
[#716]: https://github.com/RustCrypto/hashes/pull/716

## 0.1.1 (2022-11-22)
### Added
- `belt_compress` function ([#520])

[#520]: https://github.com/RustCrypto/hashes/pull/520

## 0.1.0 (2022-09-23)
- Initial release ([#416])

[#416]: https://github.com/RustCrypto/hashes/pull/416
