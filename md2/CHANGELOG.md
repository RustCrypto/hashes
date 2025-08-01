# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.11.0 (UNRELEASED)
### Added
- `alloc` crate feature ([#678])

### Changed
- Edition changed to 2024 and MSRV bumped to 1.85 ([#652])
- Relax MSRV policy and allow MSRV bumps in patch releases
- Update to `digest` v0.11
- Replace type aliases with newtypes ([#678])

### Removed
- `std` crate feature ([#678])

[#652]: https://github.com/RustCrypto/hashes/pull/652
[#678]: https://github.com/RustCrypto/hashes/pull/678

## 0.10.2 (2022-10-05)
### Added
- Feature-gated OID support ([#419])

[#419]: https://github.com/RustCrypto/hashes/pull/419

## 0.10.1 (2022-02-17)
### Fixed
- Minimal versions build ([#363])

[#363]: https://github.com/RustCrypto/hashes/pull/363

## 0.10.0 (2021-12-07)
### Changed
- Update to `digest` v0.10 ([#217])

[#217]: https://github.com/RustCrypto/hashes/pull/217

## 0.9.0 (2020-06-12)
### Changed
- Bump `opaque-debug` to v0.3.0 ([#168])
- Bump `digest` to v0.9 release; MSRV 1.41 ([#155])
- Use new `*Dirty` traits from the `digest` crate ([#153])
- Bump `block-buffer` to v0.8 release ([#151])
- Rename `*result*` to `finalize` ([#148])
- Upgrade to Rust 2018 edition ([#125])

[#168]: https://github.com/RustCrypto/hashes/pull/168
[#155]: https://github.com/RustCrypto/hashes/pull/155
[#153]: https://github.com/RustCrypto/hashes/pull/153
[#151]: https://github.com/RustCrypto/hashes/pull/151
[#148]: https://github.com/RustCrypto/hashes/pull/148
[#125]: https://github.com/RustCrypto/hashes/pull/125

## 0.8.0 (2018-10-02)

## 0.7.0 (2017-11-15)

## 0.3.0 (2017-06-12)

## 0.2.1 (2017-05-02)

## 0.2.0 (2017-04-06)

## 0.1.2 (2017-01-20)

## 0.1.1 (2017-01-12)

## 0.1.0 (2017-01-09)
