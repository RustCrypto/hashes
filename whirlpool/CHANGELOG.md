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
- `asm` crate feature ([#542])
- `std` crate feature ([#678])

[#542]: https://github.com/RustCrypto/hashes/pull/542
[#652]: https://github.com/RustCrypto/hashes/pull/652
[#678]: https://github.com/RustCrypto/hashes/pull/678

## 0.10.4 (2022-09-02)
### Fixed
- MSRV issue which was not resolved by v0.10.3 ([#401])

[#401]: https://github.com/RustCrypto/hashes/pull/401


## 0.10.3 (2022-09-02)
### Fixed
- MSRV issue caused by publishing v0.10.2 using a buggy Nightly toolchain ([#399])

[#399]: https://github.com/RustCrypto/hashes/pull/399

## 0.10.2 (2022-08-30)
### Changed
- Ignore `asm` feature on unsupported targets ([#388])

[#388]: https://github.com/RustCrypto/hashes/pull/388

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
- Upgrade to Rust 2018 edition ([#137])

[#168]: https://github.com/RustCrypto/hashes/pull/168
[#155]: https://github.com/RustCrypto/hashes/pull/155
[#153]: https://github.com/RustCrypto/hashes/pull/153
[#151]: https://github.com/RustCrypto/hashes/pull/151
[#148]: https://github.com/RustCrypto/hashes/pull/148
[#137]: https://github.com/RustCrypto/hashes/pull/148

## 0.8.1 (2018-11-14)

## 0.8.0 (2018-10-02)

## 0.7.1 (2018-04-27)

## 0.7.0 (2017-11-15)

## 0.6.0 (2017-06-12)

## 0.5.3 (2017-06-04)

## 0.5.2 (2017-05-09)

## 0.5.1 (2017-05-02)

## 0.5.0 (2017-04-06)

## 0.4.1 (2017-01-20)

## 0.4.0 (2016-12-25)

## 0.3.0 (2016-11-17)

## 0.2.0 (2016-10-14)

## 0.1.0 (2016-10-06)
