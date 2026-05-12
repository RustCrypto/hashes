# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 (2026-05-12)
### Added
- `CShake128Reader` and `CShake256Reader` type aliases ([#855])

### Changed
- Internal implementation by removing unnecessary buffering ([#849])
- `Rate: BlockSizes` generic parameter to `const RATE: usize` ([#849])

### Removed
- Implementations of `BlockSizeUser` ([#856])

[#849]: https://github.com/RustCrypto/hashes/pull/849
[#855]: https://github.com/RustCrypto/hashes/pull/855
[#856]: https://github.com/RustCrypto/hashes/pull/856

## 0.1.1 (2026-04-19)
### Fixed
- Non-compliant initialization when serialized length of function name and customization string
  is a multiple of the block size ([#834])

[#834]: https://github.com/RustCrypto/hashes/pull/834

## 0.1.0 (2026-04-13)
- Initial release with implementation moved from the `sha3` crate ([#815])

[#815]: https://github.com/RustCrypto/hashes/pull/815
