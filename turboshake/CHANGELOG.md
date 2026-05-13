# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.0 (2026-05-13)
### Added
- `CTurboShake128` and `CTurboShake256` type aliases generic over domain separator ([#866])

### Changed
- Internal implementation by removing unnecessary buffering ([#849])
- `Rate: BlockSizes` generic parameter to `const RATE: usize` ([#849])
- `TurboShake128` and `TurboShake256` type aliases are no longer generic over the domain separator
  and use the default value instead ([#866])

### Removed
- Implementations of `BlockSizeUser` ([#856])

[#849]: https://github.com/RustCrypto/hashes/pull/849
[#856]: https://github.com/RustCrypto/hashes/pull/856
[#866]: https://github.com/RustCrypto/hashes/pull/866

## 0.6.0 (2026-04-24)
Note: the crate was transferred to RustCrypto from https://github.com/itzmeanjan/turboshake

### Changed
- New implementation moved from the `sha3` crate ([#815])

[#815]: https://github.com/RustCrypto/hashes/pull/815
