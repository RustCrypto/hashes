# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (2020-06-09)
### Changed
- Update to `digest` v0.9 release; MSRV 1.41+ ([#155])
- Use `digest` crate's `alloc` feature ([#150])
- Impl the `ExtendableOutput` trait ([#149])
- Rename `*result*` to `finalize` ([#148])
- Upgrade to Rust 2018 edition ([#123])

[#155]: https://github.com/RustCrypto/hashes/pull/155
[#150]: https://github.com/RustCrypto/hashes/pull/150
[#149]: https://github.com/RustCrypto/hashes/pull/149
[#148]: https://github.com/RustCrypto/hashes/pull/148
[#123]: https://github.com/RustCrypto/hashes/pull/123

## 0.0.1 (2020-05-24)
- Initial release
