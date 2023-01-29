// TODO (laudiacay): here, do the switch to figure out which architecture's method we'll do...
// here's how that md5 PR did it (obviously wrong for what we want here...)
// #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
// mod x86;
//
// #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
// pub use x86::compress;
