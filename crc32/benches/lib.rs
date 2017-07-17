#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate crc_32 as crc32;

bench_digest!(crc32::CRC32);
