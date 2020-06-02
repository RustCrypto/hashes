use md2::{Digest, Md2};
use std::env;
use std::fs;
use std::io::{self, Read};

const BUFFER_SIZE: usize = 1024;

/// Compute digest value for given `Reader` and print it
/// On any error simply return without doing anything
fn process<R: Read>(reader: &mut R, name: &str) {
    let mut sh = Md2::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = match reader.read(&mut buffer) {
            Ok(n) => n,
            Err(_) => return,
        };
        sh.update(&buffer[..n]);
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
    }
    println!("{:x}\t{}", &sh.finalize(), name);
}

fn main() {
    let args = env::args();
    // Process files listed in command line arguments one by one
    // If no files provided process input from stdin
    if args.len() > 1 {
        for path in args.skip(1) {
            if let Ok(mut file) = fs::File::open(&path) {
                process(&mut file, &path);
            }
        }
    } else {
        process(&mut io::stdin(), "-");
    }
}
