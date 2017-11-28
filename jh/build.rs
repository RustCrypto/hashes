extern crate cc;

fn main() {
    cc::Build::new().file("src/jh_sse2_opt64.c").compile("jh");
}
