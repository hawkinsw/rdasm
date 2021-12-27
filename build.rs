// build.rs
extern crate cmake;
use std::{path::Path, env};

use cmake::Config;

fn main() {
    let out_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    eprintln!("Building example hello binary into {:?}", out_dir);
    let dest_path = Path::new(&out_dir);
    Config::new("example").out_dir(dest_path).target("hello").no_build_target(true).build();
}
