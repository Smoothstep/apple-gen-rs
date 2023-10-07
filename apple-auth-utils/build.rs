use std::{path};

extern crate cc;
extern crate cmake;
use cmake::Config;

fn main() {
    let mut config = Config::new(path::Path::new("apple_crypto"));
    
    #[cfg(target_os = "windows")]
    {
        config.generator_toolset("ClangCL");
    }

    config.very_verbose(true).build();
    
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = std::env::var("OUT_DIR").unwrap();

    println!("cargo:rustc-link-search={}", path::Path::new(&dir).join("../").display());
    println!("cargo:rustc-link-search={}", path::Path::new(&out_dir).display());


    //println!("cargo:rustc-link-lib=apple_crypto");
    //println!("cargo:rustc-link-lib=apple_crypto");

    println!("cargo:rustc-link-lib=static=apple_crypto");
    
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=stdc++");
    }
}