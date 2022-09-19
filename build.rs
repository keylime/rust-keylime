fn main() {
    if let Ok(val) = std::env::var("KEYLIME_TEST") {
        if val == "true" || val == "True" {
            println!("cargo:rustc-cfg=`feature=\"testing\"`");
        }
    }
}
