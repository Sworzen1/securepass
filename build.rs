use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let to_path = Path::new(&target_dir).join("package/securepass-0.2.1/dictionary.txt");

    let from_path = "dictionary.txt";

    fs::copy(
        from_path,
        to_path
    ).unwrap();

}
