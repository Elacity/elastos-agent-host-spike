#[cfg(unix)]
include!("browser-vz-engine-supervisor/unix.rs");

#[cfg(windows)]
fn main() {
    eprintln!("MicroVM backend unavailable on Windows");
    std::process::exit(1);
}
