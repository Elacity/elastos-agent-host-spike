//! Static stand-in provider for the Jetson proof kit.
//! Prints one line and exits. Used when #307's fcl-probe is not found.
fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| "unknown".into());
    println!("stand-in provider={name}");
}
