use crate::runtime;

/// About 6.2 GB installed plus room to stage an update.
const MIN_FREE_BYTES: u64 = 8_000_000_000;

/// A reason this computer cannot run ElastOS at all.
pub fn refusal() -> Option<String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") | ("linux", "aarch64") | ("linux", "x86_64") => None,
        ("macos", _) => Some("ElastOS needs a Mac with Apple silicon.".into()),
        _ => Some("This lab app runs on macOS and Linux only.".into()),
    }
}

/// P1 does not install ElastOS; it says what is missing and what a first run needs.
pub fn not_installed() -> String {
    let free = runtime::home_dir().and_then(|home| fs4::available_space(home).ok());
    let mut message = String::from(
        "ElastOS is not installed for this user yet. Install it with the official installer, then open ElastOS Lab again.",
    );
    if let Some(free) = free.filter(|free| *free < MIN_FREE_BYTES) {
        message.push_str(&format!(
            "\n\nInstalling needs about 8 GB free; this Mac has {:.1} GB.",
            free as f64 / 1e9
        ));
    }
    message
}
