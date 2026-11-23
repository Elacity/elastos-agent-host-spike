//! Windows owner-only files. The current user owns each new file and directory,
//! the DACL does not inherit, and a reparse point is refused. Opens are
//! handle-relative, one component at a time.

mod error;
mod name;

#[cfg(windows)]
mod win;

pub use error::CustodyError;
pub use name::one_component_name;
#[cfg(windows)]
pub use win::{create_owner_dir, open_owner_file, verify_owner_only, Disp};
