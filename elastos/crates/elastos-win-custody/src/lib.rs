//! Windows owner-only files. The current user owns each new file and directory,
//! the DACL does not inherit, and a reparse point is refused. Opens and renames
//! are handle-relative, one component at a time.

mod error;
mod name;

#[cfg(windows)]
mod win;

pub use error::CustodyError;
#[cfg(windows)]
pub use name::absolute_local_disk;
pub use name::one_component_name;
#[cfg(windows)]
pub use win::{
    create_owner_dir, discard_owner_file, open_accepted_file, open_owner_dir, open_owner_file,
    refuse_other_writers, rename_owner_file, reopen_owner_file, verify_owner_only, Disp,
    READ_EXISTING, READ_WRITE,
};
