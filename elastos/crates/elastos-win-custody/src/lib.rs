//! Windows owner-only files. The current user owns each new file and directory,
//! the DACL does not inherit, and a reparse point is refused. A folder the
//! helper writes into may also grant SYSTEM and Administrators write, and an
//! existing accepted folder may be owned by the current user, SYSTEM, or
//! Administrators. Users and Everyone stay refused. The file itself stays
//! owner-only. Opens and renames are handle-relative, one component at a time.

mod error;
mod name;

#[cfg(windows)]
mod win;

pub use error::CustodyError;
pub use name::one_component_name;
#[cfg(windows)]
pub use win::{
    create_owner_dir, discard_owner_file, flush_accepted_directory, open_owner_dir,
    open_owner_file, refuse_other_writers, rename_owner_file, reopen_owner_file,
    replace_owner_file, verify_owner_only, Disp, ReplaceStep, READ_EXISTING, READ_WRITE,
};
