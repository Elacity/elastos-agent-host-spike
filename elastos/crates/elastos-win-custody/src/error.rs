use std::fmt;
use std::io;

/// Why an owner-only open or check stopped.
#[derive(Debug)]
pub enum CustodyError {
    /// A junction, symlink, or other reparse point. Nothing was written.
    ReparsePoint {
        path: String,
    },
    /// The owner is not the current user.
    NotOwner {
        path: String,
    },
    /// The DACL is missing, inherits, or names anyone besides the owner.
    ForeignDacl {
        path: String,
    },
    /// Whole sentence, house style: "… is unsupported on Windows".
    Unsupported(&'static str),
    Io(io::Error),
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReparsePoint { path } => write!(f, "reparse point refused: {path}"),
            Self::NotOwner { path } => write!(f, "owner is not the current user: {path}"),
            Self::ForeignDacl { path } => write!(f, "DACL is not owner-only: {path}"),
            Self::Unsupported(sentence) => f.write_str(sentence),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CustodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn custody_error_display_names_the_refusal() {
        let path = "C:\\k";
        assert_eq!(
            CustodyError::ReparsePoint { path: path.into() }.to_string(),
            "reparse point refused: C:\\k"
        );
        assert_eq!(
            CustodyError::NotOwner { path: path.into() }.to_string(),
            "owner is not the current user: C:\\k"
        );
        assert_eq!(
            CustodyError::ForeignDacl { path: path.into() }.to_string(),
            "DACL is not owner-only: C:\\k"
        );
        let unsupported = CustodyError::Unsupported("owner-only files are unsupported on Windows");
        assert_eq!(
            unsupported.to_string(),
            "owner-only files are unsupported on Windows"
        );
        assert!(unsupported.source().is_none());
        let io = CustodyError::Io(io::Error::new(io::ErrorKind::NotFound, "missing"));
        assert_eq!(io.to_string(), "missing");
        assert!(io.source().is_some());
    }
}
