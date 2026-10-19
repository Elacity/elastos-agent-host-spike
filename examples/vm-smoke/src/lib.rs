//! A tiny project the small machine can test.
//!
//! `cargo test` for the host builds this. The machine runs the
//! compiled test program. It does not run the `cargo` command.

pub fn ready() -> &'static str {
    "ready"
}

/// Same digest as the guest `project_tree_hash`: sorted paths, then SHA-256.
pub fn project_digest(files: &[(&str, &str)]) -> String {
    use sha2::{Digest, Sha256};
    let mut ordered = files.to_vec();
    ordered.sort_by(|left, right| left.0.cmp(right.0));
    let mut body = String::new();
    for (path, text) in ordered {
        body.push_str(path);
        body.push('\n');
        body.push_str(text);
        body.push('\n');
    }
    format!("{:x}", Sha256::digest(body.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{project_digest, ready};

    #[test]
    fn project_is_ready() {
        assert_eq!(ready(), "ready");
        let root = std::path::Path::new("/project");
        if !root.is_dir() {
            return;
        }
        let index = std::fs::read_to_string(root.join("index.html")).expect("index");
        let style = std::fs::read_to_string(root.join("style.css")).expect("style");
        let notes = std::fs::read_to_string(root.join("notes.txt")).expect("notes");
        let digest = project_digest(&[
            ("index.html", &index),
            ("style.css", &style),
            ("notes.txt", &notes),
        ]);
        println!("project demo {digest}");
    }

    #[test]
    fn project_was_edited() {
        let root = std::path::Path::new("/project-edited");
        if !root.is_dir() {
            return;
        }
        let index = std::fs::read_to_string(root.join("index.html")).expect("index");
        let style = std::fs::read_to_string(root.join("style.css")).expect("style");
        let notes = std::fs::read_to_string(root.join("notes.txt")).expect("notes");
        let digest = project_digest(&[
            ("index.html", &index),
            ("style.css", &style),
            ("notes.txt", &notes),
        ]);
        println!("project note {notes}");
        println!("project demo {digest}");
    }

    #[test]
    fn a_missing_piece_fails() {
        assert_eq!(ready(), "missing");
    }
}
