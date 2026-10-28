// Built-by: deepseek-v4.1-flash-1017-ultrafast
//! Owner favourites, stored by CID (M2 PH6).
//!
//! Favourites name a picture by its content id, never by path: a path is the
//! surface's business, and a stored path would let one album re-point at a
//! different picture. Only a CID is accepted, so a `localhost://` uri or a
//! file name is refused `not-a-cid`.
//!
//! The store keeps favourites in first-favourited order (the order a person
//! would expect to see them) and caps them at [`MAX_FAVORITES`]. The cap is
//! refused `favorites-full` before any change is made.
//!
//! The persisted form is one CID per line (the roadmap's "simple line
//! format"). `load` refuses any line that is not a plain CID with
//! `bad-favorites-line`, naming the one-based line number.

use std::collections::BTreeSet;
use std::fmt;

/// How many favourites an owner may keep.
pub const MAX_FAVORITES: usize = 10_000;

/// The reason string for a full store.
pub const REASON_FULL: &str = "favorites-full";
/// The reason string for something that is not a CID.
pub const REASON_NOT_A_CID: &str = "not-a-cid";
/// The reason string for a persisted line that is not a CID.
pub const REASON_BAD_LINE: &str = "bad-favorites-line";

/// A refused favourites operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FavoritesError {
    /// The store already holds [`MAX_FAVORITES`] entries.
    FavoritesFull,
    /// The value is a path, a uri or otherwise not a CID.
    NotACid(String),
    /// A persisted line is not a CID.
    BadLine { line: usize, text: String },
}

impl FavoritesError {
    /// The stable reason string the surface shows.
    pub fn reason(&self) -> &'static str {
        match self {
            FavoritesError::FavoritesFull => REASON_FULL,
            FavoritesError::NotACid(_) => REASON_NOT_A_CID,
            FavoritesError::BadLine { .. } => REASON_BAD_LINE,
        }
    }
}

impl fmt::Display for FavoritesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FavoritesError::FavoritesFull => {
                write!(f, "{REASON_FULL}: at most {MAX_FAVORITES} favourites are kept")
            }
            FavoritesError::NotACid(text) => {
                write!(f, "{REASON_NOT_A_CID}: {text:?} is not a CID")
            }
            FavoritesError::BadLine { line, text } => {
                write!(f, "{REASON_BAD_LINE}: line {line} is {text:?}")
            }
        }
    }
}

impl std::error::Error for FavoritesError {}

/// The order favourites are listed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    /// First-favourited first, which is how a person adds them.
    Added,
    /// Sorted by CID, which is stable across devices.
    Cid,
}

/// One owner's favourites, keyed by CID.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Favorites {
    /// In first-favourited order; checked against the cap.
    added: Vec<String>,
    /// Membership, for `is_favorite` without a scan.
    members: BTreeSet<String>,
}

impl Favorites {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many favourites are kept.
    pub fn len(&self) -> usize {
        self.added.len()
    }

    /// True when nothing is favourited.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
    }

    /// True when `cid` is a favourite.
    pub fn is_favorite(&self, cid: &str) -> bool {
        self.members.contains(cid)
    }

    /// Adds `cid` if absent, removes it if present. Returns the new state
    /// (true when it is now a favourite).
    ///
    /// A non-CID is refused `not-a-cid`; adding past [`MAX_FAVORITES`] is
    /// refused `favorites-full` and leaves the store unchanged.
    pub fn toggle(&mut self, cid: &str) -> Result<bool, FavoritesError> {
        if !is_cid(cid) {
            return Err(FavoritesError::NotACid(cid.to_string()));
        }
        if self.members.remove(cid) {
            self.added.retain(|kept| kept != cid);
            return Ok(false);
        }
        if self.added.len() >= MAX_FAVORITES {
            return Err(FavoritesError::FavoritesFull);
        }
        self.added.push(cid.to_string());
        self.members.insert(cid.to_string());
        Ok(true)
    }

    /// The favourites as an ordered list.
    pub fn cids(&self, order: Order) -> Vec<String> {
        match order {
            Order::Added => self.added.clone(),
            // BTreeSet is already unique and sorted.
            Order::Cid => self.members.iter().cloned().collect(),
        }
    }

    /// The persisted form: one CID per line, in first-favourited order.
    pub fn to_lines(&self) -> String {
        let mut text = String::new();
        for cid in &self.added {
            text.push_str(cid);
            text.push('\n');
        }
        text
    }

    /// Reads the persisted form. Blank lines are ignored; any other line that
    /// is not a CID refuses the whole file with `bad-favorites-line`.
    pub fn load(text: &str) -> Result<Self, FavoritesError> {
        let mut favorites = Favorites::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            if !is_cid(line) {
                return Err(FavoritesError::BadLine {
                    line: index + 1,
                    text: line.to_string(),
                });
            }
            if favorites.members.contains(line) {
                continue;
            }
            if favorites.added.len() >= MAX_FAVORITES {
                return Err(FavoritesError::FavoritesFull);
            }
            favorites.added.push(line.to_string());
            favorites.members.insert(line.to_string());
        }
        Ok(favorites)
    }
}

/// True when `text` is a plain CID: either a `b`-prefixed base32 lowercase
/// multibase string, or `sha256:` followed by 64 lowercase hex digits.
///
/// This is deliberately structural and small; a stricter parser can replace
/// it without changing `Favorites`.
pub fn is_cid(text: &str) -> bool {
    const BASE32: &str = "abcdefghijklmnopqrstuvwxyz234567";
    const HEX: &str = "0123456789abcdef";

    if let Some(hex) = text.strip_prefix("sha256:") {
        return hex.len() == 64 && hex.bytes().all(|b| HEX.as_bytes().contains(&b));
    }
    let Some(rest) = text.strip_prefix('b') else {
        return false;
    };
    rest.len() >= 40 && rest.bytes().all(|b| BASE32.as_bytes().contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    // P15: a favourite is a capability request naming content, so a path or
    // uri is refused with the exact reason. Falsifier: accept a path.
    #[test]
    fn path_is_refused_not_a_cid() {
        let mut favorites = Favorites::new();
        let err = favorites
            .toggle("localhost://Users/self/Pictures/a.png")
            .unwrap_err();
        assert_eq!(err.reason(), REASON_NOT_A_CID);
        assert_eq!(err.reason(), "not-a-cid");
        assert!(favorites.is_empty(), "a refused toggle changes nothing");
    }

    // P7: the cap is refused before any change. Falsifier: push past the cap.
    #[test]
    fn cap_is_refused_favorites_full() {
        let mut favorites = Favorites::new();
        for index in 0..MAX_FAVORITES {
            let cid = format!("sha256:{:064x}", index);
            assert!(favorites.toggle(&cid).unwrap());
        }
        assert_eq!(favorites.len(), MAX_FAVORITES);
        let err = favorites
            .toggle(&format!("sha256:{:064x}", MAX_FAVORITES))
            .unwrap_err();
        assert_eq!(err.reason(), REASON_FULL);
        assert_eq!(err.reason(), "favorites-full");
        assert_eq!(favorites.len(), MAX_FAVORITES, "the store is unchanged");
    }

    // P7: toggle flips membership and keeps first-favourited order.
    #[test]
    fn toggle_round_trips_in_added_order() {
        let a = format!("sha256:{:064x}", 1);
        let b = format!("sha256:{:064x}", 2);
        let mut favorites = Favorites::new();
        assert!(favorites.toggle(&b).unwrap());
        assert!(favorites.toggle(&a).unwrap());
        assert!(favorites.is_favorite(&a));
        assert_eq!(favorites.cids(Order::Added), vec![b.clone(), a.clone()]);
        assert_eq!(favorites.cids(Order::Cid), vec![a.clone(), b.clone()]);
        assert!(!favorites.toggle(&b).unwrap());
        assert!(!favorites.is_favorite(&b));
        assert_eq!(favorites.cids(Order::Added), vec![a]);
    }

    // P7: the persisted line format round-trips, and a bad line refuses the
    // whole file with the exact reason and its one-based line number.
    // Falsifier: skip the bad line instead of refusing the file.
    #[test]
    fn load_refuses_bad_favorites_line() {
        let good = format!("sha256:{:064x}", 7);
        let text = format!("{good}\n");
        let favorites = Favorites::load(&text).unwrap();
        assert!(favorites.is_favorite(&good));
        assert_eq!(favorites.to_lines(), text);

        let bad = format!("{good}\nnot-a-cid\n");
        let err = Favorites::load(&bad).unwrap_err();
        assert_eq!(err.reason(), REASON_BAD_LINE);
        assert_eq!(err.reason(), "bad-favorites-line");
        assert_eq!(
            err,
            FavoritesError::BadLine {
                line: 2,
                text: "not-a-cid".to_string()
            }
        );
    }
}
