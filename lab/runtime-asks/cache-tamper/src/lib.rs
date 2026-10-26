//! Trial rule for the two Runtime file caches. Not the Runtime.
//!
//! A stamp (dev, inode, size, mode, mtime, ctime) is not a generation while
//! its ctime is still this coarse tick. Git's racy-git rule: do not trust
//! that stamp; compare content.

/// Plant: set to true to trust a matching stamp in the current tick.
/// `trial_rule_refuses_a_racy_same_size_rewrite` must then fail.
pub const TRUST_RACY_STAMP: bool = false;

pub fn stamp_is_racy(ctime: (i64, i64), now: (i64, i64)) -> bool {
    ctime >= now
}

/// `true` only when the cache may skip a content check.
pub fn same_generation(stamp_equal: bool, racy: bool, sha_equal: bool) -> bool {
    if TRUST_RACY_STAMP {
        stamp_equal
    } else {
        stamp_equal && (!racy || sha_equal)
    }
}
