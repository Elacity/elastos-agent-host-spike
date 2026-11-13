//! `elastos stage-bundle`: put a signed bundle into this Home's store of
//! bundles named by CID.
//!
//! The store is `<data_dir>/capsules/by-cid/`: a folder `<cid>/` with the
//! bundle's files and a file `<cid>.sig.json` beside it with the publisher's
//! signature. Only this command writes there, and only bytes it has checked.
//! Staging starts nothing; a later start checks the slot again and trusts
//! nothing this command did.

use std::fs;
use std::io::Write;
use std::path::Path;

use elastos_bundle_identity::{checked_bundle_within, CheckedBundle, LabCid};

use crate::bundle_admission::{
    bundle_signature_path, bundle_slot, walk_refusal, BundleRefusal, BUNDLE_WALK_BUDGET,
};
use crate::runtime::Runtime;

/// What staging did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    /// The bundle's name: the CID of the files that were walked.
    pub cid: String,
    /// The publisher whose signature over that name was checked.
    pub signer_did: String,
    /// False when the slot already held this bundle and was left alone.
    pub files_written: bool,
}

/// The name a publisher signs: the CID of the bundle in `folder`, from the
/// same walk under the same limits as staging. It checks no signature and
/// stages nothing.
pub fn bundle_cid(folder: &Path) -> Result<String, BundleRefusal> {
    checked_bundle_within(folder, BUNDLE_WALK_BUDGET)
        .map(|bundle| bundle.cid().to_string())
        .map_err(walk_refusal)
}

/// Stage the bundle in `folder`, signed by the file at `signature`, into the
/// store of the Home at `data_dir`, against the keys `runtime` trusts.
pub async fn stage_bundle(
    runtime: &Runtime,
    data_dir: &Path,
    folder: &Path,
    signature: &Path,
) -> Result<Staged, BundleRefusal> {
    stage_bundle_observed(runtime, data_dir, folder, signature, || {}).await
}

/// [`stage_bundle`], telling `after_walk` when the one walk of `folder` is
/// done. Tests change the folder at that moment, as another process could.
async fn stage_bundle_observed(
    runtime: &Runtime,
    data_dir: &Path,
    folder: &Path,
    signature: &Path,
    after_walk: impl FnOnce(),
) -> Result<Staged, BundleRefusal> {
    // The one walk of the source. Everything written below comes from this
    // value; the folder is not read again.
    let bundle = checked_bundle_within(folder, BUNDLE_WALK_BUDGET).map_err(walk_refusal)?;
    after_walk();
    let cid = bundle.cid();

    // The check reads the signature file itself, at its place in the order,
    // and hands back the bytes it checked.
    let accepted = runtime.check_bundle_signature(signature, &cid).await?;

    let slot = bundle_slot(data_dir, &cid);
    let files_written = if fs::symlink_metadata(&slot).is_ok() {
        // A slot is written whole, once, under its own name. One that does
        // not recompute to that name is not repaired and not replaced.
        let found = match checked_bundle_within(&slot, BUNDLE_WALK_BUDGET) {
            Ok(found) if found.cid() == cid => None,
            Ok(found) => Some(found.cid().to_string()),
            Err(refusal) => Some(refusal.to_string()),
        };
        if let Some(found) = found {
            return Err(BundleRefusal::SlotDiffers {
                cid: cid.to_string(),
                found,
            });
        }
        false
    } else {
        write_slot(&slot, &cid, &bundle)?;
        true
    };

    // The signature that was just checked goes beside the slot, replacing
    // any earlier one in one step.
    let signature_path = bundle_signature_path(data_dir, &cid);
    let mut file = tempfile::NamedTempFile::new_in(parent_of(&signature_path)?).map_err(store)?;
    file.write_all(&accepted.file).map_err(store)?;
    file.persist(&signature_path)
        .map_err(|error| store(error.error))?;

    Ok(Staged {
        cid: cid.to_string(),
        signer_did: accepted.signer_did,
        files_written,
    })
}

/// Write the checked bytes to the new slot of `cid`: into a temporary folder
/// beside it, each file read-only; that folder is walked and must give `cid`
/// before it is renamed into place. A failure on the way leaves no slot.
fn write_slot(slot: &Path, cid: &LabCid, bundle: &CheckedBundle) -> Result<(), BundleRefusal> {
    let store_dir = parent_of(slot)?;
    fs::create_dir_all(store_dir).map_err(store)?;
    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(store_dir)
        .map_err(store)?;
    for entry in bundle.entries() {
        // The walk refused every path with an empty, `.` or `..` part.
        let path = staging.path().join(&entry.path);
        fs::create_dir_all(parent_of(&path)?).map_err(store)?;
        fs::write(&path, &entry.content).map_err(store)?;
        let mut permissions = fs::metadata(&path).map_err(store)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).map_err(store)?;
    }
    let written =
        checked_bundle_within(staging.path(), BUNDLE_WALK_BUDGET).map_err(walk_refusal)?;
    if written.cid() != *cid {
        return Err(BundleRefusal::SlotDiffers {
            cid: cid.to_string(),
            found: written.cid().to_string(),
        });
    }
    // After the rename the temporary folder's own clean-up finds nothing.
    fs::rename(staging.path(), slot).map_err(store)
}

fn parent_of(path: &Path) -> Result<&Path, BundleRefusal> {
    path.parent()
        .ok_or_else(|| BundleRefusal::Store(format!("{} has no parent folder", path.display())))
}

fn store(error: std::io::Error) -> BundleRefusal {
    BundleRefusal::Store(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle_admission::tests::{did, file_for, key, sign_by_hand, signed, CID_A};
    use crate::bundle_admission::BUNDLE_SIGNATURE_DOMAIN;
    use ed25519_dalek::SigningKey;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    /// The lab's `web-app` fixture, whose recorded CID is `CID_A`.
    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../lab/capsule-identity/fixtures")
            .join(name)
    }

    /// Every file under `root`, as (path relative to it, bytes), sorted;
    /// read with `std::fs`, not with the code under test.
    fn files_of(root: &Path) -> Vec<(String, Vec<u8>)> {
        fn walk(root: &Path, dir: &Path, found: &mut Vec<(String, Vec<u8>)>) {
            for item in fs::read_dir(dir).unwrap() {
                let path = item.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, found);
                } else {
                    let relative = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned();
                    found.push((relative, fs::read(&path).unwrap()));
                }
            }
        }
        let mut found = Vec::new();
        walk(root, root, &mut found);
        found.sort();
        found
    }

    fn copy_of(source: &Path, target: &Path) {
        for (path, bytes) in files_of(source) {
            let path = target.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }

    struct Home {
        runtime: Runtime,
        dir: tempfile::TempDir,
    }

    impl Home {
        async fn trusting(keys: &[&SigningKey], dev_mode: bool) -> Home {
            let (runtime, dir) = crate::runtime::tests::test_runtime().await;
            let keys: Vec<String> = keys
                .iter()
                .map(|key| hex::encode(key.verifying_key().to_bytes()))
                .collect();
            runtime
                .configure_capsule_admission(dir.path(), &keys, dev_mode)
                .await
                .unwrap();
            Home { runtime, dir }
        }

        fn data(&self) -> PathBuf {
            self.dir.path().join("data")
        }

        fn store(&self) -> PathBuf {
            self.data().join("capsules").join("by-cid")
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.dir.path().join(name);
            fs::write(&path, bytes).unwrap();
            path
        }

        async fn stage(&self, folder: &Path, signature: &Path) -> Result<Staged, BundleRefusal> {
            stage_bundle(&self.runtime, &self.data(), folder, signature).await
        }

        /// What the store holds: nothing at all, or its sorted entry names.
        fn store_names(&self) -> Vec<String> {
            let Ok(listing) = fs::read_dir(self.store()) else {
                return Vec::new();
            };
            let mut names: Vec<String> = listing
                .map(|item| item.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        }
    }

    #[tokio::test]
    async fn staging_writes_the_checked_bytes_read_only_with_the_signature_beside() {
        let publisher = key(1);
        let home = Home::trusting(&[&publisher], false).await;
        let source = home.dir.path().join("source");
        copy_of(&fixture("web-app"), &source);
        let offered = signed(CID_A, &publisher);
        let signature = home.write("offered.sig.json", &offered);

        // The source changes right after the walk, as another process could
        // change it. The store must hold what was walked.
        let staged =
            stage_bundle_observed(&home.runtime, &home.data(), &source, &signature, || {
                fs::write(source.join("browser/app.js"), b"changed after the walk").unwrap();
            })
            .await
            .expect("staged");

        assert_eq!(
            staged,
            Staged {
                cid: CID_A.into(),
                signer_did: did(&publisher.verifying_key()),
                files_written: true,
            }
        );
        // The slot is under the recorded CID and holds the fixture's bytes,
        // file for file, not the changed source's.
        let slot = home.store().join(CID_A);
        assert_eq!(files_of(&slot), files_of(&fixture("web-app")));
        assert_ne!(files_of(&slot), files_of(&source));
        for (path, _) in files_of(&slot) {
            let mode = fs::metadata(slot.join(&path)).unwrap().permissions();
            assert!(mode.readonly(), "{path} is writable");
        }
        // The signature is beside the folder, byte for byte as offered, and
        // nothing else is left in the store.
        assert_eq!(
            home.store_names(),
            [CID_A.to_string(), format!("{CID_A}.sig.json")]
        );
        assert_eq!(
            fs::read(home.store().join(format!("{CID_A}.sig.json"))).unwrap(),
            offered
        );
    }

    #[tokio::test]
    async fn the_name_a_publisher_signs_is_the_recorded_cid_under_the_same_limits() {
        let home = Home::trusting(&[], false).await;
        assert_eq!(bundle_cid(&fixture("web-app")), Ok(CID_A.to_string()));
        let deep = bundle_with(&home, "name-depth-17", |folder| {
            let dir = folder.join("d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("f"), b"x").unwrap();
        });
        let refusal = bundle_cid(&deep).expect_err("name-depth-17");
        assert_eq!(refusal.code(), "bundle_walk_over_budget", "{refusal}");
        assert!(home.store_names().is_empty());
    }

    #[tokio::test]
    async fn a_slot_holding_something_else_is_refused_and_nothing_is_written() {
        let publisher = key(1);
        let home = Home::trusting(&[&publisher], false).await;
        let signature = home.write("offered.sig.json", &signed(CID_A, &publisher));
        let slot = home.store().join(CID_A);

        // Another valid bundle sits under this bundle's name.
        copy_of(&fixture("content-sample"), &slot);
        let before = files_of(&slot);
        let refusal = home
            .stage(&fixture("web-app"), &signature)
            .await
            .expect_err("other bytes");
        assert_eq!(refusal.code(), "bundle_slot_differs", "{refusal}");
        assert_eq!(files_of(&slot), before);
        assert_eq!(home.store_names(), [CID_A.to_string()]);

        // So does a folder that is no bundle at all.
        fs::remove_file(slot.join("capsule.json")).unwrap();
        let refusal = home
            .stage(&fixture("web-app"), &signature)
            .await
            .expect_err("no bundle");
        assert_eq!(refusal.code(), "bundle_slot_differs", "{refusal}");
        assert_eq!(home.store_names(), [CID_A.to_string()]);
    }

    #[tokio::test]
    async fn staging_again_with_another_trusted_key_replaces_the_signature_and_leaves_the_files() {
        let (first, second, stranger) = (key(1), key(2), key(7));
        let home = Home::trusting(&[&first, &second], false).await;
        let by_first = home.write("first.sig.json", &signed(CID_A, &first));
        let by_second = home.write("second.sig.json", &signed(CID_A, &second));
        let by_stranger = home.write("stranger.sig.json", &signed(CID_A, &stranger));
        let slot = home.store().join(CID_A);
        let stored = home.store().join(format!("{CID_A}.sig.json"));
        let inodes = |slot: &Path| -> Vec<u64> {
            let mut inodes = vec![fs::metadata(slot).unwrap().ino()];
            for (path, _) in files_of(slot) {
                inodes.push(fs::metadata(slot.join(path)).unwrap().ino());
            }
            inodes
        };

        home.stage(&fixture("web-app"), &by_first)
            .await
            .expect("first");
        let files_before = inodes(&slot);
        assert_eq!(fs::read(&stored).unwrap(), signed(CID_A, &first));

        let again = home
            .stage(&fixture("web-app"), &by_second)
            .await
            .expect("second");
        assert_eq!(again.signer_did, did(&second.verifying_key()));
        assert!(!again.files_written);
        assert_eq!(
            inodes(&slot),
            files_before,
            "the slot's files were written again"
        );
        assert_eq!(fs::read(&stored).unwrap(), signed(CID_A, &second));

        // A signature that is not accepted replaces nothing.
        let refusal = home
            .stage(&fixture("web-app"), &by_stranger)
            .await
            .expect_err("stranger");
        assert_eq!(refusal, BundleRefusal::SignatureNotAccepted);
        assert_eq!(fs::read(&stored).unwrap(), signed(CID_A, &second));
        assert_eq!(
            home.store_names(),
            [CID_A.to_string(), format!("{CID_A}.sig.json")]
        );
    }

    #[tokio::test]
    async fn a_refused_signature_stages_nothing_whatever_dev_mode_says() {
        let (publisher, stranger) = (key(1), key(7));
        let trusted_did = did(&publisher.verifying_key());
        let forged = file_for(
            CID_A,
            &trusted_did,
            &sign_by_hand(&stranger, BUNDLE_SIGNATURE_DOMAIN, CID_A),
        );
        let other_cid = "bafybeicesxlwcolv5hifwotsyafyyaclaq23gyzwl7esuvhwlownrhatym";
        for dev_mode in [false, true] {
            let home = Home::trusting(&[&publisher], dev_mode).await;
            // A valid signature file, padded with spaces past the size cap.
            let mut padded = signed(CID_A, &publisher);
            padded.resize(4097, b' ');
            let cases: [(&str, Option<Vec<u8>>, &str); 6] = [
                ("no file", None, "bundle_unsigned"),
                ("not json", Some(b"{".to_vec()), "bundle_signature_unparsed"),
                (
                    "too large",
                    Some(padded.clone()),
                    "bundle_signature_unparsed",
                ),
                (
                    "for another bundle",
                    Some(signed(other_cid, &publisher)),
                    "bundle_signature_names_another_cid",
                ),
                (
                    "trusted name, bad signature",
                    Some(forged.clone()),
                    "bundle_signature_not_accepted",
                ),
                (
                    "valid, not trusted",
                    Some(signed(CID_A, &stranger)),
                    "bundle_signature_not_accepted",
                ),
            ];
            for (case, file, code) in cases {
                let case = format!("{case}, dev_mode {dev_mode}");
                let signature = match file {
                    Some(bytes) => home.write("offered.sig.json", &bytes),
                    None => home.dir.path().join("absent.sig.json"),
                };
                let refusal = home
                    .stage(&fixture("web-app"), &signature)
                    .await
                    .expect_err(&case);
                assert_eq!(refusal.code(), code, "{case}: {refusal}");
                assert!(
                    home.store_names().is_empty(),
                    "{case}: {:?}",
                    home.store_names()
                );
            }
            // The controls: the same Home stages the same bundle when it is
            // signed, also with the file padded to exactly the size cap.
            let signature = home.write("offered.sig.json", &signed(CID_A, &publisher));
            home.stage(&fixture("web-app"), &signature)
                .await
                .expect("signed");
            padded.truncate(4096);
            let signature = home.write("offered.sig.json", &padded);
            home.stage(&fixture("web-app"), &signature)
                .await
                .expect("at the cap");
        }

        // A Home that trusts no key refuses a valid signature, and an absent
        // one as unsigned, with dev_mode on.
        let home = Home::trusting(&[], true).await;
        let signature = home.write("offered.sig.json", &signed(CID_A, &publisher));
        let refusal = home
            .stage(&fixture("web-app"), &signature)
            .await
            .expect_err("no trust");
        assert_eq!(refusal, BundleRefusal::TrustSetEmpty);
        // It gives that same answer for a signature file over the size cap:
        // the trust set is asked before the file is read.
        let mut over = signed(CID_A, &publisher);
        over.resize(4097, b' ');
        let signature = home.write("over.sig.json", &over);
        let refusal = home
            .stage(&fixture("web-app"), &signature)
            .await
            .expect_err("no trust, too large");
        assert_eq!(refusal, BundleRefusal::TrustSetEmpty);
        let absent = home.dir.path().join("absent.sig.json");
        let refusal = home
            .stage(&fixture("web-app"), &absent)
            .await
            .expect_err("unsigned");
        assert_eq!(refusal, BundleRefusal::Unsigned);
        assert!(home.store_names().is_empty());
    }

    /// A bundle of `capsule.json` (the fixture's) and whatever `add` adds.
    fn bundle_with(home: &Home, name: &str, add: impl FnOnce(&Path)) -> PathBuf {
        let folder = home.dir.path().join(name);
        fs::create_dir_all(&folder).unwrap();
        fs::copy(
            fixture("web-app").join("capsule.json"),
            folder.join("capsule.json"),
        )
        .unwrap();
        add(&folder);
        folder
    }

    /// Stage `folder` unsigned: a walk within the limits gets as far as the
    /// signature and is refused there; a walk over a limit never does.
    async fn walk_of(home: &Home, folder: &Path) -> BundleRefusal {
        let absent = home.dir.path().join("absent.sig.json");
        home.stage(folder, &absent).await.expect_err("unsigned")
    }

    async fn assert_within(home: &Home, folder: &Path) {
        let name = folder.file_name().unwrap().to_string_lossy();
        assert_eq!(
            walk_of(home, folder).await,
            BundleRefusal::Unsigned,
            "{name}"
        );
    }

    async fn assert_past(home: &Home, folder: &Path, limit: &str) {
        let name = folder.file_name().unwrap().to_string_lossy();
        let refusal = walk_of(home, folder).await;
        assert_eq!(
            refusal.code(),
            "bundle_walk_over_budget",
            "{name}: {refusal}"
        );
        let text = format!("passes the walk's limit on {limit}");
        assert!(refusal.to_string().ends_with(&text), "{name}: {refusal}");
    }

    #[tokio::test]
    async fn the_walk_at_staging_is_under_the_four_limits() {
        let home = Home::trusting(&[&key(1)], false).await;
        let nested = |folder: &Path, levels: usize| {
            let mut dir = folder.to_path_buf();
            for _ in 0..levels {
                dir.push("d");
            }
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("f"), b"x").unwrap();
        };
        let many = |folder: &Path, files: usize| {
            for index in 0..files {
                fs::write(folder.join(format!("f{index}")), b"").unwrap();
            }
        };
        // A path of exactly `bytes` bytes: folders of 200 bytes and a file
        // name that makes up the rest. Made one step at a time from inside
        // the folder, because one system this runs on takes no whole path
        // that long.
        let long = |folder: &Path, bytes: usize| {
            let mut steps = String::new();
            let mut left = bytes;
            while left > 201 {
                steps.push_str(&format!("mkdir {0} && cd {0} && ", "p".repeat(200)));
                left -= 201;
            }
            let made = std::process::Command::new("sh")
                .current_dir(folder)
                .args(["-c", &format!("{steps}: > {}", "n".repeat(left))])
                .status()
                .unwrap();
            assert!(made.success());
        };
        // A file of `bytes` bytes that takes no room on disk.
        let sized = |folder: &Path, bytes: u64| {
            fs::File::create(folder.join("big"))
                .unwrap()
                .set_len(bytes)
                .unwrap();
        };

        // Depth: a path of 16 parts passes (15 folders and a file); one of
        // 17 parts does not, and its last folder is not entered.
        assert_within(
            &home,
            &bundle_with(&home, "depth-16", |folder| nested(folder, 15)),
        )
        .await;
        assert_past(
            &home,
            &bundle_with(&home, "depth-17", |folder| nested(folder, 16)),
            "depth",
        )
        .await;

        // Entries: the manifest and 4,095 files pass, one more does not.
        assert_within(
            &home,
            &bundle_with(&home, "entries-4096", |folder| many(folder, 4_095)),
        )
        .await;
        assert_past(
            &home,
            &bundle_with(&home, "entries-4097", |folder| many(folder, 4_096)),
            "entries",
        )
        .await;

        // Path: 1,024 bytes pass, 1,025 do not.
        assert_within(
            &home,
            &bundle_with(&home, "path-1024", |folder| long(folder, 1_024)),
        )
        .await;
        assert_past(
            &home,
            &bundle_with(&home, "path-1025", |folder| long(folder, 1_025)),
            "path bytes",
        )
        .await;

        // Bytes: a file that would take the total past 64 MiB is refused
        // from its size, before it is read. The same folder with a small
        // file passes. (The crate's own tests hold the exact boundary.)
        let folder = bundle_with(&home, "bytes-over", |folder| {
            sized(folder, 64 * 1024 * 1024)
        });
        assert_past(&home, &folder, "total bytes").await;
        sized(&folder, 1024);
        assert_within(&home, &folder).await;

        assert!(home.store_names().is_empty());
    }

    #[test]
    fn the_server_walks_a_bundle_only_under_its_budget() {
        // The crate's other ways to name a folder take no budget. No file of
        // the server may call one, and every bounded walk takes the server's
        // one budget. The needles are split so this file does not match.
        let unbounded = [
            ["checked_bundle", "("].concat(),
            ["checked_bundle", "_observed("].concat(),
            ["lab_cid", "("].concat(),
            ["lab_cid", "_observed("].concat(),
            ["check_name", "("].concat(),
            ["Budget::", "UNLIMITED"].concat(),
            // The encoder takes entries a caller already holds, under no
            // budget. The server hands it none.
            ["encode_entries", "("].concat(),
            ["encode_listed_files", "("].concat(),
        ];
        let bounded = ["checked_bundle", "_within("].concat();
        fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
            for item in fs::read_dir(dir).unwrap() {
                let path = item.unwrap().path();
                if path.is_dir() {
                    rust_files(&path, found);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    found.push(path);
                }
            }
        }
        let mut files = Vec::new();
        rust_files(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        assert!(files.len() > 50, "found {} files", files.len());
        let (mut walks, mut of_a_start) = (0, 0);
        for file in &files {
            let text = fs::read_to_string(file).unwrap();
            for needle in &unbounded {
                assert!(
                    !text.contains(needle.as_str()),
                    "{} names {needle}",
                    file.display()
                );
            }
            for line in text.lines().filter(|line| line.contains(bounded.as_str())) {
                // The start by CID walks each bundle of a closure under what
                // is left of one budget. That this budget is the server's,
                // and that it only shrinks, is held by the start's own pin
                // (`the_start_by_cid_reads_each_slot_once_and_fetches_nothing`).
                let what_is_left = file.ends_with("runtime.rs") && line.contains("(&slot, *left)");
                assert!(
                    line.contains("BUNDLE_WALK_BUDGET)") || what_is_left,
                    "{}: a walk without the server's budget: {}",
                    file.display(),
                    line.trim()
                );
                walks += 1;
                of_a_start += usize::from(what_is_left);
            }
        }
        // Staging makes four (the name, the source, a slot that is there,
        // the slot it wrote); the start by CID makes one, of each slot.
        assert_eq!(walks, 5, "the walks the server makes");
        assert_eq!(of_a_start, 1, "the one walk under what is left");
    }
}
