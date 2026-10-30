//! Lab stand-in for the Runtime's live-grant view, not the Runtime.
//!
//! `get_capability_list` is the one answer for `GET /api/capability/list`.
//! `None` is the plain route. `Some("all_sessions_live")` is the query form.
//! One filter keeps a grant whose life is `Live`. An ended session stays.
//!
//! `post_capsules`, `get_capsules` and `delete_capsule` answer the capsule
//! routes for an admitted resident guest. Admission names a bundle by its lab
//! CID and checks the publisher's name signature; launch names it by that lab
//! CID only (M1 check B1). Admission refuses a `content` manifest with status
//! 403: a content capsule opens by CID as content and never runs as code, so
//! no row, instance or grant exists for it. Launch answers `starting` with
//! the Bus session before `finish_start`. A stop stores `stopped` and revokes
//! that session's `Live` grants; a failed start stores `failed` and revokes
//! them too. One map names the five statuses. One age compare keeps a
//! `failed` or `stopped` entry. One check refuses a client on a shell-only
//! route. `post_capability_validate` is the one use path; its private
//! `authorise` runs on that same filter.
//!
//! `stop_one` and the `worker_exited` seam share one private end path,
//! `end_instance`. It refuses an unknown or already-ended id before anything
//! changes; otherwise it applies the given phase and cause, then revokes and
//! settles. `worker_exited` is the stand-in's dead worker with no stop
//! request (M1 check A11): fixed cause `worker exited`, instance `failed`.
//!
//! A `once` grant minted by `post_capability_grant` stores its expiry as its
//! `granted_at` plus `GRANT_LIFETIME_SECS`. One compare reads the stand-in's
//! instant: at or past that instant `authorise` answers `grant is not live:
//! Expired` and the live view drops the grant.
//!
//! `get_capability_requests` answers `GET /api/capability/requests?session=`
//! from one request store beside the grants. `seed_request` is the store
//! writer: the only non-test caller is `post_capability_request`, which runs
//! `declared_ask` before it, so every stored request passed the signed ask
//! check.
//! An accepted stop denies that session's pending requests with the stop
//! cause; a worker kill passes `stopped: worker killed`. A failed
//! start denies them with the failure cause. One writer stores those three
//! fields, so a request that outlives the guest call still records its
//! settlement and settler. `post_capability_deny` answers
//! `POST /api/capability/deny` through that writer with `shell` as settler.
//! A `starting` instance of that session ends `failed` with the reason, and
//! the same revoke and settle cleanup that a failed start runs then ends its
//! `Live` grants and denies its other pending requests with that reason.
//! `post_capability_grant` answers `POST /api/capability/grant` through the
//! same writer with `granted` and `shell`, then `seed_grant` stores the one
//! `Live` grant. A grant body carries no token.
//!
//! `get_capability_pending` answers `GET /api/capability/pending` from that
//! same store. A client is refused before the store is read. Only a `Pending`
//! record is listed, sorted by `session_id` then `request_id`. `expires_at`
//! is `requested_at` plus `REQUEST_TIMEOUT_SECS`, saturated. The list does
//! not grant and does not settle.
//!
//! `set_instant` calls `expire_due`, which passes the one writer `expired`,
//! `Request timed out` and `runtime` for each pending request at least 300
//! seconds old. A granted or denied record and its instance stay.

use capsule_identity::{
    checked_bundle, verify_checked_signature, CheckedBundle, LabCid, NameSignature, Refusal,
};
use serde_json::{json, Map, Value};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

const LIVE_SCOPE: &str = "all_sessions_live";
const RESIDENT_WORLD: &str = "resident-capsule";
const FAILED_KEEP_SECS: u64 = 60;
const REQUEST_TIMEOUT_SECS: u64 = 300;
const GRANT_LIFETIME_SECS: u64 = 3_600;
/// The one cause `worker_exited` stores, and the one reason it settles with.
const WORKER_EXITED: &str = "worker exited";

/// One reason per storage refusal. The stand-in never repairs a file; it
/// refuses it and names why.
const LINK_REASON: &str = "storage directory is a symbolic link";
const ENTRY_REASON: &str = "storage entry stays under the selected Home";
const DATA_REASON: &str = "storage directory is outside the selected Home";
const NOT_REGULAR_REASON: &str = "storage file is not a single regular file";
const NOT_ONE_LINK_REASON: &str = "storage file does not have exactly one link";
const NOT_CREATED_REASON: &str = "storage file was not created by the stand-in";
const SWAPPED_REASON: &str = "storage file is not the file the stand-in created";
const EXISTS_REASON: &str = "storage file already exists";
const SHELL_STORAGE_REASON: &str = "storage belongs to one agent instance";
const MISSING_STORAGE_REASON: &str = "storage directory does not exist";
const NOT_DIR_REASON: &str = "storage directory is not a directory";
const EXISTING_STORAGE_REASON: &str = "storage directory already exists";
const DATA_STEP: &str = "storage directory";
const ENTRY_STEP: &str = "storage file";

/// Authenticated caller. A method argument, not a JSON field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caller<'a> {
    Shell,
    Client { session_id: &'a str },
}

/// Life of one seeded grant. The filter keeps `Live`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Life {
    Live,
    Exhausted,
    Revoked,
    Expired,
}

/// Outcome of one `resident.start` call, supplied by the test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    Ok,
    Error(String),
    Trap(String),
}

/// Five list statuses. This slice stores `Starting`, `Running`, `Stopped` and `Failed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResidentStatus {
    Starting,
    Running,
    #[allow(dead_code)]
    Stopping,
    Stopped,
    Failed,
}

struct Grant {
    request_id: String,
    session_id: String,
    resource: String,
    action: String,
    duration: String,
    granted_at: u64,
    expires_at: Option<u64>,
    life: Life,
    session_ended: bool,
    /// The plan this grant was approved for (M1 check A15a). A private value:
    /// the shell's grant route mints it from the plan hash the request stored,
    /// and `authorise` compares it with the plan hash of the use. No caller
    /// holds or constructs it.
    plan: Option<PlanBinding>,
    /// The hosted run this grant was minted for (M1 check A6). The grant route
    /// mints it from the request's session; the request read returns it; the
    /// use path compares the pair the effect presents. Its fields are private,
    /// so only this module mints a value and no test or crate can name one.
    run: RunBinding,
}

/// One approved-plan binding on a grant. Its one field is private, so only
/// this module mints a value and no test or crate can name one.
#[derive(Clone)]
struct PlanBinding {
    plan_sha256: String,
}

/// The pair a hosted effect presents: the run id and the request id its own
/// grant route minted (M1 check A6). The Runtime binds an effect by the same
/// pair (`elastos/crates/elastos-server/src/api/model_provider_egress.rs:645-646`),
/// and the provider sends both as `x-elastos-run-id` and
/// `x-elastos-request-id` (`capsules/model-provider/src/adapters.rs:67-68`).
/// Both fields are private: a caller reads the pair back from a route answer
/// and cannot construct one.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RunBinding {
    run_id: String,
    request_id: String,
}

impl RunBinding {
    /// The `x-elastos-run-id` value: the grant's request id under `run-`.
    fn run_id_for(request_id: &str) -> String {
        format!("run-{request_id}")
    }
}

/// One admitted row. It keeps what launch needs to re-run the same check:
/// the bundle path, the publisher's signature and the accepted list, beside
/// the CID it was admitted under.
///
/// It also keeps the asks the signed bundle declares. They come from
/// `asks.json` inside the bytes the admitted lab CID covers, read by the one
/// walk, so they hold only when that signature verifies (M1 check B2).
struct Admitted {
    cid: LabCid,
    name: String,
    start: Start,
    world: &'static str,
    bundle: PathBuf,
    sig: NameSignature,
    accepted: Vec<String>,
    asks: Vec<Ask>,
}

/// One ask a signed bundle declares, as `asks.json` gives it.
///
/// Provisional: this schema mirrors the #464 draft and is not that draft's
/// final form. The file is `{"schema": "elastos.agent-host.asks/v1", "asks":
/// [{"kind": <kind>, "resource": <resource>}]}`. It sits in the bundle beside
/// `capsule.json`, so the signed lab CID covers it. `kind` is the request's
/// action, lowercased as the request route lowercases it, and `resource` is
/// the request's resource: the route stores a request only when both match
/// one ask exactly.
struct Ask {
    kind: String,
    resource: String,
}

/// One launched guest. `post_capsules` is the only writer of `instances`: it
/// makes the `check_bundle` call over the row's admitted signature before the
/// push, so every launch path re-verifies the signed bundle on disk now.
struct Instance {
    id: String,
    name: String,
    start: Start,
    phase: ResidentStatus,
    cause: String,
    ended_at: Option<u64>,
    /// The lab CID of the admitted row this launch started. The request route
    /// reads that row's signed asks (M1 check B2).
    started_cid: LabCid,
}

/// One storage file the stand-in created. The `(device, inode)` pair is what
/// every later check compares, so a file swapped at the name is a different
/// file even when its type and link count match.
struct Record {
    home: PathBuf,
    name: String,
    /// `fstat`'s device type on this platform: `rustix::fs::Dev` is the libc
    /// `dev_t`, which is `u64` on Linux and `i32` on macOS.
    device: rustix::fs::Dev,
    inode: u64,
}

/// Four request statuses this slice stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestStatus {
    Pending,
    Granted,
    Denied,
    Expired,
}

struct Request {
    request_id: String,
    session_id: String,
    resource: String,
    action: String,
    reason: String,
    requested_at: u64,
    status: RequestStatus,
    decision_reason: String,
    settled_by: Option<&'static str>,
    /// The plan hash the requester stored (M1 check A15a). It is folded out of
    /// the body, so no store field carries it back to the instance.
    plan: Option<String>,
}

pub struct StandIn {
    /// The Home root this stand-in runs under. Storage routes take the Home
    /// from this field, never from a caller string or a request body, so one
    /// stand-in reads and writes only under this Home. `None` until a test or
    /// a launcher names it through `set_home`.
    home: Option<PathBuf>,
    /// The held Home handle `set_home` opened once, from a handle on `/` with
    /// one `O_NOFOLLOW` step per component. Every storage call walks below
    /// this handle; no call opens the Home by path again. A failed open is
    /// kept as its error, so every later storage call answers with it.
    home_fd: Option<Result<OwnedFd, (u16, String)>>,
    grants: Vec<Grant>,
    requests: Vec<Request>,
    admitted: Vec<Admitted>,
    instances: Vec<Instance>,
    storage: Vec<Record>,
    /// A name the next `create_storage` joins to the file it just made,
    /// between that open call and its `fstat`. Set only by the test seam
    /// `join_next_create`, so the shared link rule sees two names.
    join_next: Option<PathBuf>,
    next_id: u64,
    next_request: u64,
    instant: u64,
}

impl StandIn {
    pub fn new() -> Self {
        Self {
            home: None,
            home_fd: None,
            grants: Vec::new(),
            requests: Vec::new(),
            admitted: Vec::new(),
            instances: Vec::new(),
            storage: Vec::new(),
            join_next: None,
            next_id: 1,
            next_request: 1,
            instant: 0,
        }
    }

    /// Lab test seam, not a route.
    ///
    /// Names the one Home root this stand-in runs under. The launcher names
    /// it from the selected Home; the storage routes then take it from this
    /// value, never from a caller string or a request body. This call opens
    /// the Home exactly once, at holder creation: its ancestors are resolved
    /// once by path, and the Home's own final component is taken on that
    /// parent handle with `O_NOFOLLOW`, so the Home itself must not be a
    /// link. Every later storage call walks below the stored handle and
    /// never opens the Home by path again, so an ancestor renamed into the
    /// Home's place after this call is not followed. A failed open is stored
    /// as its error and every later storage call answers with it. This call
    /// creates nothing and reads no clock.
    pub fn set_home(&mut self, home: &Path) {
        let opened = open_home(home);
        self.home = Some(home.to_path_buf());
        self.home_fd = Some(opened);
    }

    /// Lab test seam, not a route.
    ///
    /// Makes the next `create_storage` join `name` to the file it just made,
    /// between that open call and its `fstat`, so the one link rule sees a
    /// second name. It creates nothing itself and reads no file.
    pub fn join_next_create(&mut self, name: &Path) {
        self.join_next = Some(name.to_path_buf());
    }

    /// Lab test seam, not a route.
    ///
    /// The `run` launcher's storage directory follows the selected Home: it is
    /// `harness::data_dir(home)` joined with `storage`. The fixed shared temp
    /// path is refused before that rule runs on it. This call creates nothing.
    pub fn storage_for_home(home: &Path) -> Result<PathBuf, (u16, String)> {
        const SHARED_TEMP: &str = "/tmp/elastos/storage";
        const NEEDS_HOME: &str = "storage needs a selected Home";
        const SHARED_REASON: &str = "shared temp directory is not agent storage";

        let refused = |reason: &str| Err((400, reason.to_owned()));
        if home.as_os_str().is_empty()
            || !home.is_absolute()
            || home
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return refused(NEEDS_HOME);
        }
        if home == Path::new(SHARED_TEMP) {
            return refused(SHARED_REASON);
        }
        let data = crate::harness::data_dir(home).map_err(|reason| (400, reason.to_owned()))?;
        let storage = data.join("storage");
        if storage == Path::new(SHARED_TEMP) {
            return refused(SHARED_REASON);
        }
        Ok(storage)
    }

    /// The storage check and the storage use are one operation.
    ///
    /// The Home is the one `set_home` named, never a caller argument.
    /// The Home handle is the one `set_home` opened at holder creation,
    /// where the Home's ancestors were resolved once and the Home itself
    /// was opened with `O_NOFOLLOW`. Every step from that handle down to
    /// the storage directory is opened once from the handle of the step
    /// above with `O_NOFOLLOW`, `O_DIRECTORY`, `O_NONBLOCK` and
    /// `O_CLOEXEC`, so a symbolic link below the Home, a parent swapped
    /// after an earlier call, or a non-directory at any step fails that
    /// step and nothing is followed. The entry name must be one
    /// normal component. The stand-in creates every storage file itself with
    /// `openat` `O_CREAT|O_EXCL|O_NOFOLLOW`, and records `(st_dev, st_ino)`
    /// in the per-Home record this value keeps. Every later call opens the
    /// entry on that Home's directory handle with
    /// `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, then `fstat`s that handle, and
    /// requires a regular file, `st_nlink == 1` and the recorded pair. A
    /// file the stand-in did not create, a file with a second name, or a
    /// file whose recorded inode is gone is refused with a reason and never
    /// repaired. The handle is what the read or the write then uses, so no
    /// name is resolved again after the check. This call creates no
    /// directory and no file.
    pub fn confirm_storage(&mut self, entry: &str) -> Result<(), (u16, String)> {
        let home = self.selected_home()?;
        let named = match Path::new(entry).components().next() {
            None => false,
            Some(Component::Normal(_)) if plain_name(entry) => true,
            _ => return Err((400, ENTRY_REASON.to_owned())),
        };
        if !named {
            // An absent storage directory is accepted with no name: only a
            // named entry needs the directory. A link on any step is still
            // refused by the walk.
            let _ = self.storage_directory(&home)?;
            return Ok(());
        }
        let _ = self.storage_file(&home, entry, false)?;
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Creates one storage file for the Home named by `set_home` with
    /// `O_CREAT|O_EXCL` and records its `(st_dev, st_ino)`. This is the only
    /// way a file enters the Home's record, so every later `confirm_storage`,
    /// `read_storage` and `write_storage` for that name checks the recorded
    /// pair. A name that already has a record is status 400 with the reason
    /// `storage file already exists`, and this call changes nothing then.
    /// The storage directory is made, when it is absent, one component at a
    /// time with `mkdirat` on the handle the walk reached, so creation never
    /// resolves the data path a second time. This call reads no clock.
    pub fn create_storage(&mut self, entry: &str) -> Result<(), (u16, String)> {
        use std::os::fd::AsFd;

        let home = self.selected_home()?;
        if !plain_name(entry) {
            return Err((400, ENTRY_REASON.to_owned()));
        }
        if self.storage_record(&home, entry).is_some() {
            return Err((400, EXISTS_REASON.to_owned()));
        }
        // The walk reports the handle it reached and, when a step is absent,
        // that step and every step below it by name. Creation makes exactly
        // those names on that handle, so no path is derived from the Home
        // again: a Home path re-opened here would follow a swapped ancestor.
        let handle = match self.storage_directory(&home)? {
            Walk::Reached(directory) => directory,
            Walk::Absent { parent, steps } => {
                let mut made = parent;
                for part in steps {
                    made = make_step(&made, &part)?;
                }
                made
            }
        };
        let make = rustix::fs::openat(
            handle.as_fd(),
            entry,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                (400, EXISTS_REASON.to_owned())
            } else {
                file_failure(&error)
            }
        })?;
        if let Some(name) = self.join_next.take() {
            // The controlled interleaving: the test's name joins this file
            // after the open call and before the `fstat`.
            rustix::fs::linkat(
                handle.as_fd(),
                entry,
                rustix::fs::CWD,
                &name,
                rustix::fs::AtFlags::empty(),
            )
            .map_err(|error| file_failure(&error))?;
        }
        let stat = rustix::fs::fstat(&make).map_err(|error| file_failure(&error))?;
        check_file(&stat)?;
        self.storage.push(Record {
            home,
            name: entry.to_owned(),
            device: stat.st_dev,
            inode: stat.st_ino,
        });
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Reads one storage entry of the Home this stand-in recorded for the
    /// client's instance. The check and the read share the one handle
    /// `storage_file` returns, so a name swapped after the check is never
    /// resolved again.
    pub fn read_storage(
        &mut self,
        caller: Caller<'_>,
        entry: &str,
    ) -> Result<Vec<u8>, (u16, String)> {
        use std::io::Read;

        let home = self.storage_home(caller)?;
        if !plain_name(entry) {
            return Err((400, ENTRY_REASON.to_owned()));
        }
        let handle = self.storage_file(&home, entry, false)?;
        let mut bytes = Vec::new();
        std::fs::File::from(handle)
            .read_to_end(&mut bytes)
            .map_err(|error| (400, format!("storage file: {error}")))?;
        Ok(bytes)
    }

    /// Lab test seam, not a route.
    ///
    /// Writes `bytes` to one storage entry of the Home this stand-in
    /// recorded for the client's instance. The check and the write share the
    /// one handle `storage_file` returns, and that handle already passed the
    /// regular-file, one-link and recorded-`(st_dev, st_ino)` checks, so a
    /// name moved, linked or replaced after the check cannot reach another
    /// file.
    pub fn write_storage(
        &mut self,
        caller: Caller<'_>,
        entry: &str,
        bytes: &[u8],
    ) -> Result<(), (u16, String)> {
        use std::io::{Seek, SeekFrom, Write};

        let home = self.storage_home(caller)?;
        if !plain_name(entry) {
            return Err((400, ENTRY_REASON.to_owned()));
        }
        let handle = self.storage_file(&home, entry, true)?;
        let mut file = std::fs::File::from(handle);
        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
            .and_then(|()| file.write_all(bytes))
            .map_err(|error| (400, format!("storage file: {error}")))
    }

    /// The Home this stand-in runs under, once the caller's instance is live.
    /// An instance of another stand-in has no storage here, so the caller
    /// must name a live instance of this one.
    fn storage_home(&self, caller: Caller<'_>) -> Result<PathBuf, (u16, String)> {
        let Caller::Client { session_id } = caller else {
            return Err((403, SHELL_STORAGE_REASON.to_owned()));
        };
        let Some(instance) = self
            .instances
            .iter()
            .find(|instance| instance.id == session_id)
        else {
            return Err(unknown_instance(session_id));
        };
        if !matches!(
            instance.phase,
            ResidentStatus::Starting | ResidentStatus::Running
        ) {
            return Err(not_live(instance.phase));
        }
        let Some(home) = self.home.clone() else {
            return Err((400, "storage needs a selected Home".to_owned()));
        };
        Ok(home)
    }

    fn storage_record(&self, home: &Path, entry: &str) -> Option<(rustix::fs::Dev, u64)> {
        self.storage
            .iter()
            .find(|record| record.home == home && record.name == entry)
            .map(|record| (record.device, record.inode))
    }

    /// The Home named by `set_home`, which is the one Home this stand-in
    /// runs under. A call before `set_home` has no Home to use.
    fn selected_home(&self) -> Result<PathBuf, (u16, String)> {
        self.home
            .clone()
            .ok_or_else(|| (400, "storage needs a selected Home".to_owned()))
    }

    /// Walks from the HELD Home handle `set_home` opened once, with one
    /// `O_NOFOLLOW|O_DIRECTORY` step per component of
    /// `harness::data_dir(home)` down to the storage directory, so a
    /// symbolic link at any step below the Home is refused and not followed,
    /// and an ancestor of the Home swapped after `set_home` cannot reach
    /// this walk at all: no path is opened here, and no step starts at the
    /// current directory. The held handle is borrowed for the walk; the
    /// reachable result holds a step or a `try_clone` of the held handle
    /// when the storage directory is the Home itself. Nothing is
    /// canonicalized.
    ///
    /// The walk stops on the first absent step and returns the names of that
    /// step and every step below it, on the handle of the absent step's
    /// parent. Creation then makes exactly those names with `mkdirat` on the
    /// handle the walk reached, so it derives no path from the Home again.
    fn storage_directory(&self, home: &Path) -> Result<Walk, (u16, String)> {
        use std::os::fd::AsFd;

        let Some(opened) = &self.home_fd else {
            return Err((400, "storage needs a selected Home".to_owned()));
        };
        let held = opened.as_ref().map_err(Clone::clone)?;
        let storage = Self::storage_for_home(home)?;
        let to_storage = storage
            .strip_prefix(home)
            .map_err(|_| (400, DATA_REASON.to_owned()))?;
        let mut current = held
            .try_clone()
            .map_err(|_| (400, DATA_REASON.to_owned()))?;
        let mut absent: Vec<std::ffi::OsString> = Vec::new();
        for part in to_storage.components() {
            let Component::Normal(part) = part else {
                return Err((400, DATA_REASON.to_owned()));
            };
            if !absent.is_empty() {
                absent.push(part.to_os_string());
                continue;
            }
            let missing = |error: &rustix::io::Errno| *error == rustix::io::Errno::NOENT;
            match step(current.as_fd(), &missing, &storage_failure, part)? {
                Some(next) => current = next,
                None => absent.push(part.to_os_string()),
            }
        }
        if absent.is_empty() {
            Ok(Walk::Reached(current))
        } else {
            Ok(Walk::Absent {
                parent: current,
                steps: absent,
            })
        }
    }

    /// Opens one storage entry on the Home's directory handle and checks
    /// that handle. The returned handle is the checked file.
    /// `writable` opens the recorded file for a write that then truncates
    /// that same handle. The check is the same on both paths.
    fn storage_file(
        &self,
        home: &Path,
        entry: &str,
        writable: bool,
    ) -> Result<OwnedFd, (u16, String)> {
        use std::os::fd::AsFd;

        // A recorded name needs the storage directory. An absent one is the
        // directory's own reason, so a missing directory never reads as a
        // missing file.
        let Walk::Reached(directory) = self.storage_directory(home)? else {
            return Err((400, MISSING_STORAGE_REASON.to_owned()));
        };
        let Some((device, inode)) = self.storage_record(home, entry) else {
            return Err((400, NOT_CREATED_REASON.to_owned()));
        };
        let access = if writable {
            rustix::fs::OFlags::WRONLY
        } else {
            rustix::fs::OFlags::RDONLY
        };
        let handle = rustix::fs::openat(
            directory.as_fd(),
            entry,
            access
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::ISDIR {
                (400, NOT_REGULAR_REASON.to_owned())
            } else if error == rustix::io::Errno::NOENT {
                // The record's name is gone: the file it names is not there.
                (400, NOT_CREATED_REASON.to_owned())
            } else {
                file_failure(&error)
            }
        })?;
        let stat = rustix::fs::fstat(&handle).map_err(|error| file_failure(&error))?;
        check_file(&stat)?;
        if (stat.st_dev, stat.st_ino) != (device, inode) {
            return Err((400, SWAPPED_REASON.to_owned()));
        }
        Ok(handle)
    }

    /// Lab test seam, not a route.
    ///
    /// `granted_at` is the seeded value. This method reads no clock. A seeded
    /// grant is unbound: the plan binding is minted only by
    /// `post_capability_grant`, so this seam can never create one.
    #[allow(clippy::too_many_arguments)]
    pub fn seed_grant(
        &mut self,
        request_id: &str,
        session_id: &str,
        resource: &str,
        action: &str,
        duration: &str,
        granted_at: u64,
        life: Life,
        session_ended: bool,
    ) {
        self.grants.push(Grant {
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            resource: resource.to_owned(),
            action: action.to_owned(),
            duration: duration.to_owned(),
            granted_at,
            expires_at: expiry_at(duration, granted_at),
            life,
            session_ended,
            plan: None,
            // `seed_grant` mints no run pair: only the grant route does (M1
            // check A6), so a seeded grant is not reachable by a presented pair.
            run: RunBinding {
                run_id: String::new(),
                request_id: String::new(),
            },
        });
    }

    /// Lab test seam, not a route. Private to this module.
    ///
    /// Stores one pending request at the current instant. This method reads no
    /// clock and no disk. Its route caller `post_capability_request` runs
    /// `declared_ask` first, so an id it stores carries a declared ask.
    pub(crate) fn seed_request(
        &mut self,
        request_id: &str,
        session_id: &str,
        resource: &str,
        action: &str,
        reason: &str,
    ) -> Result<(), (u16, String)> {
        if request_id.is_empty()
            || session_id.is_empty()
            || resource.is_empty()
            || action.is_empty()
        {
            return Err((
                400,
                "request needs an id, a session, a resource and an action".to_owned(),
            ));
        }
        if self
            .requests
            .iter()
            .any(|request| request.request_id == request_id)
        {
            return Err((400, format!("request already stored: {request_id}")));
        }
        self.requests.push(Request {
            request_id: request_id.to_owned(),
            session_id: session_id.to_owned(),
            resource: resource.to_owned(),
            action: action.to_owned(),
            reason: reason.to_owned(),
            requested_at: self.instant,
            status: RequestStatus::Pending,
            decision_reason: String::new(),
            settled_by: None,
            plan: None,
        });
        Ok(())
    }

    /// `GET /api/capability/requests?session=`.
    ///
    /// `session` is the query, a method argument. Ok means status 200.
    pub fn get_capability_requests(
        &self,
        caller: Caller<'_>,
        session: Option<&str>,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let Some(session) = session.filter(|session| !session.is_empty()) else {
            return Err((400, "requests need a session".to_owned()));
        };
        let mut listed: Vec<&Request> = self
            .requests
            .iter()
            .filter(|request| request.session_id == session)
            .collect();
        listed.sort_by(|left, right| left.request_id.cmp(&right.request_id));
        let requests = listed.into_iter().map(request_entry).collect::<Vec<_>>();
        Ok(json!({ "requests": requests }))
    }

    /// `GET /api/capability/pending`.
    ///
    /// The shell receives every session's still-pending requests. The shell
    /// check runs before the store is read. A record whose status is not
    /// `Pending` is omitted. The remainder is sorted by `session_id`, then
    /// `request_id`. Each entry reads `request_id`, `session_id`, `resource`,
    /// `action` and `reason` from the request, `requested_at` from the
    /// request, and `expires_at` from `pending_expires_at`. This read grants
    /// nothing and settles nothing.
    pub fn get_capability_pending(&self, caller: Caller<'_>) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let mut listed: Vec<&Request> = self
            .requests
            .iter()
            .filter(|request| request.status == RequestStatus::Pending)
            .collect();
        listed.sort_by(|left, right| {
            left.session_id
                .cmp(&right.session_id)
                .then(left.request_id.cmp(&right.request_id))
        });
        let requests = listed
            .into_iter()
            .map(|request| {
                json!({
                    "request_id": request.request_id,
                    "session_id": request.session_id,
                    "resource": request.resource,
                    "action": request.action,
                    "reason": request.reason,
                    "requested_at": request.requested_at,
                    "expires_at": pending_expires_at(request.requested_at),
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({ "requests": requests }))
    }

    /// `POST /api/capability/request`.
    ///
    /// A client instance that is `starting` or `running` stores one pending
    /// request through `seed_request`. A shell is refused before the body is
    /// read. A `stopped` or `failed` instance is not live and stores nothing.
    /// After the scheme and action checks, and before anything is stored, the
    /// live instance's session is traced to the admitted row of the guest its
    /// launch started, and the request must be declared in that bundle's
    /// signed asks (M1 check B2): status 403 with `ask not declared in the
    /// signed manifest: <resource> <action>` otherwise. Coverage is an exact
    /// match on the resource and the lowercased action, so no prefix and no
    /// other action covers it. Ok is `{"status": "pending", "request_id":
    /// ...}` and carries no token.
    pub fn post_capability_request(
        &mut self,
        caller: Caller<'_>,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        let Caller::Client { session_id } = caller else {
            return Err((
                403,
                "capability request needs an instance session".to_owned(),
            ));
        };
        let fields = request_body(body);
        let (resource, given_action, reason, plan) = fields?;
        if !resource.starts_with("elastos://") && !resource.starts_with("localhost://") {
            return Err((
                400,
                "Unsupported resource scheme. Allowed: elastos://, localhost://".to_owned(),
            ));
        }
        let action = given_action.to_lowercase();
        if !matches!(
            action.as_str(),
            "read" | "write" | "execute" | "delete" | "message" | "admin"
        ) {
            return Err((
                400,
                format!(
                    "Invalid action: {given_action}. Expected: read, write, execute, delete, message, admin"
                ),
            ));
        }
        let phase = self
            .instances
            .iter()
            .find(|instance| instance.id == session_id)
            .map(|instance| instance.phase)
            .ok_or_else(|| unknown_instance(session_id))?;
        if !matches!(phase, ResidentStatus::Starting | ResidentStatus::Running) {
            return Err(not_live(phase));
        }
        self.declared_ask(session_id, resource, &action)?;
        let plan = plan.map(str::to_owned);
        let request_id = format!("request-{}", self.next_request);
        self.seed_request(&request_id, session_id, resource, &action, reason)?;
        let stored = self
            .requests
            .iter_mut()
            .find(|request| request.request_id == request_id)
            .expect("seed_request just stored this request");
        stored.plan = plan;
        self.next_request += 1;
        Ok(json!({ "status": "pending", "request_id": request_id }))
    }

    /// Lab observation, not a route.
    ///
    /// Reads the shell capsule list and that session's shell request records
    /// through the existing reads. A `stopped` or `failed` instance at the
    /// test instant stays listed with that status and one request record that
    /// is not pending. This method reads no clock and no disk.
    pub fn watch_ended(&self, session_id: &str, ended: &str) -> Result<(), (u16, String)> {
        if ended != "stopped" && ended != "failed" {
            return Err((400, "watch status must be stopped or failed".to_owned()));
        }
        let listed = self.get_capsules(Caller::Shell)?;
        let Some(entry) = listed["capsules"]
            .as_array()
            .and_then(|capsules| capsules.iter().find(|entry| entry["id"] == session_id))
        else {
            return Err((400, format!("left the instance list: {session_id}")));
        };
        let status = entry["status"].as_str().unwrap_or("");
        if status != ended {
            return Err((
                400,
                format!("changed from {ended} to {status}: {session_id}"),
            ));
        }
        let records = self.get_capability_requests(Caller::Shell, Some(session_id))?;
        let requests = records["requests"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if requests
            .iter()
            .any(|request| request["status"] == "pending")
        {
            return Err((400, format!("made a request after it ended: {session_id}")));
        }
        if requests.len() != 1 {
            return Err((
                400,
                format!(
                    "{session_id} has {} request records after it ended",
                    requests.len()
                ),
            ));
        }
        Ok(())
    }

    /// `POST /api/capability/deny`.
    ///
    /// A shell denies one pending request through the one writer, which stores
    /// `shell` as settler. A `starting` instance with that session ends
    /// `failed` with the deny reason as its cause, then `revoke_live` ends that
    /// session's `Live` grants and `settle_pending` denies its other pending
    /// requests with the same cause; any other phase stays. Ok is
    /// `{"success": true}`.
    pub fn post_capability_deny(
        &mut self,
        caller: Caller<'_>,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let (request_id, reason) = deny_body(body)?;
        let Some(request) = self
            .requests
            .iter()
            .find(|request| request.request_id == request_id)
        else {
            return Err((400, format!("unknown request: {request_id}")));
        };
        if request.status != RequestStatus::Pending {
            return Err((400, format!("request is not pending: {request_id}")));
        }
        let session_id = request.session_id.clone();
        self.settle_record(request_id, RequestStatus::Denied, reason, "shell");
        let instant = self.instant;
        let mut failed = false;
        if let Some(instance) = self
            .instances
            .iter_mut()
            .find(|instance| instance.id == session_id.as_str())
        {
            if instance.phase == ResidentStatus::Starting {
                instance.phase = ResidentStatus::Failed;
                instance.cause = reason.to_owned();
                instance.ended_at = Some(instant);
                failed = true;
            }
        }
        if failed {
            let cause = reason.to_owned();
            self.revoke_live(&session_id);
            self.settle_pending(&session_id, &cause);
        }
        Ok(json!({ "success": true }))
    }

    /// `POST /api/capability/grant`.
    ///
    /// A shell grants one pending request through the one writer, which stores
    /// `granted`, the rationale and `shell` as settler. `seed_grant` then
    /// stores the one `Live` grant for that request. Ok is
    /// `{"success": true}` and carries no token. A client is refused before
    /// the body is read, so the requester and its sibling resident cannot
    /// approve their own pending request.
    ///
    /// A request that stored a plan hash (M1 check A15a) is granted only when
    /// the body carries `plan_sha256` equal to that hash, so the owner
    /// approves the plan the agent requested and the shell showed. A missing
    /// or different hash is status 403 with `approved plan does not match the
    /// requested plan`; a body hash on a request that stored none is status
    /// 400 with `request has no plan to approve`. Either refusal mints
    /// nothing and leaves the request pending. The one mint helper
    /// `mint_plan_binding` then reads the hash from the folded record, not
    /// from the body.
    pub fn post_capability_grant(
        &mut self,
        caller: Caller<'_>,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let parsed = grant_body(body);
        let GrantBody {
            request_id,
            duration,
            rationale,
            plan_sha256,
        } = parsed?;
        let Some(request) = self
            .requests
            .iter()
            .find(|request| request.request_id == request_id)
        else {
            return Err((400, format!("unknown request: {request_id}")));
        };
        if request.status != RequestStatus::Pending {
            return Err((400, format!("request is not pending: {request_id}")));
        }
        match (&request.plan, plan_sha256) {
            (Some(requested), Some(approved)) if approved == requested.as_str() => {}
            (Some(_), _) => return Err(approved_plan_mismatch()),
            (None, Some(_)) => return Err((400, "request has no plan to approve".to_owned())),
            (None, None) => {}
        }
        let request_id = request.request_id.clone();
        let session_id = request.session_id.clone();
        let resource = request.resource.clone();
        let action = request.action.clone();
        let plan = request.plan.clone();
        self.settle_record(&request_id, RequestStatus::Granted, rationale, "shell");
        let instant = self.instant;
        self.seed_grant(
            &request_id,
            &session_id,
            &resource,
            &action,
            duration,
            instant,
            Life::Live,
            false,
        );
        let minted = mint_plan_binding(&plan);
        let run = mint_run_binding(&request_id);
        if let Some(stored) = self
            .grants
            .iter_mut()
            .find(|grant| grant.request_id == request_id.as_str())
        {
            stored.plan = minted;
            stored.run = run.clone();
        }
        Ok(json!({ "success": true }))
    }

    /// `GET /api/capability/request/:id`.
    ///
    /// `request_id` is the path, a method argument, not a JSON field. The
    /// lookup runs before the caller check. A record that is missing is status
    /// 404 with `Request not found: ` plus that id. A shell, or a client whose
    /// session is not the record's, is status 403 with `Cannot access another
    /// session's request`. Ok carries the stored status word, and a denied or
    /// expired record also carries its decision reason. It carries no token
    /// and stores nothing.
    pub fn get_capability_request(
        &self,
        caller: Caller<'_>,
        request_id: &str,
    ) -> Result<Value, (u16, String)> {
        let Some(request) = self
            .requests
            .iter()
            .find(|request| request.request_id == request_id)
        else {
            return Err((404, format!("Request not found: {request_id}")));
        };
        let owns = matches!(
            caller,
            Caller::Client { session_id } if session_id == request.session_id
        );
        if !owns {
            return Err((403, "Cannot access another session's request".to_owned()));
        }
        let status = request_status_text(request.status);
        match request.status {
            RequestStatus::Pending | RequestStatus::Granted => Ok(json!({ "status": status })),
            RequestStatus::Denied | RequestStatus::Expired => Ok(json!({
                "status": status,
                "reason": request.decision_reason,
            })),
        }
    }

    /// `GET /api/capability/list` for the plain route or `?scope=`.
    pub fn get_capability_list(
        &self,
        caller: Caller<'_>,
        scope: Option<&str>,
    ) -> Result<Value, (u16, String)> {
        if let Some(scope) = scope {
            if scope != LIVE_SCOPE {
                return Err((400, format!("unknown capability list scope: {scope}")));
            }
            require_shell(caller)?;
        }
        Ok(self.render(caller))
    }

    /// `POST /api/capability/validate`.
    ///
    /// This is the one use path. The body's keys are `request_id` and an
    /// optional string `plan_sha256`, the hash of the canonical plan bytes the
    /// instance means to run. A shell is refused before the body is read, as
    /// on every other client route. A `once` grant stores `Exhausted` on the
    /// first success, so the live view omits it and a second use is not live.
    /// A grant bound to a plan authorises that plan's hash alone.
    pub fn post_capability_validate(
        &mut self,
        caller: Caller<'_>,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        require_client(caller)?;
        let (request_id, run_id, plan_sha256) = validate_body(body)?;
        self.authorise(caller, request_id, run_id, plan_sha256)?;
        Ok(json!({ "valid": true }))
    }

    /// `POST /api/hosted-effect` (M1 check A6), the stand-in's hosted effect
    /// socket. A hosted effect carries no grant id and no session: the
    /// provider sends the offer, the effect, and the pair `(run_id,
    /// request_id)` the grant route minted
    /// (`capsules/model-provider/src/adapters.rs:61-70`). That pair alone
    /// names the grant, and the grant's own session is then checked, so an
    /// agent that presents another agent's pair is refused. Ok is
    /// `{"valid": true}`; every refusal spends nothing.
    pub fn post_hosted_effect(
        &mut self,
        caller: Caller<'_>,
        offer_id: &str,
        effect: &str,
        run_id: &str,
        request_id: &str,
    ) -> Result<Value, (u16, String)> {
        if offer_id.is_empty() || effect.is_empty() {
            return Err((400, "hosted effect needs an offer and an effect".to_owned()));
        }
        self.authorise(caller, request_id, Some(run_id), None)?;
        Ok(json!({ "valid": true }))
    }

    /// The pair the grant route minted for `request_id`, read back by the
    /// grant's own session. `GET /api/capability/run-binding`.
    ///
    /// This is a read, not a use: it spends nothing and changes no record.
    /// It exists because the grant route's answer stays exactly
    /// `{"success": true}` (its shape is a standing contract), so an instance
    /// that wants to present the pair on a hosted effect reads it here. Only
    /// the grant's own session reads it, and only while the grant is live, so
    /// a sibling learns nothing (M1 check A6). A request id with no grant is
    /// status 400 `unknown grant`; a sibling or the shell is status 403.
    pub fn get_run_binding(
        &self,
        caller: Caller<'_>,
        request_id: &str,
    ) -> Result<Value, (u16, String)> {
        let Some(grant) = self
            .grants
            .iter()
            .find(|grant| grant.request_id == request_id)
        else {
            return Err(unknown_grant());
        };
        if !is_live(grant.life) {
            return Err(grant_not_live(grant.life));
        }
        if !session_authorises(grant, caller) {
            return Err(wrong_capsule(grant, caller));
        }
        Ok(json!({
            "run_id": grant.run.run_id,
            "request_id": grant.run.request_id,
        }))
    }

    /// The one use check. `post_capability_validate` is its route.
    ///
    /// `Ok(())` means the grant authorises that caller and, for a bound grant,
    /// that exact plan hash, and a `once` grant stores `Exhausted`. Every
    /// refusal runs before that store, so a refused use spends nothing. This
    /// method reads no clock, no disk and no WIT file.
    fn authorise(
        &mut self,
        caller: Caller<'_>,
        request_id: &str,
        run_id: Option<&str>,
        plan_sha256: Option<&str>,
    ) -> Result<(), (u16, String)> {
        let Some(index) = self
            .grants
            .iter()
            .position(|grant| grant.request_id == request_id)
        else {
            return Err(unknown_grant());
        };
        let run_matches = run_accepts(&self.grants[index], run_id);
        let grant = &self.grants[index];
        if !is_live(grant.life) {
            return Err(grant_not_live(grant.life));
        }
        if is_due(grant, self.instant) {
            return Err(grant_not_live(Life::Expired));
        }
        if !run_matches {
            return Err(unminted_run(run_id.unwrap_or_default(), request_id));
        }
        if !session_authorises(grant, caller) {
            return Err(wrong_capsule(grant, caller));
        }
        if !plan_accepts(grant.plan.as_ref(), plan_sha256) {
            return Err(plan_not_bound());
        }
        if grant.duration == "once" {
            self.grants[index].life = Life::Exhausted;
        }
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Stores one resident guest for the bundle at `bundle`, keyed by that
    /// bundle's lab CID, with the manifest's own name (M1 check B1). The one
    /// walk is `checked_bundle`; the one signature check is
    /// `verify_checked_signature` over the bytes that walk read, against the
    /// explicit `accepted` publisher list. A walk refusal is status 400 with
    /// its own text; a signature or name refusal is status 403 with its own
    /// text. A refused admission stores nothing. `Ok(())` grants nothing.
    ///
    /// The asks that request route checks come from `asks.json` in those same
    /// checked bytes (M1 check B2): the row takes `CheckedBundle::entry` of
    /// the walked file, and a schema it does not read, or no such file, is
    /// status 400 with its own text. No asks are taken from disk a second
    /// time and none come from this call's arguments.
    ///
    /// A `content` manifest is content, never code: it opens by CID as
    /// content and never runs as code, so it is refused here with status 403
    /// and the one content reason, and nothing is stored.
    pub fn admit_resident(
        &mut self,
        bundle: &Path,
        sig: &NameSignature,
        accepted: &[String],
        start: Start,
    ) -> Result<(), (u16, String)> {
        let checked = check_bundle(bundle, sig, accepted)?;
        refuse_content(&checked)?;
        let cid = checked.cid();
        if self.admitted.iter().any(|row| row.cid == cid) {
            return Err((403, format!("bundle already admitted: {cid}")));
        }
        let asks = admitted_asks(&checked)?;
        self.admitted.push(Admitted {
            cid,
            name: checked.manifest_name().to_owned(),
            start,
            world: RESIDENT_WORLD,
            bundle: bundle.to_path_buf(),
            sig: sig.clone(),
            accepted: accepted.to_vec(),
            asks,
        });
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Applies the admitted `Start` once. This is the stand-in's `resident.start`.
    /// An `Error` or `Trap` stores `failed`, then `revoke_live` ends that
    /// session's `Live` grants and the pending requests are denied with its cause.
    pub fn finish_start(&mut self, id: &str) -> Result<(), (u16, String)> {
        let instant = self.instant;
        let Some(instance) = self.instances.iter_mut().find(|instance| instance.id == id) else {
            return Err(unknown_instance(id));
        };
        if matches!(
            instance.phase,
            ResidentStatus::Stopped | ResidentStatus::Stopping
        ) {
            return Err(not_live(instance.phase));
        }
        if instance.phase != ResidentStatus::Starting {
            return Err((400, "start already returned".to_owned()));
        }
        let (phase, cause, ended_at) = apply_start(&instance.start, instant);
        instance.phase = phase;
        instance.cause = cause;
        instance.ended_at = ended_at;
        if phase != ResidentStatus::Failed {
            return Ok(());
        }
        let session_id = instance.id.clone();
        let cause = instance.cause.clone();
        self.revoke_live(&session_id);
        self.settle_pending(&session_id, &cause);
        Ok(())
    }

    /// Lab test seam, not a route.
    ///
    /// Replaces the instant used for ended-entry age and request age. It then
    /// expires the due pending requests through `expire_due`. This method reads
    /// no clock.
    pub fn set_instant(&mut self, secs: u64) {
        self.instant = secs;
        self.expire_due();
    }

    /// `POST /api/capsules`.
    ///
    /// The body's only key is `cid`, a printed lab CID. Only a row admitted
    /// under exactly that CID launches; there is no path fallback (M1 check
    /// B1). The row's one walk and one signature check run again over the
    /// bytes on disk now, with the row's own signature and accepted list, so
    /// bytes changed or a signature that no longer verifies after admission
    /// is refused with status 403 and the library's own text. That check
    /// compares the row's signature name with the bytes, so a changed bundle
    /// is refused there with `Refusal::NameMismatch`, before any other
    /// compare. The launch names the instance from the row's checked manifest
    /// name. A launch adds one `Starting` instance and no grant.
    ///
    /// Those bytes carry the asks too (M1 check B2). Any changed byte, the
    /// `asks.json` bytes included, leaves the bundle under a new lab CID, so
    /// this walk's `check_name` refuses it with the row's name and no ask is
    /// read from a bundle other than the one admitted. A refusal keeps the
    /// launch, its instance and its grants out.
    pub fn post_capsules(
        &mut self,
        caller: Caller<'_>,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let cid = launch_cid(body)?;
        let row = self.admit_row(cid)?;
        check_bundle(&row.bundle, &row.sig, &row.accepted)?;
        let name = row.name.clone();
        let start = row.start.clone();
        let id = self.mint_id();
        let phase = ResidentStatus::Starting;
        self.instances.push(Instance {
            id: id.clone(),
            name: name.clone(),
            start,
            phase,
            cause: String::new(),
            ended_at: None,
            started_cid: cid,
        });
        Ok(launch_body(&id, &name, phase))
    }

    /// `GET /api/capsules`.
    pub fn get_capsules(&self, caller: Caller<'_>) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let mut listed: Vec<&Instance> = self
            .instances
            .iter()
            .filter(|instance| keeps_instance(instance, self.instant))
            .collect();
        listed.sort_by(|left, right| left.id.cmp(&right.id));
        let capsules = listed.into_iter().map(capsule_entry).collect::<Vec<_>>();
        Ok(json!({ "capsules": capsules }))
    }

    /// `DELETE /api/capsules/:id`.
    ///
    /// `id` is the path segment. The shell body carries `reason`. Ok is null.
    pub fn delete_capsule(
        &mut self,
        caller: Caller<'_>,
        id: &str,
        body: &Value,
    ) -> Result<Value, (u16, String)> {
        require_shell(caller)?;
        let reason = stop_reason(body)?;
        self.stop_one(id, reason)?;
        Ok(Value::Null)
    }

    fn stop_one(&mut self, id: &str, reason: &str) -> Result<(), (u16, String)> {
        self.end_instance(id, ResidentStatus::Stopped, format!("stopped: {reason}"))
    }

    /// Lab test seam, not a route.
    ///
    /// Stands for the Runtime reaping a worker that died with no stop
    /// request (M1 check A11). `id` is the only argument; the cause is the
    /// fixed cause `worker exited` and the settler is `runtime`. It ends that
    /// one instance `failed` through `end_instance`, the same path a stop
    /// takes, so the instance leaves the live set and its pending requests
    /// settle. An unknown id, or an instance that is already `stopped` or
    /// `failed`, is refused and changes nothing. Other instances stay.
    pub fn worker_exited(&mut self, id: &str) -> Result<(), (u16, String)> {
        self.end_instance(id, ResidentStatus::Failed, WORKER_EXITED.to_owned())
    }

    /// The one end path for a live instance. `delete_capsule` reaches it
    /// through `stop_one` with `stopped` and the stop cause; `worker_exited`
    /// reaches it with `failed` and the fixed cause. An unknown id, or an
    /// instance that is not `starting` or `running`, is refused before
    /// anything changes. It writes the phase, the cause and `ended_at`, then
    /// `revoke_live` ends that session's `Live` grants and `settle_pending`
    /// denies its pending requests with that cause.
    fn end_instance(
        &mut self,
        id: &str,
        phase: ResidentStatus,
        cause: String,
    ) -> Result<(), (u16, String)> {
        let instant = self.instant;
        let Some(index) = self.instances.iter().position(|instance| instance.id == id) else {
            return Err(unknown_instance(id));
        };
        let current = self.instances[index].phase;
        if !matches!(current, ResidentStatus::Starting | ResidentStatus::Running) {
            return Err(not_live(current));
        }
        let session_id = self.instances[index].id.clone();
        self.instances[index].phase = phase;
        self.instances[index].cause = cause.clone();
        self.instances[index].ended_at = Some(instant);
        self.revoke_live(&session_id);
        self.settle_pending(&session_id, &cause);
        Ok(())
    }

    /// Writes `Revoked` on `Live` grants of one session. Other lives stay.
    fn revoke_live(&mut self, session_id: &str) {
        for grant in &mut self.grants {
            if grant.session_id == session_id && is_live(grant.life) {
                grant.life = Life::Revoked;
            }
        }
    }

    /// The one request writer. It stores the status, the reason and the
    /// settler on one request.
    ///
    /// The stop and failed-start settlement passes `denied` and `runtime`; the
    /// shell deny route passes `denied` and `shell`; the grant route passes
    /// `granted` and `shell`.
    fn settle_record(
        &mut self,
        request_id: &str,
        status: RequestStatus,
        reason: &str,
        settled_by: &'static str,
    ) {
        if let Some(request) = self
            .requests
            .iter_mut()
            .find(|request| request.request_id == request_id)
        {
            request.status = status;
            request.decision_reason = reason.to_owned();
            request.settled_by = Some(settled_by);
        }
    }

    /// Denies the pending requests of one session with that instance's cause.
    ///
    /// Only `Pending` records change; a record of another session stays. The
    /// one writer stores `runtime` as settler.
    fn settle_pending(&mut self, session_id: &str, cause: &str) {
        let pending = self
            .requests
            .iter()
            .filter(|request| {
                request.session_id == session_id && request.status == RequestStatus::Pending
            })
            .map(|request| request.request_id.clone())
            .collect::<Vec<_>>();
        for request_id in pending {
            self.settle_record(&request_id, RequestStatus::Denied, cause, "runtime");
        }
    }

    /// Not a route. Expires the pending requests whose age is at least
    /// `REQUEST_TIMEOUT_SECS`.
    ///
    /// Age is the stored instant minus that request's `requested_at`. Only
    /// `Pending` records change. The one writer stores `expired`,
    /// `Request timed out` and `runtime` as settler. This method reads no clock.
    fn expire_due(&mut self) {
        let instant = self.instant;
        let due = self
            .requests
            .iter()
            .filter(|request| {
                request.status == RequestStatus::Pending
                    && instant.saturating_sub(request.requested_at) >= REQUEST_TIMEOUT_SECS
            })
            .map(|request| request.request_id.clone())
            .collect::<Vec<_>>();
        for request_id in due {
            self.settle_record(
                &request_id,
                RequestStatus::Expired,
                "Request timed out",
                "runtime",
            );
        }
    }

    fn mint_id(&mut self) -> String {
        let id = format!("component-{}", self.next_id);
        self.next_id += 1;
        id
    }

    fn admit_row(&self, cid: LabCid) -> Result<&Admitted, (u16, String)> {
        if let Some(row) = self.admitted.iter().find(|row| row.cid == cid) {
            return Ok(row);
        }
        Err(self.not_admitted(cid))
    }

    /// The one declared-ask check. `post_capability_request` is its route.
    ///
    /// Traces the live instance's session to the lab CID its launch started,
    /// then to that admitted row's signed asks. `resource` is the body's
    /// resource unchanged; `action` is already lowercased by the route, as an
    /// ask's `kind` is when the row is admitted. One ask covers the request
    /// when both fields are equal, so no prefix and no other action covers
    /// it. A request that matches no such ask is status 403 with one reason; this
    /// method reads no disk and stores nothing.
    fn declared_ask(
        &self,
        session_id: &str,
        resource: &str,
        action: &str,
    ) -> Result<(), (u16, String)> {
        let cid = self
            .instances
            .iter()
            .find(|instance| instance.id == session_id)
            .map(|instance| instance.started_cid)
            .ok_or_else(|| unknown_instance(session_id))?;
        let asks = &self.admit_row(cid)?.asks;
        if asks
            .iter()
            .any(|ask| ask.kind == action && ask.resource == resource)
        {
            return Ok(());
        }
        Err((
            403,
            format!("ask not declared in the signed manifest: {resource} {action}"),
        ))
    }

    fn not_admitted(&self, cid: LabCid) -> (u16, String) {
        (
            404,
            format!(
                "no bundle is admitted under {cid} in world {}",
                self.resident_world()
            ),
        )
    }

    fn resident_world(&self) -> &'static str {
        self.admitted
            .first()
            .map(|row| row.world)
            .unwrap_or(RESIDENT_WORLD)
    }

    fn render(&self, caller: Caller<'_>) -> Value {
        let mut grants = self.kept(caller);
        let shell = matches!(caller, Caller::Shell);
        if shell {
            grants.sort_by(|left, right| {
                left.session_id
                    .cmp(&right.session_id)
                    .then(left.request_id.cmp(&right.request_id))
            });
        } else {
            grants.sort_by(|left, right| left.request_id.cmp(&right.request_id));
        }
        let capabilities = grants
            .iter()
            .map(|grant| entry(grant, shell))
            .collect::<Vec<_>>();
        body(shell, capabilities)
    }

    /// One filter. A grant stays when its life is `Live`. An ended session stays.
    fn kept(&self, caller: Caller<'_>) -> Vec<&Grant> {
        self.grants
            .iter()
            .filter(|grant| keep(grant, caller, self.instant))
            .collect()
    }
}

fn keep(grant: &Grant, caller: Caller<'_>, instant: u64) -> bool {
    // Ending a session leaves a live grant in this view.
    let _ended = grant.session_ended;
    is_live(grant.life) && !is_due(grant, instant) && visible(grant, caller)
}

/// One expiry compare. `keep` and `authorise` use it with the stored instant.
/// A grant at or past its `expires_at` no longer authorises and leaves the view.
fn is_due(grant: &Grant, instant: u64) -> bool {
    matches!(grant.expires_at, Some(expires_at) if instant >= expires_at)
}

/// Life seconds of one granted duration. `once` lasts `GRANT_LIFETIME_SECS`
/// and `session` lasts until its session ends, so it has no instant.
fn expiry_at(duration: &str, granted_at: u64) -> Option<u64> {
    match duration {
        "once" => Some(granted_at.saturating_add(GRANT_LIFETIME_SECS)),
        _ => None,
    }
}

/// One life test. `keep`, `revoke_live` and `authorise` use it.
fn is_live(life: Life) -> bool {
    life == Life::Live
}

fn visible(grant: &Grant, caller: Caller<'_>) -> bool {
    match caller {
        Caller::Shell => true,
        Caller::Client { session_id } => grant.session_id == session_id,
    }
}

/// Session decision for `authorise`. A shell sees every grant and still does
/// not hold it. The session compare stays in `visible`.
fn session_authorises(grant: &Grant, caller: Caller<'_>) -> bool {
    !matches!(caller, Caller::Shell) && visible(grant, caller)
}

fn entry(grant: &Grant, include_session: bool) -> Value {
    let mut fields = Map::new();
    fields.insert("request_id".to_owned(), json!(grant.request_id));
    if include_session {
        fields.insert("session_id".to_owned(), json!(grant.session_id));
    }
    fields.insert("resource".to_owned(), json!(grant.resource));
    fields.insert("action".to_owned(), json!(grant.action));
    fields.insert("duration".to_owned(), json!(grant.duration));
    fields.insert("granted_at".to_owned(), json!(grant.granted_at));
    Value::Object(fields)
}

fn body(shell: bool, capabilities: Vec<Value>) -> Value {
    if shell {
        json!({
            "scope": LIVE_SCOPE,
            "capabilities": capabilities,
        })
    } else {
        json!({ "capabilities": capabilities })
    }
}

/// `expires_at` for one pending entry. The one timeout is `REQUEST_TIMEOUT_SECS`.
fn pending_expires_at(requested_at: u64) -> u64 {
    requested_at.saturating_add(REQUEST_TIMEOUT_SECS)
}

fn request_entry(request: &Request) -> Value {
    json!({
        "request_id": request.request_id,
        "session_id": request.session_id,
        "resource": request.resource,
        "action": request.action,
        "reason": request.reason,
        "status": request_status_text(request.status),
        "decision_reason": request.decision_reason,
        "settled_by": request.settled_by,
        // The plan hash the agent asked to run, so the owner can read and
        // approve it (M1 check A15a). Null when the request stored no plan.
        "plan": request.plan,
    })
}

/// The four request status strings this slice stores.
fn request_status_text(status: RequestStatus) -> &'static str {
    match status {
        RequestStatus::Pending => "pending",
        RequestStatus::Granted => "granted",
        RequestStatus::Denied => "denied",
        RequestStatus::Expired => "expired",
    }
}

/// The one file name a storage entry may name: exactly one normal component.
/// An empty name, `.`, `..` or a name with a separator fails.
fn plain_name(entry: &str) -> bool {
    let mut parts = Path::new(entry).components();
    matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(_)), None)
    )
}

/// The one regular-file, one-link rule for a storage file. `create_storage`
/// on the file it just made and `storage_file` on the file it just opened
/// both call this, so a weaker rule is weaker on both paths.
fn check_file(stat: &rustix::fs::Stat) -> Result<(), (u16, String)> {
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        return Err((400, NOT_REGULAR_REASON.to_owned()));
    }
    if stat.st_nlink != 1 {
        return Err((400, NOT_ONE_LINK_REASON.to_owned()));
    }
    Ok(())
}

/// Where the storage walk stopped: on the storage directory itself, or on
/// the handle of the parent of the first absent step, with that step and
/// every step below it. Both cases hold a directory handle the walk reached
/// from the held Home handle, never a path.
enum Walk {
    Reached(OwnedFd),
    Absent {
        parent: OwnedFd,
        steps: Vec<std::ffi::OsString>,
    },
}

/// Opens the Home once, at holder creation. The Home must be absolute and
/// hold no `.` or `..` component. Its ancestors are resolved once here: the
/// Home's parent is opened by path for reading and directory access, so a
/// symbolic link among the ancestors is followed this one time (system
/// ancestors such as `/var` on macOS are links). The Home's own name is then
/// the final component, taken on that parent handle with the existing
/// `O_DIRECTORY|O_NOFOLLOW` step, so a link at the Home itself is refused
/// and nothing is followed. This is the only place a Home path is opened;
/// every later storage call walks below the returned handle. An absent
/// component is the missing storage directory.
fn open_home(home: &Path) -> Result<OwnedFd, (u16, String)> {
    use std::os::fd::AsFd;

    // A relative Home would start at the current directory, which is never
    // the selected Home, so it is refused before any open.
    if !home.is_absolute() {
        return Err((400, DATA_REASON.to_owned()));
    }
    let mut parts = home
        .components()
        .map(|part| match part {
            Component::RootDir => Ok(None),
            Component::Normal(part) => Ok(Some(part)),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                Err((400, DATA_REASON.to_owned()))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let Some(name) = parts.pop().flatten() else {
        return Err((400, DATA_REASON.to_owned()));
    };
    let Some(parent) = home.parent() else {
        return Err((400, DATA_REASON.to_owned()));
    };
    let opened = rustix::fs::open(
        parent,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            (400, MISSING_STORAGE_REASON.to_owned())
        } else {
            storage_failure(&error)
        }
    })?;
    // The Home must be present: an absent final component is the missing
    // storage directory, as before.
    let present = |_: &rustix::io::Errno| false;
    match step(opened.as_fd(), &present, &storage_failure, name)? {
        Some(held) => Ok(held),
        None => Err((400, MISSING_STORAGE_REASON.to_owned())),
    }
}

/// One directory step of the storage walk: `name` is opened on the handle of
/// its parent with `O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, so a name is
/// never a multi-component path and a symbolic link is refused, not followed.
/// The caller's `missing` predicate says which error is an absent step; every
/// other error goes through the caller's one reason for its refusal.
fn step(
    parent: std::os::fd::BorrowedFd<'_>,
    missing: &dyn Fn(&rustix::io::Errno) -> bool,
    refused: &dyn Fn(&rustix::io::Errno) -> (u16, String),
    name: &std::ffi::OsStr,
) -> Result<Option<OwnedFd>, (u16, String)> {
    match rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(next) => Ok(Some(next)),
        Err(error) if missing(&error) => Ok(None),
        Err(error) => Err(refused(&error)),
    }
}

/// The refusal for an entry that `mkdirat` reported as present. The entry is
/// opened once here without following a link: a symbolic link is the link
/// rule, and a real directory is its own reason. Nothing is created.
fn existing_step(directory: &OwnedFd, name: &std::ffi::OsStr) -> (u16, String) {
    use std::os::fd::AsFd;

    match rustix::fs::openat(
        directory.as_fd(),
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(_) => (409, EXISTING_STORAGE_REASON.to_owned()),
        // The entry `mkdirat` saw is not a directory and not a link: it is
        // the not-a-directory case. Every other error keeps its own reason.
        Err(error) if error == rustix::io::Errno::NOTDIR => (400, NOT_DIR_REASON.to_owned()),
        Err(error) => storage_failure(&error),
    }
}

/// Makes one directory step on a parent handle and opens it without
/// following a link. A present step is the link rule, because the walk
/// reported it absent and the tree changed under the creation.
fn make_step(parent: &OwnedFd, name: &std::ffi::OsStr) -> Result<OwnedFd, (u16, String)> {
    use std::os::fd::AsFd;

    rustix::fs::mkdirat(
        parent,
        name,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            existing_step(parent, name)
        } else {
            storage_failure(&error)
        }
    })?;
    rustix::fs::openat(
        parent.as_fd(),
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| storage_failure(&error))
}

/// A storage file open or `fstat` refusal. It names the file step, never the
/// directory step.
fn file_failure(error: &rustix::io::Errno) -> (u16, String) {
    match *error {
        rustix::io::Errno::LOOP => (400, NOT_REGULAR_REASON.to_owned()),
        _ => (400, format!("{ENTRY_STEP}: {error}")),
    }
}

/// The one storage-directory reason for every open step: the Home and every
/// step of `harness::data_dir(home)` down to the storage directory. Every
/// open on that walk asks for `O_NOFOLLOW|O_DIRECTORY`, so ELOOP and ENOTDIR
/// are the symbolic link the call refused to follow. ENOTDIR on an entry
/// that is a plain file is the separate not-a-directory case, which
/// `existing_step` reports itself.
fn storage_failure(error: &rustix::io::Errno) -> (u16, String) {
    match *error {
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => (400, LINK_REASON.to_owned()),
        rustix::io::Errno::NOENT => (400, MISSING_STORAGE_REASON.to_owned()),
        _ => (400, format!("{DATA_STEP}: {error}")),
    }
}

/// One refusal. A client on a shell-only route is status 403.
fn require_shell(caller: Caller<'_>) -> Result<(), (u16, String)> {
    match caller {
        Caller::Shell => Ok(()),
        Caller::Client { .. } => Err((403, "This endpoint requires shell privileges".to_owned())),
    }
}

/// The client check for `post_capability_validate`. The use path holds only an
/// instance session, so a shell is refused before the body is read.
fn require_client(caller: Caller<'_>) -> Result<(), (u16, String)> {
    match caller {
        Caller::Client { .. } => Ok(()),
        Caller::Shell => Err((
            403,
            "capability validate needs an instance session".to_owned(),
        )),
    }
}

/// The validate body's keys are `request_id` and an optional string
/// `plan_sha256`. The use names the plan it runs, and the hash is compared
/// with a bound grant's own hash.
/// The validate body's three fields: the request id, and the optional pair
/// `(run_id, plan_sha256)` a use may present.
type ValidateFields<'a> = (&'a str, Option<&'a str>, Option<&'a str>);

fn validate_body(body: &Value) -> Result<ValidateFields<'_>, (u16, String)> {
    const NEEDS_ID: &str = "validate body needs request_id";

    let Some(object) = body.as_object() else {
        return Err((400, NEEDS_ID.to_owned()));
    };
    let mut request_id = None;
    let mut run_id = None;
    let mut plan_sha256 = None;
    for (key, value) in object {
        match key.as_str() {
            "request_id" => match value {
                Value::String(text) => request_id = Some(text.as_str()),
                _ => return Err((400, "validate request_id must be a string".to_owned())),
            },
            "run_id" => match value {
                Value::String(text) => run_id = Some(text.as_str()),
                _ => return Err((400, "validate run_id must be a string".to_owned())),
            },
            "plan_sha256" => match value {
                Value::String(text) => plan_sha256 = Some(text.as_str()),
                _ => return Err((400, "validate plan_sha256 must be a string".to_owned())),
            },
            other => return Err((400, format!("validate body rejects {other}"))),
        }
    }
    let request_id = request_id.ok_or_else(|| (400, NEEDS_ID.to_owned()))?;
    Ok((request_id, run_id, plan_sha256))
}

/// The one mint helper for the run pair (M1 check A6). Only the grant route
/// calls it, so the pair exists only after the shell approved the request.
fn mint_run_binding(request_id: &str) -> RunBinding {
    RunBinding {
        run_id: RunBinding::run_id_for(request_id),
        request_id: request_id.to_owned(),
    }
}

/// The one refusal for a hosted effect whose pair this stand-in did not mint
/// (M1 check A6).
fn unminted_run(run_id: &str, request_id: &str) -> (u16, String) {
    (
        403,
        format!("effect run {run_id} is not bound to request {request_id}"),
    )
}

/// The one mint helper for an approved-plan binding. Only
/// `post_capability_grant` calls it, with the hash the request stored, so a
/// binding exists only on a grant the shell approved.
fn mint_plan_binding(plan: &Option<String>) -> Option<PlanBinding> {
    plan.as_ref().map(|plan_sha256| PlanBinding {
        plan_sha256: plan_sha256.clone(),
    })
}

/// The one run-pair compare (M1 check A6). A use that presents no run id
/// (the validate route) is compared on the request id alone. A use that
/// presents one must present the exact pair the grant route minted, and an
/// empty presented id is a pair this stand-in never minted. A seeded grant
/// holds an empty run id, so no presented pair reaches it, empty or not.
fn run_accepts(grant: &Grant, run_id: Option<&str>) -> bool {
    match run_id {
        None => true,
        Some("") => false,
        Some(run_id) => !grant.run.run_id.is_empty() && grant.run.run_id == run_id,
    }
}

/// One binding compare. A grant with no binding accepts any use, as before. A
/// bound grant accepts only a use that names its exact hash.
fn plan_accepts(binding: Option<&PlanBinding>, plan_sha256: Option<&str>) -> bool {
    match binding {
        None => true,
        Some(binding) => plan_sha256 == Some(binding.plan_sha256.as_str()),
    }
}

/// The one bound-grant refusal (M1 check A15a).
fn plan_not_bound() -> (u16, String) {
    (403, "grant is not bound to this plan".to_owned())
}

/// The one owner-hash refusal (M1 check A15a). The plan the owner approved is
/// not the plan the agent requested.
fn approved_plan_mismatch() -> (u16, String) {
    (
        403,
        "approved plan does not match the requested plan".to_owned(),
    )
}

/// The five status strings from the resident-instance list.
fn status_text(status: ResidentStatus) -> &'static str {
    match status {
        ResidentStatus::Starting => "starting",
        ResidentStatus::Running => "running",
        ResidentStatus::Stopping => "stopping",
        ResidentStatus::Stopped => "stopped",
        ResidentStatus::Failed => "failed",
    }
}

/// One library refusal as this stand-in answers it: its own text, unchanged.
fn said(refusal: &Refusal) -> String {
    refusal.to_string()
}

/// The one bundle check. Admission and launch both call it: one walk over the
/// bytes on disk now, then the one signature check over the bytes that walk
/// read against the explicit accepted list. A walk refusal is status 400 and
/// a signature or name refusal status 403, each with the library's own text.
fn check_bundle(
    bundle: &Path,
    sig: &NameSignature,
    accepted: &[String],
) -> Result<CheckedBundle, (u16, String)> {
    let checked = checked_bundle(bundle).map_err(|refusal| (400, said(&refusal)))?;
    verify_checked_signature(&checked, sig, accepted).map_err(|refusal| (403, said(&refusal)))?;
    Ok(checked)
}

/// The first key in `object` that is not one of `allowed`, in the object's
/// own order. `None` means every key is known.
fn unknown_key<'a>(object: &'a Map<String, Value>, allowed: &[&str]) -> Option<&'a str> {
    object
        .keys()
        .map(String::as_str)
        .find(|key| !allowed.contains(key))
}

/// The asks of one checked bundle, from the `asks.json` the walk read.
///
/// Provisional, mirrors the #464 draft: the schema is
/// `elastos.agent-host.asks/v1` and each ask is `{"kind": ..., "resource":
/// ...}`. This reads only `CheckedBundle::entry`, so it judges the bytes the
/// one walk named and the name signature covers, and it reads no folder. Each
/// `kind` is lowercased exactly as the request route lowercases an action, so
/// coverage is the route's own compare. A missing file, a file that is not
/// JSON, another schema, a missing field or an empty list is status 400 with
/// its own text. The file object may hold only `schema` and `asks`, and each
/// ask only `kind` and `resource`: any other key is status 400 with
/// `asks.json carries an unknown key: ` plus that key, and it stores nothing.
fn admitted_asks(checked: &CheckedBundle) -> Result<Vec<Ask>, (u16, String)> {
    const ASKS_FILE: &str = "asks.json";
    const ASKS_SCHEMA: &str = "elastos.agent-host.asks/v1";
    const ASKS_KEYS: [&str; 2] = ["schema", "asks"];
    const ASK_KEYS: [&str; 2] = ["kind", "resource"];
    const BAD_ASKS: &str = "asks.json does not follow the provisional ask schema";

    let bytes = checked
        .entry(ASKS_FILE)
        .ok_or_else(|| (400, format!("bundle declares no {ASKS_FILE}")))?;
    let file = serde_json::from_slice::<Value>(bytes).ok();
    let refuse_unknown = |key: &str| (400, format!("asks.json carries an unknown key: {key}"));
    if let Some(key) = file
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|object| unknown_key(object, &ASKS_KEYS))
    {
        return Err(refuse_unknown(key));
    }
    let bad = || (400, BAD_ASKS.to_owned());
    let schema = file
        .as_ref()
        .and_then(|file| file.get("schema"))
        .and_then(Value::as_str);
    let asks = file
        .as_ref()
        .and_then(|file| file.get("asks"))
        .and_then(Value::as_array);
    let (Some(schema), Some(asks)) = (schema, asks) else {
        return Err(bad());
    };
    if schema != ASKS_SCHEMA {
        return Err(bad());
    }
    for ask in asks {
        let object = ask.as_object().ok_or_else(bad)?;
        if let Some(key) = unknown_key(object, &ASK_KEYS) {
            return Err(refuse_unknown(key));
        }
    }
    if asks.is_empty() {
        return Err(bad());
    }
    asks.iter()
        .map(|ask| {
            Some(Ask {
                kind: ask.get("kind")?.as_str()?.to_lowercase(),
                resource: ask.get("resource")?.as_str()?.to_owned(),
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(bad)
}

/// The role a manifest names for content. Content opens by CID as content
/// and never runs as code (M2 exit (b)).
const CONTENT_ROLE: &str = "content";

/// The one content refusal. Admission calls it on the bundle it just checked,
/// so the role and the bytes it names are one value: no second read of
/// `capsule.json` and no path to re-resolve after the check. A bundle whose
/// manifest role is [`CONTENT_ROLE`] is status 403 with a reason naming it.
/// Any other role passes.
fn refuse_content(checked: &CheckedBundle) -> Result<(), (u16, String)> {
    if checked.manifest_role() == CONTENT_ROLE {
        return Err((
            403,
            format!(
                "bundle {cid} has role {CONTENT_ROLE}: content opens by CID and never runs as code",
                cid = checked.cid()
            ),
        ));
    }
    Ok(())
}

/// The launch body is an object whose only key is a string `cid`, parsed as
/// one printed lab CID by `LabCid`'s `FromStr`. A `path` or any other key is
/// status 400 with its own reason.
fn launch_cid(body: &Value) -> Result<LabCid, (u16, String)> {
    let Some(object) = body.as_object() else {
        return Err((400, "resident launch body needs cid".to_owned()));
    };
    let mut cid = None;
    let mut cid_not_string = false;
    for (key, value) in object {
        if key == "cid" {
            match value {
                Value::String(text) => cid = Some(text.as_str()),
                _ => cid_not_string = true,
            }
        } else {
            return Err((400, format!("resident launch body rejects {key}")));
        }
    }
    if cid_not_string {
        return Err((400, "resident launch cid must be a string".to_owned()));
    }
    let printed = cid.ok_or_else(|| (400, "resident launch body needs cid".to_owned()))?;
    LabCid::from_str(printed).map_err(|refusal| (400, said(&refusal)))
}

fn launch_body(id: &str, name: &str, phase: ResidentStatus) -> Value {
    json!({
        "id": id,
        "name": name,
        "status": status_text(phase),
        "session_id": id,
    })
}

fn capsule_entry(instance: &Instance) -> Value {
    json!({
        "id": instance.id,
        "name": instance.name,
        "status": status_text(instance.phase),
        "session_id": instance.id,
        "cause": instance.cause,
    })
}

/// Applies `Error` and `Trap` on one arm, and `Ok` on the other.
fn apply_start(start: &Start, instant: u64) -> (ResidentStatus, String, Option<u64>) {
    match start {
        Start::Ok => (ResidentStatus::Running, String::new(), None),
        Start::Error(text) | Start::Trap(text) => {
            (ResidentStatus::Failed, text.clone(), Some(instant))
        }
    }
}

/// One age compare. `failed` and `stopped` stay while age is under 60 seconds.
fn keeps_instance(instance: &Instance, instant: u64) -> bool {
    match instance.phase {
        ResidentStatus::Starting | ResidentStatus::Running => true,
        ResidentStatus::Failed | ResidentStatus::Stopped => match instance.ended_at {
            Some(at) => instant.saturating_sub(at) < FAILED_KEEP_SECS,
            None => false,
        },
        ResidentStatus::Stopping => false,
    }
}

/// One unknown-instance reason. `delete_capsule` and `finish_start` both use it.
fn unknown_instance(id: &str) -> (u16, String) {
    (400, format!("unknown instance: {id}"))
}

/// One unknown-grant reason. `authorise` uses it. The reason is fixed, so an
/// absent-id reply omits the supplied id.
fn unknown_grant() -> (u16, String) {
    (400, "unknown grant".to_owned())
}

fn life_text(life: Life) -> &'static str {
    match life {
        Life::Live => "Live",
        Life::Exhausted => "Exhausted",
        Life::Revoked => "Revoked",
        Life::Expired => "Expired",
    }
}

fn grant_not_live(life: Life) -> (u16, String) {
    (400, format!("grant is not live: {}", life_text(life)))
}

fn wrong_capsule(grant: &Grant, caller: Caller<'_>) -> (u16, String) {
    let mut reason = format!("wrong capsule: expected {}", grant.session_id);
    if let Caller::Client { session_id } = caller {
        reason.push_str(&format!(", got {session_id}"));
    }
    (403, reason)
}

/// One not-live reason. `delete_capsule` and `finish_start` both use it.
fn not_live(status: ResidentStatus) -> (u16, String) {
    (
        400,
        format!("instance is not live: {}", status_text(status)),
    )
}

/// The deny body's only keys are `request_id` and an optional string `reason`.
///
/// A missing reason is `Denied by user`.
fn deny_body(body: &Value) -> Result<(&str, &str), (u16, String)> {
    const NEEDS_ID: &str = "deny body needs request_id";
    const DEFAULT_REASON: &str = "Denied by user";

    let Some(object) = body.as_object() else {
        return Err((400, NEEDS_ID.to_owned()));
    };
    let mut request_id = None;
    let mut reason = None;
    let mut request_id_not_string = false;
    let mut reason_not_string = false;
    for (key, value) in object {
        match key.as_str() {
            "request_id" => match value {
                Value::String(text) => request_id = Some(text.as_str()),
                _ => request_id_not_string = true,
            },
            "reason" => match value {
                Value::String(text) => reason = Some(text.as_str()),
                _ => reason_not_string = true,
            },
            other => return Err((400, format!("deny body rejects {other}"))),
        }
    }
    if request_id_not_string {
        return Err((400, "deny request_id must be a string".to_owned()));
    }
    if reason_not_string {
        return Err((400, "deny reason must be a string".to_owned()));
    }
    let request_id = request_id.ok_or_else(|| (400, NEEDS_ID.to_owned()))?;
    Ok((request_id, reason.unwrap_or(DEFAULT_REASON)))
}

/// The grant body's keys are `request_id`, `duration`, `rationale` and an
/// optional string `plan_sha256`, the plan hash the owner approved.
///
/// A missing duration is `session`; a present duration is stored as its
/// lowercase form. A missing rationale is `Shell auto-grant`.
fn grant_body(body: &Value) -> Result<GrantBody<'_>, (u16, String)> {
    const NEEDS_ID: &str = "grant body needs request_id";
    const DEFAULT_DURATION: &str = "session";
    const DEFAULT_RATIONALE: &str = "Shell auto-grant";

    let Some(object) = body.as_object() else {
        return Err((400, NEEDS_ID.to_owned()));
    };
    let mut request_id = None;
    let mut duration = None;
    let mut rationale = None;
    let mut plan_sha256 = None;
    let mut request_id_not_string = false;
    let mut duration_not_string = false;
    let mut rationale_not_string = false;
    for (key, value) in object {
        match key.as_str() {
            "request_id" => match value {
                Value::String(text) => request_id = Some(text.as_str()),
                _ => request_id_not_string = true,
            },
            "duration" => match value {
                Value::String(text) => duration = Some(text.as_str()),
                _ => duration_not_string = true,
            },
            "rationale" => match value {
                Value::String(text) => rationale = Some(text.as_str()),
                _ => rationale_not_string = true,
            },
            "plan_sha256" => match value {
                Value::String(text) => plan_sha256 = Some(text.as_str()),
                _ => return Err((400, "grant plan_sha256 must be a string".to_owned())),
            },
            other => return Err((400, format!("grant body rejects {other}"))),
        }
    }
    if request_id_not_string {
        return Err((400, "grant request_id must be a string".to_owned()));
    }
    if duration_not_string {
        return Err((400, "grant duration must be a string".to_owned()));
    }
    if rationale_not_string {
        return Err((400, "grant rationale must be a string".to_owned()));
    }
    let request_id = request_id.ok_or_else(|| (400, NEEDS_ID.to_owned()))?;
    let duration = match duration {
        None => DEFAULT_DURATION,
        Some(text) => match text.to_lowercase().as_str() {
            "once" => "once",
            "session" => "session",
            _ => {
                return Err((
                    400,
                    format!("Invalid duration: {text}. Expected 'once' or 'session'"),
                ))
            }
        },
    };
    Ok(GrantBody {
        request_id,
        duration,
        rationale: rationale.unwrap_or(DEFAULT_RATIONALE),
        plan_sha256,
    })
}

/// One parsed grant body. Built only by `grant_body`.
struct GrantBody<'a> {
    request_id: &'a str,
    duration: &'a str,
    rationale: &'a str,
    plan_sha256: Option<&'a str>,
}

type RequestBody<'a> = (&'a str, &'a str, &'a str, Option<&'a str>);

/// The request body's only keys are `resource`, `action`, a `reason` and an
/// optional plan preview (`plan`, the preview's `sha256`).
///
/// The returned action is the given text; its lowercase form is checked by the
/// caller. A missing reason is `""`. A `plan` that is not a string is status
/// 400 with its own reason, and any other `plan*` key is `request body rejects
/// ` plus that key, so a plan value is never silently dropped. A string `plan`
/// is stored as given: it is the hash of the plan already previewed.
fn request_body(body: &Value) -> Result<RequestBody<'_>, (u16, String)> {
    const NEEDS_RESOURCE: &str = "request body needs resource";
    const NEEDS_ACTION: &str = "request body needs action";

    let Some(object) = body.as_object() else {
        return Err((400, NEEDS_RESOURCE.to_owned()));
    };
    let mut resource = None;
    let mut action = None;
    let mut reason = "";
    let mut plan = None;
    let mut resource_not_string = false;
    let mut action_not_string = false;
    let mut reason_not_string = false;
    let mut plan_not_string = false;
    for (key, value) in object {
        match key.as_str() {
            "resource" => match value {
                Value::String(text) => resource = Some(text.as_str()),
                _ => resource_not_string = true,
            },
            "action" => match value {
                Value::String(text) => action = Some(text.as_str()),
                _ => action_not_string = true,
            },
            "reason" => match value {
                Value::String(text) => reason = text.as_str(),
                _ => reason_not_string = true,
            },
            "plan" => match value {
                Value::String(text) => plan = Some(text.as_str()),
                _ => plan_not_string = true,
            },
            other => {
                return Err((400, format!("request body rejects {other}")));
            }
        }
    }
    if resource_not_string {
        return Err((400, "request resource must be a string".to_owned()));
    }
    let Some(resource) = resource else {
        return Err((400, NEEDS_RESOURCE.to_owned()));
    };
    if action_not_string {
        return Err((400, "request action must be a string".to_owned()));
    }
    let Some(action) = action else {
        return Err((400, NEEDS_ACTION.to_owned()));
    };
    if reason_not_string {
        return Err((400, "request reason must be a string".to_owned()));
    }
    if plan_not_string {
        return Err((400, "request plan must be a string".to_owned()));
    }
    Ok((resource, action, reason, plan))
}

/// The stop body is an object whose only key is a non-empty string `reason`.
fn stop_reason(body: &Value) -> Result<&str, (u16, String)> {
    let Some(object) = body.as_object() else {
        return Err((400, "stop body needs reason".to_owned()));
    };
    let mut reason = None;
    let mut reason_not_string = false;
    for (key, value) in object {
        if key != "reason" {
            return Err((400, format!("stop body rejects {key}")));
        }
        match value {
            Value::String(text) if text.is_empty() => {
                return Err((400, "stop needs a reason".to_owned()));
            }
            Value::String(text) => reason = Some(text.as_str()),
            _ => reason_not_string = true,
        }
    }
    if reason_not_string {
        return Err((400, "stop reason must be a string".to_owned()));
    }
    reason.ok_or_else(|| (400, "stop body misses reason".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::fs;

    use capsule_identity::sign_bundle;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    /// The committed `agent-host` fixture: a real bundle the walk accepts.
    const AGENT_HOST_FILES: [(&str, &[u8]); 2] = [
        (
            "capsule.json",
            include_bytes!("../../capsule-identity/fixtures/agent-host/capsule.json"),
        ),
        (
            "asks.json",
            include_bytes!("../../capsule-identity/fixtures/agent-host/asks.json"),
        ),
    ];

    /// One signed fixture bundle in a fresh tempdir, its accepted publisher
    /// and the key that signed it. A second `Shared` is a second bundle with
    /// other bytes, so it has its own lab CID.
    struct Shared {
        bundle: TempDir,
        accepted: Vec<String>,
        key: SigningKey,
    }

    impl Shared {
        fn new() -> Self {
            let bundle = TempDir::new().expect("make a bundle tempdir");
            write_agent_host(bundle.path());
            let key = fresh_key();
            let accepted = vec![did_of(&key)];
            Shared {
                bundle,
                accepted,
                key,
            }
        }

        fn path(&self) -> &Path {
            self.bundle.path()
        }

        /// The printed lab CID of this bundle's bytes: identity, not a grant.
        fn cid(&self) -> String {
            checked_bundle(self.path())
                .expect("the walk names the fixture bundle")
                .cid()
                .to_string()
        }

        fn signature(&self) -> NameSignature {
            sign_bundle(&self.key, self.path()).expect("sign the fixture bundle")
        }

        fn body(&self) -> Value {
            json!({ "cid": self.cid() })
        }

        fn admit(&self, standin: &mut StandIn, start: Start) -> Result<(), (u16, String)> {
            self.admit_with(standin, &self.signature(), start)
        }

        fn admit_with(
            &self,
            standin: &mut StandIn,
            sig: &NameSignature,
            start: Start,
        ) -> Result<(), (u16, String)> {
            standin.admit_resident(self.path(), sig, &self.accepted, start)
        }

        fn launch(&self, standin: &mut StandIn) -> Result<Value, (u16, String)> {
            standin.post_capsules(Caller::Shell, &self.body())
        }
    }

    /// A second signed bundle with other bytes and so another lab CID.
    fn other_bundle() -> Shared {
        let other = Shared::new();
        let asks = other.path().join("asks.json");
        let mut bytes = fs::read(&asks).expect("read asks.json");
        bytes.push(b'\n');
        fs::write(&asks, &bytes).expect("change the second bundle");
        other
    }

    /// A second signed bundle with other manifest bytes and so another lab
    /// CID. Its manifest `name` is `name` and its `role` stays the fixture's,
    /// so the walk accepts it and a launch that reports one admitted name for
    /// every launch is caught.
    fn named_bundle(name: &str) -> Shared {
        let bundle = Shared::new();
        let manifest = bundle.path().join("capsule.json");
        let text = fs::read_to_string(&manifest).expect("read capsule.json");
        let name_key = format!("\"name\": \"{SHARED_NAME}\"");
        assert!(
            text.contains(&name_key) && text.contains("\"role\": \"app\""),
            "the committed fixture manifest holds {name_key} and the app role"
        );
        let renamed = text.replace(&name_key, &format!("\"name\": \"{name}\""));
        fs::write(&manifest, renamed).expect("rename the second bundle's manifest");
        bundle
    }

    fn write_agent_host(root: &Path) {
        for (path, bytes) in AGENT_HOST_FILES {
            let target = root.join(path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).expect("make a bundle folder");
            }
            fs::write(&target, bytes).expect("write a bundle file");
        }
        declare_asks(
            root,
            &[(SHARED_RESOURCE, "read"), (SHARED_RESOURCE, "write")],
        );
    }

    /// Replaces the fixture's `asks.json` with exactly `asks`, in that order,
    /// before the bundle is signed. A test that needs another declared set
    /// gives it here; the committed file stays the fixture the other lanes
    /// read.
    fn declare_asks(root: &Path, asks: &[(&str, &str)]) {
        let listed = asks
            .iter()
            .map(|(resource, kind)| json!({ "kind": kind, "resource": resource }))
            .collect::<Vec<_>>();
        let file = json!({ "schema": "elastos.agent-host.asks/v1", "asks": listed });
        fs::write(
            root.join("asks.json"),
            serde_json::to_vec_pretty(&file).expect("encode the fixture asks"),
        )
        .expect("write the fixture asks");
    }

    /// A fresh Ed25519 test key. Nothing writes it or keeps a seed.
    fn fresh_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn did_of(key: &SigningKey) -> String {
        elastos_identity::encode_signing_key_did(key)
    }

    fn keys(value: &Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("the stand-in returns an object")
            .keys()
            .cloned()
            .collect()
    }

    fn assert_keys(value: &Value, expected: &[&str], message: &str) {
        let expected: BTreeSet<String> = expected.iter().copied().map(str::to_owned).collect();
        assert_eq!(keys(value), expected, "{message}");
    }

    fn request_ids(body: &Value) -> BTreeSet<String> {
        body["capabilities"]
            .as_array()
            .expect("the stand-in returns a capability list")
            .iter()
            .map(|entry| {
                entry["request_id"]
                    .as_str()
                    .expect("the stand-in entry names request_id")
                    .to_owned()
            })
            .collect()
    }

    fn request_order(body: &Value) -> Vec<String> {
        body["capabilities"]
            .as_array()
            .expect("the stand-in returns a capability list")
            .iter()
            .map(|entry| entry["request_id"].as_str().unwrap().to_owned())
            .collect()
    }

    fn shell_pair(standin: &StandIn) -> (Value, Value) {
        let plain = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell plain view");
        let query = standin
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("the stand-in shell query view");
        (plain, query)
    }

    const SHELL_ENTRY: &[&str] = &[
        "action",
        "duration",
        "granted_at",
        "request_id",
        "resource",
        "session_id",
    ];

    const CLIENT_ENTRY: &[&str] = &["action", "duration", "granted_at", "request_id", "resource"];

    fn assert_entry_keys(body: &Value, expected: &[&str], message: &str) {
        for entry in body["capabilities"].as_array().unwrap() {
            assert_keys(entry, expected, message);
        }
    }

    #[test]
    fn standin_shell_sees_every_live_grant() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-b",
            "s-b",
            "res-b",
            "read",
            "once",
            30,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-z",
            "s-a",
            "res-z",
            "read",
            "session",
            20,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-a",
            "s-a",
            "res-a",
            "write",
            "once",
            10,
            Life::Live,
            true,
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-a".to_owned(), "req-b".to_owned(), "req-z".to_owned()]),
            "the stand-in lists every live grant"
        );
        assert_eq!(
            request_order(&plain),
            ["req-a", "req-z", "req-b"],
            "the stand-in sorts live grants by session then request"
        );
        assert_keys(
            &plain,
            &["capabilities", "scope"],
            "the stand-in shell view carries the scope marker",
        );
        assert_eq!(
            plain["scope"], "all_sessions_live",
            "the stand-in marks the shell view all_sessions_live"
        );
        assert_entry_keys(
            &plain,
            SHELL_ENTRY,
            "the stand-in shell entry carries the live-grant fields",
        );
        assert_eq!(
            plain,
            json!({
                "scope": "all_sessions_live",
                "capabilities": [
                    {
                        "request_id": "req-a",
                        "session_id": "s-a",
                        "resource": "res-a",
                        "action": "write",
                        "duration": "once",
                        "granted_at": 10,
                    },
                    {
                        "request_id": "req-z",
                        "session_id": "s-a",
                        "resource": "res-z",
                        "action": "read",
                        "duration": "session",
                        "granted_at": 20,
                    },
                    {
                        "request_id": "req-b",
                        "session_id": "s-b",
                        "resource": "res-b",
                        "action": "read",
                        "duration": "once",
                        "granted_at": 30,
                    },
                ],
            }),
            "the stand-in shell body is the seeded live grants"
        );
    }

    #[test]
    fn standin_empty_shell_view_has_the_scope_marker() {
        let standin = StandIn::new();
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one empty shell body for both route forms"
        );
        assert_keys(
            &plain,
            &["capabilities", "scope"],
            "the stand-in empty shell view has the scope marker",
        );
        assert_eq!(
            plain["scope"], "all_sessions_live",
            "the stand-in marks an empty shell view all_sessions_live"
        );
        assert_eq!(
            plain["capabilities"],
            json!([]),
            "the stand-in returns an empty capability list when nothing is live"
        );
    }

    #[test]
    fn standin_client_sees_only_its_own_grant() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-b",
            "s-own",
            "res-b",
            "read",
            "once",
            200,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-a",
            "s-own",
            "res-a",
            "read",
            "once",
            100,
            Life::Live,
            false,
        );
        standin.seed_grant(
            "req-s",
            "s-sib",
            "res-s",
            "read",
            "once",
            300,
            Life::Live,
            false,
        );
        let own = standin
            .get_capability_list(
                Caller::Client {
                    session_id: "s-own",
                },
                None,
            )
            .expect("the stand-in client view");
        assert_eq!(
            request_ids(&own),
            BTreeSet::from(["req-a".to_owned(), "req-b".to_owned()]),
            "the stand-in lists the caller's live grants and leaves the sibling out"
        );
        assert_eq!(
            request_order(&own),
            ["req-a", "req-b"],
            "the stand-in sorts the caller's grants by request"
        );
        assert_keys(
            &own,
            &["capabilities"],
            "the stand-in client view is the capability list",
        );
        assert_entry_keys(
            &own,
            CLIENT_ENTRY,
            "the stand-in client entry leaves session_id out",
        );
        assert_eq!(
            own,
            json!({
                "capabilities": [
                    {
                        "request_id": "req-a",
                        "resource": "res-a",
                        "action": "read",
                        "duration": "once",
                        "granted_at": 100,
                    },
                    {
                        "request_id": "req-b",
                        "resource": "res-b",
                        "action": "read",
                        "duration": "once",
                        "granted_at": 200,
                    },
                ],
            }),
            "the stand-in client body is that session's live grants"
        );
        let empty = standin
            .get_capability_list(
                Caller::Client {
                    session_id: "s-none",
                },
                None,
            )
            .expect("the stand-in empty client view");
        assert_eq!(
            request_ids(&empty),
            BTreeSet::new(),
            "the stand-in returns an empty capability list for a client with no grant"
        );
        assert_eq!(
            empty,
            json!({ "capabilities": [] }),
            "the stand-in empty client view has no scope marker"
        );
    }

    #[test]
    fn standin_client_global_view_is_refused() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-a",
            "s-a",
            "res-a",
            "read",
            "once",
            1,
            Life::Live,
            false,
        );
        let client = standin.get_capability_list(
            Caller::Client { session_id: "s-a" },
            Some("all_sessions_live"),
        );
        assert!(
            matches!(
                &client,
                Err((403, reason)) if reason == "This endpoint requires shell privileges"
            ),
            "the stand-in refuses a client global view: {client:?}"
        );
        assert!(
            standin
                .get_capability_list(Caller::Shell, Some("all_sessions_live"))
                .is_ok(),
            "the stand-in shell view is available to the shell"
        );
    }

    #[test]
    fn standin_unknown_scope_is_refused() {
        let standin = StandIn::new();
        let callers = [Caller::Shell, Caller::Client { session_id: "s-a" }];
        for caller in callers {
            for scope in ["session", ""] {
                let result = standin.get_capability_list(caller, Some(scope));
                assert!(
                    matches!(
                        &result,
                        Err((400, reason))
                            if reason.starts_with("unknown capability list scope:")
                                && reason.contains(scope)
                                && reason == &format!("unknown capability list scope: {scope}")
                    ),
                    "the stand-in refuses unknown scope {scope:?}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn standin_dead_grants_stay_out() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-exhausted",
            "s-a",
            "res-e",
            "read",
            "once",
            1,
            Life::Exhausted,
            false,
        );
        standin.seed_grant(
            "req-revoked",
            "s-b",
            "res-r",
            "read",
            "once",
            2,
            Life::Revoked,
            false,
        );
        standin.seed_grant(
            "req-expired",
            "s-c",
            "res-x",
            "read",
            "once",
            3,
            Life::Expired,
            false,
        );
        standin.seed_grant(
            "req-live",
            "s-d",
            "res-l",
            "read",
            "once",
            4,
            Life::Live,
            false,
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-live".to_owned()]),
            "the stand-in leaves exhausted, revoked and expired grants out"
        );
    }

    /// The manifest `name` of `AGENT_HOST_FILES`.
    const SHARED_NAME: &str = "agent-host";
    /// The manifest names of the two agent fixtures, each signed by its own
    /// fresh test publisher. The list entry keeps the admitted manifest's own
    /// name, so these entries must read their own name, not a shared one.
    const AGENT_A_NAME: &str = "agent-a";
    const AGENT_B_NAME: &str = "agent-b";

    fn shell_list(standin: &StandIn) -> Value {
        standin
            .get_capsules(Caller::Shell)
            .expect("the stand-in shell capsule list")
    }

    fn assert_launch_400(result: &Result<Value, (u16, String)>, token: &str, message: &str) {
        assert!(
            matches!(result, Err((400, reason)) if reason.contains(token)),
            "{message}: {result:?}"
        );
    }

    fn assert_delete(
        result: &Result<Value, (u16, String)>,
        status: u16,
        reason: &str,
        message: &str,
    ) {
        assert!(
            matches!(
                result,
                Err((got_status, got_reason)) if *got_status == status && got_reason == reason
            ),
            "{message}: {result:?}"
        );
    }

    fn admit_shared(shared: &Shared, standin: &mut StandIn, start: Start) {
        shared
            .admit(standin, start)
            .expect("the stand-in admits the signed bundle");
    }

    fn launch_starting(shared: &Shared, standin: &mut StandIn) -> String {
        let launched = shared.launch(standin).expect("the stand-in launches");
        launched["id"]
            .as_str()
            .expect("the stand-in names the launch")
            .to_owned()
    }

    fn launch_finished(shared: &Shared, standin: &mut StandIn) -> String {
        let id = launch_starting(shared, standin);
        standin
            .finish_start(&id)
            .expect("the stand-in finishes start");
        id
    }

    /// Admits one fresh signed fixture bundle and launches it through
    /// `POST /api/capsules` by its lab CID.
    fn admit_and_launch(standin: &mut StandIn) -> String {
        let shared = Shared::new();
        admit_shared(&shared, standin, Start::Ok);
        launch_finished(&shared, standin)
    }

    fn stop_body() -> Value {
        json!({ "reason": "stop one" })
    }

    fn seed_at(standin: &mut StandIn, request_id: &str, session_id: &str, life: Life) {
        standin.seed_grant(
            request_id, session_id, "res", "read", "once", 1, life, false,
        );
    }

    fn grant_record(standin: &StandIn, request_id: &str) -> (Life, bool) {
        let grant = standin
            .grants
            .iter()
            .find(|grant| grant.request_id == request_id)
            .expect("the stand-in stores the seeded grant");
        (grant.life, grant.session_ended)
    }

    fn assert_capsule(standin: &StandIn, id: &str, status: &str, cause: &str, message: &str) {
        let listed = shell_list(standin);
        let entry = listed["capsules"]
            .as_array()
            .expect("the stand-in returns capsules")
            .iter()
            .find(|entry| entry["id"] == id);
        let expected = json!({
            "id": id,
            "name": SHARED_NAME,
            "status": status,
            "session_id": id,
            "cause": cause,
        });
        assert_eq!(entry, Some(&expected), "{message}");
    }

    fn assert_next_launch(shared: &Shared, standin: &mut StandIn, id: &str) {
        let launched = shared
            .launch(standin)
            .expect("the stand-in launches after a refused stop");
        assert_eq!(
            launched["id"], id,
            "the stand-in does not spend an id on a refused stop"
        );
    }

    const SHARED_RESOURCE: &str = "localhost://Public/resident-instances/shared.txt";

    const REQUEST_ENTRY: &[&str] = &[
        "action",
        "decision_reason",
        "reason",
        "request_id",
        "resource",
        "session_id",
        "plan",
        "settled_by",
        "status",
    ];

    fn seed_shared_request(standin: &mut StandIn, request_id: &str, session_id: &str) {
        standin
            .seed_request(
                request_id,
                session_id,
                SHARED_RESOURCE,
                "read",
                "read shared",
            )
            .expect("the stand-in seeds one pending request");
    }

    fn shell_requests(standin: &StandIn, session: &str) -> Value {
        standin
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the stand-in shell request record")
    }

    fn request_entries(standin: &StandIn, session: &str) -> Vec<Value> {
        shell_requests(standin, session)["requests"]
            .as_array()
            .expect("the stand-in returns a request list")
            .clone()
    }

    fn pending_request(request_id: &str, session_id: &str) -> Value {
        json!({
            "request_id": request_id,
            "session_id": session_id,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "pending",
            "decision_reason": "",
            "settled_by": Value::Null,
            "plan": Value::Null,
        })
    }

    fn denied_request(request_id: &str, session_id: &str, cause: &str) -> Value {
        json!({
            "request_id": request_id,
            "session_id": session_id,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "denied",
            "decision_reason": cause,
            "settled_by": "runtime",
            "plan": Value::Null,
        })
    }

    fn expired_request(request_id: &str, session_id: &str) -> Value {
        json!({
            "request_id": request_id,
            "session_id": session_id,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "expired",
            "decision_reason": "Request timed out",
            "settled_by": "runtime",
            "plan": Value::Null,
        })
    }

    fn shell_denied_request(request_id: &str, session_id: &str, cause: &str) -> Value {
        json!({
            "request_id": request_id,
            "session_id": session_id,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "denied",
            "decision_reason": cause,
            "settled_by": "shell",
            "plan": Value::Null,
        })
    }

    fn granted_request(request_id: &str, session_id: &str, rationale: &str) -> Value {
        json!({
            "request_id": request_id,
            "session_id": session_id,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "granted",
            "decision_reason": rationale,
            "settled_by": "shell",
            "plan": Value::Null,
        })
    }

    fn assert_request_refused(result: &Result<(), (u16, String)>, reason: &str, message: &str) {
        assert!(
            matches!(
                result,
                Err((400, got)) if got == reason
            ),
            "{message}: {result:?}"
        );
    }

    #[test]
    fn standin_one_admit_per_cid() {
        let shared = Shared::new();
        let other = other_bundle();
        let mut standin = StandIn::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let second = shared.admit(&mut standin, Start::Error("replaced".to_owned()));
        let expected = format!("bundle already admitted: {}", shared.cid());
        assert!(
            matches!(&second, Err((403, reason)) if reason == &expected),
            "the stand-in keeps the first admit of one CID: {second:?}"
        );
        let same_bytes = other.admit(&mut standin, Start::Ok);
        assert!(
            same_bytes.is_ok(),
            "the stand-in admits a second bundle with another CID: {same_bytes:?}"
        );
        let launched = shared
            .launch(&mut standin)
            .expect("the stand-in launches the first admit");
        let id = launched["id"]
            .as_str()
            .expect("the stand-in names the launch");
        standin
            .finish_start(id)
            .expect("the stand-in follows the first Start");
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "running",
            "the stand-in finish_start follows the first Start::Ok"
        );
    }

    #[test]
    fn standin_unadmitted_cid_is_refused() {
        let shared = Shared::new();
        let mut standin = StandIn::new();
        let result = shared.launch(&mut standin);
        let expected = format!(
            "no bundle is admitted under {} in world {}",
            shared.cid(),
            RESIDENT_WORLD
        );
        assert!(
            matches!(&result, Err((404, reason)) if reason == &expected),
            "the stand-in refuses a CID no bundle was admitted under: {result:?}"
        );
        admit_shared(&shared, &mut standin, Start::Ok);
        let launched = shared
            .launch(&mut standin)
            .expect("the stand-in launches once the CID is admitted");
        assert_eq!(
            launched["id"], "component-1",
            "the stand-in does not spend an id on an unadmitted CID"
        );
    }

    #[test]
    fn standin_launch_body_is_cid_only() {
        let shared = Shared::new();
        let mut standin = StandIn::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let unknown = UnknownCid::new();
        let missing = standin.post_capsules(Caller::Shell, &json!({}));
        assert_launch_400(
            &missing,
            "needs cid",
            "the stand-in refuses a launch body with no cid",
        );
        let numeric = standin.post_capsules(Caller::Shell, &json!({ "cid": 1 }));
        assert_launch_400(
            &numeric,
            "cid must be a string",
            "the stand-in refuses a launch cid that is not a string",
        );
        let extra = standin.post_capsules(
            Caller::Shell,
            &json!({ "cid": shared.cid(), "component": SHARED_NAME }),
        );
        assert_launch_400(
            &extra,
            "rejects component",
            "the stand-in refuses a launch body with an extra key",
        );
        let not_object = standin.post_capsules(Caller::Shell, &Value::Null);
        assert_launch_400(
            &not_object,
            "needs cid",
            "the stand-in refuses a launch body that is not an object",
        );
        let principal = standin.post_capsules(
            Caller::Shell,
            &json!({ "cid": shared.cid(), "principal_id": "person" }),
        );
        assert_launch_400(
            &principal,
            "rejects principal_id",
            "the stand-in refuses principal_id on the launch body",
        );
        let grant = standin.post_capsules(
            Caller::Shell,
            &json!({ "cid": shared.cid(), "launch_grant": "token" }),
        );
        assert_launch_400(
            &grant,
            "rejects launch_grant",
            "the stand-in refuses launch_grant on the launch body",
        );
        let not_a_cid = standin.post_capsules(Caller::Shell, &json!({ "cid": "bafybeix" }));
        assert_launch_400(
            &not_a_cid,
            "is not a lab CID",
            "the stand-in refuses a cid that is not a printed lab CID",
        );
        let unknown_cid = standin.post_capsules(Caller::Shell, &unknown.body());
        assert!(
            matches!(&unknown_cid, Err((404, reason)) if reason.contains(&unknown.0)),
            "the stand-in refuses a well-formed CID no bundle was admitted under: {unknown_cid:?}"
        );
        let launched = shared
            .launch(&mut standin)
            .expect("the stand-in launches after the refused bodies");
        assert_eq!(
            launched["id"], "component-1",
            "the stand-in does not spend an id on a refused launch body"
        );
    }

    /// One printed lab CID that parses and that no fixture admission stored:
    /// the encoder's own name for an empty directory, with its final digit
    /// changed.
    struct UnknownCid(String);

    impl UnknownCid {
        fn new() -> Self {
            let mut cid = capsule_identity::encode_entries(&[])
                .expect("the encoder names an empty directory")
                .to_string();
            let last = cid.pop().expect("a printed lab CID is not empty");
            let flipped = if last == 'a' { 'b' } else { 'a' };
            Self(format!("{cid}{flipped}"))
        }

        fn body(&self) -> Value {
            json!({ "cid": self.0 })
        }
    }

    #[test]
    fn standin_launch_by_path_is_refused() {
        let shared = Shared::new();
        let mut standin = StandIn::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let bodies = [
            json!({ "path": shared.path().display().to_string() }),
            json!({ "cid": shared.cid(), "path": shared.path().display().to_string() }),
        ];
        for body in bodies {
            let refused = standin.post_capsules(Caller::Shell, &body);
            assert_launch_400(
                &refused,
                "rejects path",
                "the stand-in refuses a launch body that names a path",
            );
        }
        assert_eq!(
            shell_list(&standin),
            json!({ "capsules": [] }),
            "the stand-in launches nothing for a path body"
        );
        let launched = shared
            .launch(&mut standin)
            .expect("the stand-in launches the admitted CID only");
        assert_eq!(
            launched["id"], "component-1",
            "the stand-in does not spend an id on a path body"
        );
    }

    #[test]
    fn standin_unsigned_bundle_is_refused() {
        let shared = Shared::new();
        let stranger = fresh_key();
        let mut standin = StandIn::new();
        let sig = sign_bundle(&stranger, shared.path()).expect("the stranger signs the bundle");
        let refused = standin.admit_resident(shared.path(), &sig, &shared.accepted, Start::Ok);
        let expected = Refusal::SignerNotAccepted {
            did: did_of(&stranger),
        }
        .to_string();
        assert!(
            matches!(&refused, Err((403, reason)) if reason == &expected),
            "the stand-in refuses a signer outside the accepted list: {refused:?}"
        );
        assert!(
            standin.admitted.is_empty(),
            "a refused admission stores no row"
        );
        let launch = shared.launch(&mut standin);
        let reason = format!(
            "no bundle is admitted under {} in world {RESIDENT_WORLD}",
            shared.cid()
        );
        assert!(
            matches!(&launch, Err((404, got)) if got == &reason),
            "the stand-in refuses to launch the CID after the refused admission: {launch:?}"
        );
        let none_accepted =
            standin.admit_resident(shared.path(), &shared.signature(), &[], Start::Ok);
        let expected = Refusal::SignerNotAccepted {
            did: did_of(&shared.key),
        }
        .to_string();
        assert!(
            matches!(&none_accepted, Err((403, reason)) if reason == &expected),
            "an empty accepted list refuses every signer: {none_accepted:?}"
        );
        assert!(standin.admitted.is_empty(), "still no row is stored");
    }

    #[test]
    fn standin_mismatched_bundle_is_refused() {
        let signed = Shared::new();
        let other = other_bundle();
        let other_cid = checked_bundle(other.path())
            .expect("the walk names the second bundle")
            .cid();
        let signed_cid = checked_bundle(signed.path())
            .expect("the walk names the signed bundle")
            .cid();
        assert_ne!(signed_cid, other_cid, "two bundles, two lab CIDs");
        let mut standin = StandIn::new();
        let refused = standin.admit_resident(
            other.path(),
            &signed.signature(),
            &signed.accepted,
            Start::Ok,
        );
        let expected = Refusal::NameMismatch {
            actual: other_cid,
            claimed: signed_cid.to_string(),
        }
        .to_string();
        assert!(
            matches!(&refused, Err((403, reason)) if reason == &expected),
            "the stand-in refuses a signature over another bundle's bytes: {refused:?}"
        );
        assert!(
            standin.admitted.is_empty(),
            "a refused admission stores no row"
        );
        let launch = standin.post_capsules(Caller::Shell, &json!({ "cid": other_cid.to_string() }));
        assert!(
            matches!(&launch, Err((404, reason)) if reason.contains(&other_cid.to_string())),
            "the stand-in refuses to launch the other bundle's CID: {launch:?}"
        );
    }

    #[test]
    fn standin_flipped_byte_after_signing_is_refused() {
        let shared = Shared::new();
        let sig = shared.signature();
        let before = checked_bundle(shared.path())
            .expect("the walk names the bundle before the change")
            .cid();
        let asks = shared.path().join("asks.json");
        let mut bytes = fs::read(&asks).expect("read asks.json");
        bytes[0] ^= 0x01;
        fs::write(&asks, &bytes).expect("flip one byte of asks.json");
        let mut standin = StandIn::new();
        let refused = standin.admit_resident(shared.path(), &sig, &shared.accepted, Start::Ok);
        let after = checked_bundle(shared.path())
            .expect("the walk names the bundle after the change")
            .cid();
        let expected = Refusal::NameMismatch {
            actual: after,
            claimed: before.to_string(),
        }
        .to_string();
        assert!(
            matches!(&refused, Err((403, reason)) if reason == &expected),
            "the stand-in refuses a bundle whose bytes changed after signing: {refused:?}"
        );
        assert!(
            standin.admitted.is_empty(),
            "a refused admission stores no row"
        );
        let launch = standin.post_capsules(Caller::Shell, &json!({ "cid": before.to_string() }));
        assert!(
            matches!(&launch, Err((404, reason)) if reason.contains(&before.to_string())),
            "the stand-in refuses to launch the signed CID over changed bytes: {launch:?}"
        );
    }

    #[test]
    fn standin_corrupted_signature_is_refused() {
        let shared = Shared::new();
        let mut standin = StandIn::new();
        let good = shared.signature();
        let cid = shared.cid();
        let mut flipped = good.clone();
        flipped.signature[7] ^= 0x01;
        let mut zeroed = good.clone();
        zeroed.signature = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        for (case, sig) in [("one flipped byte", flipped), ("all zero", zeroed)] {
            let before_list = shell_list(&standin);
            let refused = shared.admit_with(&mut standin, &sig, Start::Ok);
            let expected = Refusal::SignatureDoesNotVerify {
                did: did_of(&shared.key),
                name: cid.clone(),
            }
            .to_string();
            assert!(
                matches!(&refused, Err((403, reason)) if reason == &expected),
                "the stand-in refuses a corrupted signature ({case}) by the accepted signer over the signed name: {refused:?}"
            );
            assert!(
                standin.admitted.is_empty(),
                "a refused admission by the accepted signer stores no row ({case})"
            );
            assert_eq!(
                shell_list(&standin),
                before_list,
                "a refused admission creates no instance ({case})"
            );
            assert!(
                standin.grants.is_empty(),
                "a refused admission mints no grant ({case})"
            );
            let launch = shared.launch(&mut standin);
            let reason = format!("no bundle is admitted under {cid} in world {RESIDENT_WORLD}");
            assert!(
                matches!(&launch, Err((404, got)) if got == &reason),
                "the stand-in refuses to launch after the refused admission ({case}): {launch:?}"
            );
        }
    }

    #[test]
    fn standin_bundle_changed_after_admit_is_refused_at_launch() {
        let shared = Shared::new();
        let mut standin = StandIn::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let admitted_cid = shared.cid();
        let asks = shared.path().join("asks.json");
        let mut bytes = fs::read(&asks).expect("read asks.json");
        bytes[0] ^= 0x01;
        fs::write(&asks, &bytes).expect("flip one byte of asks.json after admission");
        let launch = standin.post_capsules(Caller::Shell, &json!({ "cid": admitted_cid }));
        let now = checked_bundle(shared.path())
            .expect("the walk names the changed bundle")
            .cid();
        let expected = Refusal::NameMismatch {
            actual: now,
            claimed: admitted_cid.clone(),
        }
        .to_string();
        assert!(
            matches!(&launch, Err((403, reason)) if reason == &expected),
            "the stand-in re-checks the bundle at launch and refuses changed bytes: {launch:?}"
        );
        assert!(
            standin.instances.is_empty(),
            "a refused launch creates no instance"
        );
        assert!(standin.grants.is_empty(), "a refused launch mints no grant");
        assert_eq!(
            shell_list(&standin),
            json!({ "capsules": [] }),
            "the capsule list stays empty after the refused launch"
        );
    }

    #[test]
    fn standin_valid_signature_grants_nothing() {
        let shared = Shared::new();
        let mut standin = StandIn::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        assert!(standin.grants.is_empty(), "admission mints no grant");
        let launched = shared
            .launch(&mut standin)
            .expect("the stand-in launches the signed bundle");
        assert!(
            standin.grants.is_empty(),
            "a valid signature alone mints no grant"
        );
        let session = launched["session_id"]
            .as_str()
            .expect("the stand-in names the Bus session");
        let own = standin
            .get_capability_list(
                Caller::Client {
                    session_id: session,
                },
                None,
            )
            .expect("the stand-in client view");
        assert_eq!(
            own,
            json!({ "capabilities": [] }),
            "the launched session holds no capability"
        );
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "starting",
            "the instance still exists while it holds no grant"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            request_ids(&query),
            BTreeSet::new(),
            "the shell grant view is empty after a signed launch"
        );
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
    }

    #[test]
    fn standin_launch_returns_before_start() {
        let shared = Shared::new();
        let mut standin = StandIn::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        assert_eq!(
            shell_list(&standin),
            json!({ "capsules": [] }),
            "the stand-in lists no instance before launch"
        );
        let launched = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launches before start returns");
        assert_eq!(
            launched,
            json!({
                "id": "component-1",
                "name": SHARED_NAME,
                "status": "starting",
                "session_id": "component-1",
            }),
            "the stand-in returns starting and the Bus session before start finishes"
        );
        assert_keys(
            &launched,
            &["id", "name", "session_id", "status"],
            "the stand-in launch value carries id, name, status and session_id",
        );
        let listed = shell_list(&standin);
        assert_eq!(
            listed["capsules"][0],
            json!({
                "id": "component-1",
                "name": SHARED_NAME,
                "status": "starting",
                "session_id": "component-1",
                "cause": "",
            }),
            "the stand-in lists the instance as starting with an empty cause"
        );
        assert_keys(
            &listed["capsules"][0],
            &["cause", "id", "name", "session_id", "status"],
            "the stand-in list entry carries id, name, status, session_id and cause",
        );
    }

    #[test]
    fn standin_two_launches_are_two_instances() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let first = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in first launch");
        let second = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in second launch");
        assert_eq!(
            first["id"], "component-1",
            "the stand-in numbers the first launch component-1"
        );
        assert_eq!(
            second["id"], "component-2",
            "the stand-in numbers the second launch component-2"
        );
        assert_eq!(
            first["session_id"], first["id"],
            "the stand-in uses the first launch id as its Bus session"
        );
        assert_eq!(
            second["session_id"], second["id"],
            "the stand-in uses the second launch id as its Bus session"
        );
        let listed = shell_list(&standin);
        assert_keys(
            &listed,
            &["capsules"],
            "the stand-in capsule list has one key",
        );
        assert_eq!(
            listed,
            json!({
                "capsules": [
                    {
                        "id": "component-1",
                        "name": SHARED_NAME,
                        "status": "starting",
                        "session_id": "component-1",
                        "cause": "",
                    },
                    {
                        "id": "component-2",
                        "name": SHARED_NAME,
                        "status": "starting",
                        "session_id": "component-2",
                        "cause": "",
                    },
                ]
            }),
            "the stand-in lists both instances sorted by id"
        );
    }

    #[test]
    fn standin_two_agent_components_stay_resident() {
        let agent_a = named_bundle(AGENT_A_NAME);
        let agent_b = named_bundle(AGENT_B_NAME);
        assert_ne!(
            agent_a.cid(),
            agent_b.cid(),
            "the two agent bundles have two lab CIDs"
        );
        let mut standin = StandIn::new();
        admit_shared(&agent_a, &mut standin, Start::Ok);
        admit_shared(&agent_b, &mut standin, Start::Ok);
        let first = agent_a
            .launch(&mut standin)
            .expect("the stand-in launches agent-a");
        let second = agent_b
            .launch(&mut standin)
            .expect("the stand-in launches agent-b");
        assert_eq!(
            first["id"], "component-1",
            "the stand-in numbers the agent-a launch component-1"
        );
        assert_eq!(
            second["id"], "component-2",
            "the stand-in numbers the agent-b launch component-2"
        );
        assert_eq!(
            first["session_id"], first["id"],
            "the stand-in uses the agent-a launch id as its Bus session"
        );
        assert_eq!(
            second["session_id"], second["id"],
            "the stand-in uses the agent-b launch id as its Bus session"
        );
        assert_eq!(
            first["name"], AGENT_A_NAME,
            "the stand-in names the agent-a launch from its admitted path"
        );
        assert_eq!(
            second["name"], AGENT_B_NAME,
            "the stand-in names the agent-b launch from its admitted path"
        );
        assert_eq!(
            shell_list(&standin),
            json!({
                "capsules": [
                    {
                        "id": "component-1",
                        "name": AGENT_A_NAME,
                        "status": "starting",
                        "session_id": "component-1",
                        "cause": "",
                    },
                    {
                        "id": "component-2",
                        "name": AGENT_B_NAME,
                        "status": "starting",
                        "session_id": "component-2",
                        "cause": "",
                    },
                ]
            }),
            "the stand-in lists both agent components starting after both launches"
        );
        standin
            .finish_start("component-1")
            .expect("the stand-in applies agent-a Start::Ok");
        standin
            .finish_start("component-2")
            .expect("the stand-in applies agent-b Start::Ok");
        let running = shell_list(&standin);
        assert_eq!(
            running,
            json!({
                "capsules": [
                    {
                        "id": "component-1",
                        "name": AGENT_A_NAME,
                        "status": "running",
                        "session_id": "component-1",
                        "cause": "",
                    },
                    {
                        "id": "component-2",
                        "name": AGENT_B_NAME,
                        "status": "running",
                        "session_id": "component-2",
                        "cause": "",
                    },
                ]
            }),
            "the stand-in lists both agent components running with distinct ids after start returned"
        );
        standin.set_instant(60);
        assert_eq!(
            shell_list(&standin),
            running,
            "the stand-in still lists both running agent components at test instant 60"
        );
        assert_eq!(
            standin.delete_capsule(Caller::Shell, "component-1", &stop_body()),
            Ok(Value::Null),
            "the stand-in stops component-1 and answers null"
        );
        let after_stop = shell_list(&standin);
        assert_eq!(
            after_stop["capsules"][0],
            json!({
                "id": "component-1",
                "name": AGENT_A_NAME,
                "status": "stopped",
                "session_id": "component-1",
                "cause": "stopped: stop one",
            }),
            "the stand-in lists component-1 stopped with the stop cause"
        );
        assert_eq!(
            after_stop["capsules"][1],
            json!({
                "id": "component-2",
                "name": AGENT_B_NAME,
                "status": "running",
                "session_id": "component-2",
                "cause": "",
            }),
            "the stand-in keeps component-2 running as agent-b after the sibling stop"
        );
        assert_eq!(
            after_stop["capsules"]
                .as_array()
                .expect("the stand-in returns capsules")
                .len(),
            2,
            "the stand-in lists exactly the two agent components after one stop"
        );
    }

    #[test]
    fn standin_start_ok_is_running() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let launched = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launch");
        let id = launched["id"]
            .as_str()
            .expect("the stand-in names the launch")
            .to_owned();
        standin
            .finish_start(&id)
            .expect("the stand-in applies Start::Ok");
        assert_eq!(
            shell_list(&standin)["capsules"][0],
            json!({
                "id": "component-1",
                "name": SHARED_NAME,
                "status": "running",
                "session_id": "component-1",
                "cause": "",
            }),
            "the stand-in stores running with an empty cause when start returns ok"
        );
        standin.set_instant(60);
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "running",
            "the stand-in keeps a running instance at instant 60"
        );
    }

    #[test]
    fn standin_bad_start_is_failed() {
        for (start, cause) in [
            (Start::Error("start refused".to_owned()), "start refused"),
            (Start::Trap("trap: fuel".to_owned()), "trap: fuel"),
        ] {
            let mut standin = StandIn::new();
            let shared = Shared::new();
            admit_shared(&shared, &mut standin, start);
            let launched = standin
                .post_capsules(Caller::Shell, &shared.body())
                .expect("the stand-in launch");
            let id = launched["id"]
                .as_str()
                .expect("the stand-in names the launch")
                .to_owned();
            standin
                .finish_start(&id)
                .expect("the stand-in applies the bad start");
            assert_eq!(
                shell_list(&standin)["capsules"][0],
                json!({
                    "id": "component-1",
                    "name": SHARED_NAME,
                    "status": "failed",
                    "session_id": "component-1",
                    "cause": cause,
                }),
                "the stand-in lists a failed start with its cause"
            );
        }
    }

    #[test]
    fn standin_failed_stays_for_sixty_seconds() {
        let shared = Shared::new();
        let mut standin = StandIn::new();
        standin.set_instant(0);
        admit_shared(
            &shared,
            &mut standin,
            Start::Error("start refused".to_owned()),
        );
        let launched = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launch");
        let id = launched["id"]
            .as_str()
            .expect("the stand-in names the launch")
            .to_owned();
        standin
            .finish_start(&id)
            .expect("the stand-in applies the failed start");
        let at_zero = shell_list(&standin);
        assert_eq!(
            at_zero["capsules"][0]["status"], "failed",
            "the stand-in lists a failed instance at instant 0"
        );
        assert_eq!(
            at_zero["capsules"][0]["cause"], "start refused",
            "the stand-in keeps the failed cause at instant 0"
        );
        standin.set_instant(59);
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "failed",
            "the stand-in lists a failed instance at instant 59"
        );
        standin.set_instant(60);
        assert_eq!(
            shell_list(&standin),
            json!({ "capsules": [] }),
            "the stand-in omits a failed instance at instant 60"
        );
    }

    #[test]
    fn standin_start_returns_once() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let launched = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launch");
        let id = launched["id"]
            .as_str()
            .expect("the stand-in names the launch")
            .to_owned();
        standin
            .finish_start(&id)
            .expect("the stand-in applies the first start");
        let second = standin.finish_start(&id);
        assert!(
            matches!(
                &second,
                Err((400, reason)) if reason == "start already returned"
            ),
            "the stand-in accepts start once: {second:?}"
        );
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "running",
            "the stand-in keeps running after a second start"
        );
        let unknown = standin.finish_start("component-9");
        assert!(
            matches!(
                &unknown,
                Err((400, reason)) if reason == "unknown instance: component-9"
            ),
            "the stand-in refuses an unknown instance: {unknown:?}"
        );
        assert_eq!(
            shell_list(&standin)["capsules"][0]["status"],
            "running",
            "the stand-in leaves the running instance in place"
        );

        let mut failed = StandIn::new();
        admit_shared(
            &shared,
            &mut failed,
            Start::Error("start refused".to_owned()),
        );
        let failed_id = launch_finished(&shared, &mut failed);
        let second_failed = failed.finish_start(&failed_id);
        assert!(
            matches!(
                &second_failed,
                Err((400, reason)) if reason == "start already returned"
            ),
            "the stand-in accepts start once on a failed instance: {second_failed:?}"
        );
        assert_capsule(
            &failed,
            &failed_id,
            "failed",
            "start refused",
            "the stand-in keeps the failed cause after a second start",
        );
    }

    #[test]
    fn standin_client_cannot_launch_or_list() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let client = Caller::Client {
            session_id: "s-client",
        };
        let launch = standin.post_capsules(client, &shared.body());
        let list = standin.get_capsules(client);
        assert!(
            matches!(
                &launch,
                Err((403, reason)) if reason == "This endpoint requires shell privileges"
            ) && matches!(
                &list,
                Err((403, reason)) if reason == "This endpoint requires shell privileges"
            ),
            "the stand-in refuses a client launch and list: {launch:?} {list:?}"
        );
        let listed = shell_list(&standin);
        assert_eq!(
            listed,
            json!({ "capsules": [] }),
            "the stand-in shell list stays available"
        );
        let launched = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in shell launch");
        assert_eq!(
            launched["id"], "component-1",
            "the stand-in does not spend an id on a refused client launch"
        );
    }

    #[test]
    fn standin_stop_sets_stopped() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = launch_finished(&shared, &mut standin);
        assert_eq!(
            id, "component-1",
            "the stand-in names the first launch component-1"
        );
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops one running instance");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it stops one instance"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in stores stopped with the stop reason",
        );
        let later = standin.finish_start("component-1");
        assert!(
            matches!(
                &later,
                Err((400, reason)) if reason == "instance is not live: stopped"
            ),
            "the stand-in refuses finish_start after a stop: {later:?}"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in keeps stopped after finish_start",
        );
    }

    #[test]
    fn standin_stop_body_is_reason_only() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        let cases = [
            (Value::Null, "stop body needs reason"),
            (json!({}), "stop body misses reason"),
            (json!({ "reason": 1 }), "stop reason must be a string"),
            (json!({ "reason": "" }), "stop needs a reason"),
            (
                json!({ "reason": "stop one", "cid": "bafy" }),
                "stop body rejects cid",
            ),
        ];
        for (body, reason) in cases {
            let result = standin.delete_capsule(Caller::Shell, "component-1", &body);
            let message = format!("the stand-in refuses this stop body: {reason}");
            assert_delete(&result, 400, reason, &message);
            assert_capsule(
                &standin,
                "component-1",
                "running",
                "",
                "the stand-in leaves the running instance unchanged",
            );
            assert_eq!(
                grant_record(&standin, "req-1"),
                (Life::Live, false),
                "the stand-in leaves the live grant unchanged"
            );
        }
        assert_next_launch(&shared, &mut standin, "component-2");
    }

    #[test]
    fn standin_unknown_stop_is_refused() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        let unknown = standin.delete_capsule(Caller::Shell, "component-9", &stop_body());
        assert_delete(
            &unknown,
            400,
            "unknown instance: component-9",
            "the stand-in refuses an unknown stop",
        );
        let empty = standin.delete_capsule(Caller::Shell, "", &stop_body());
        assert_delete(
            &empty,
            400,
            "unknown instance: ",
            "the stand-in refuses a stop of an empty id",
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in leaves the known instance unchanged",
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Live, false),
            "the stand-in leaves the seeded grant live"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in still lists the seeded live grant"
        );
        assert_next_launch(&shared, &mut standin, "component-2");
    }

    #[test]
    fn standin_stop_refuses_a_failed_instance() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(
            &shared,
            &mut standin,
            Start::Error("start refused".to_owned()),
        );
        launch_finished(&shared, &mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        let result = standin.delete_capsule(Caller::Shell, "component-1", &stop_body());
        assert_delete(
            &result,
            400,
            "instance is not live: failed",
            "the stand-in refuses to stop a failed instance",
        );
        assert_capsule(
            &standin,
            "component-1",
            "failed",
            "start refused",
            "the stand-in keeps the failed cause",
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Live, false),
            "the stand-in leaves a live grant on a refused stop"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in still lists the live grant"
        );
        assert_next_launch(&shared, &mut standin, "component-2");
    }

    #[test]
    fn standin_stop_revokes_that_sessions_grants() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        launch_finished(&shared, &mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        seed_at(&mut standin, "req-1b", "component-1", Life::Live);
        seed_at(&mut standin, "req-e", "component-1", Life::Exhausted);
        seed_at(&mut standin, "req-r", "component-1", Life::Revoked);
        seed_at(&mut standin, "req-x", "component-1", Life::Expired);
        seed_at(&mut standin, "req-2", "component-2", Life::Live);
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it revokes that session"
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Revoked, false),
            "the stand-in revokes that session's live grant"
        );
        assert_eq!(
            grant_record(&standin, "req-1b"),
            (Life::Revoked, false),
            "the stand-in revokes every live grant of that session"
        );
        assert_eq!(
            grant_record(&standin, "req-e"),
            (Life::Exhausted, false),
            "the stand-in leaves an exhausted grant exhausted"
        );
        assert_eq!(
            grant_record(&standin, "req-r"),
            (Life::Revoked, false),
            "the stand-in leaves a revoked grant revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-x"),
            (Life::Expired, false),
            "the stand-in leaves an expired grant expired"
        );
        assert_eq!(
            grant_record(&standin, "req-2"),
            (Life::Live, false),
            "the stand-in leaves the sibling session's grant live"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in lists the sibling grant and leaves the revoked grants out"
        );
        let client = standin
            .get_capability_list(
                Caller::Client {
                    session_id: "component-1",
                },
                None,
            )
            .expect("the stand-in client view");
        assert_eq!(
            request_ids(&client),
            BTreeSet::new(),
            "the stand-in client view is empty after the stop"
        );
    }

    #[test]
    fn standin_stop_leaves_the_sibling() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        launch_finished(&shared, &mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        seed_at(&mut standin, "req-2", "component-2", Life::Live);
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it stops one sibling"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves the sibling running",
        );
        assert_eq!(
            grant_record(&standin, "req-2"),
            (Life::Live, false),
            "the stand-in leaves the sibling grant live"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in still lists the sibling grant"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in stops only the named instance",
        );
    }

    #[test]
    fn standin_stop_denies_that_sessions_pending() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        launch_finished(&shared, &mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        seed_at(&mut standin, "req-g", "component-1", Life::Live);
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        assert_eq!(
            shell_requests(&standin, "component-1"),
            json!({
                "requests": [denied_request(
                    "req-1",
                    "component-1",
                    "stopped: stop one",
                )],
            }),
            "the stand-in denies the stopped instance's pending request and names the stop"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::new(),
            "the stand-in shell live-grant list is empty after the stop"
        );
        assert_eq!(
            request_entries(&standin, "component-1")
                .iter()
                .filter(|entry| entry["request_id"] == "req-g")
                .count(),
            0,
            "the stand-in request record does not list the revoked grant"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's pending request"
        );
        standin.set_instant(60);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "stopped: stop one")],
            "the stand-in returns the denied request at instant 60"
        );

        let mut multi = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut multi, Start::Ok);
        launch_finished(&shared, &mut multi);
        seed_shared_request(&mut multi, "req-b", "component-1");
        seed_shared_request(&mut multi, "req-a", "component-1");
        multi
            .delete_capsule(
                Caller::Shell,
                "component-1",
                &json!({ "reason": "cancel the run" }),
            )
            .expect("the stand-in stops component-1 with another reason");
        assert_eq!(
            request_entries(&multi, "component-1"),
            vec![
                denied_request("req-a", "component-1", "stopped: cancel the run"),
                denied_request("req-b", "component-1", "stopped: cancel the run"),
            ],
            "the stand-in denies every pending request of that session, sorted, with that stop reason"
        );
    }

    #[test]
    fn standin_stop_leaves_the_siblings_request() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        launch_finished(&shared, &mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        let sibling = request_entries(&standin, "component-2");
        assert_eq!(
            sibling,
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's request pending"
        );
        assert!(
            sibling[0]["settled_by"].is_null(),
            "the stand-in leaves the sibling request with no settler"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves the sibling running",
        );
    }

    #[test]
    fn standin_worker_kill_settles_the_outliving_request() {
        let mut standin = StandIn::new();
        admit_and_launch(&mut standin);
        let owner = Caller::Client {
            session_id: "component-1",
        };
        let posted = standin.post_capability_request(owner, &request_client_body());
        assert_eq!(
            posted,
            Ok(json!({ "status": "pending", "request_id": "request-1" })),
            "the agent's own route stores the pending request"
        );
        let answered = standin
            .get_capability_request(owner, "request-1")
            .expect("the stand-in answers the live request before the kill");
        assert_eq!(
            answered,
            json!({ "status": "pending" }),
            "the stand-in leaves the request pending while the worker runs"
        );
        let killed = json!({ "reason": "worker killed" });
        standin
            .delete_capsule(Caller::Shell, "component-1", &killed)
            .expect("the stand-in stops component-1 as a worker kill");
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: worker killed",
            "the stand-in stores the worker kill as the instance cause",
        );
        assert_eq!(
            shell_requests(&standin, "component-1"),
            json!({
                "requests": [denied_request(
                    "request-1",
                    "component-1",
                    "stopped: worker killed",
                )],
            }),
            "the stand-in settles the request that outlived the killed worker, with the kill cause and the runtime as settler"
        );
        assert_eq!(
            standin.get_capability_request(owner, "request-1"),
            Ok(json!({ "status": "denied", "reason": "stopped: worker killed" })),
            "the stand-in answers the owner that its request settled after the kill"
        );
        assert_live_request_ids_empty(&standin, "the kill settlement leaves no live grant");
    }

    #[test]
    fn standin_settled_request_is_not_reposted() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        assert_eq!(
            launch_finished(&shared, &mut standin),
            "component-1",
            "the stand-in launches the admitted CID as component-1"
        );
        let owner = Caller::Client {
            session_id: "component-1",
        };
        standin
            .post_capability_request(owner, &request_client_body())
            .expect("the agent's own route stores request-1");
        let killed = json!({ "reason": "worker killed" });
        standin
            .delete_capsule(Caller::Shell, "component-1", &killed)
            .expect("the stand-in stops component-1 as a worker kill");
        let settled = denied_request("request-1", "component-1", "stopped: worker killed");
        assert_eq!(
            standin.seed_request("request-1", "component-1", SHARED_RESOURCE, "read", "again"),
            Err((400, "request already stored: request-1".to_owned())),
            "the store seam refuses a second store of the settled id"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![settled.clone()],
            "the stand-in keeps the settled record instead of a silent retry"
        );
        let relaunched = launch_finished(&shared, &mut standin);
        assert_eq!(
            relaunched, "component-2",
            "the stand-in launches the already-admitted CID again as a new instance"
        );
        assert_eq!(
            standin
                .get_capability_requests(Caller::Shell, Some(&relaunched))
                .expect("the stand-in lists the relaunched instance"),
            json!({ "requests": [] }),
            "the stand-in leaves a new instance of the same capsule with no request whose id the kill already settled"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![settled.clone()],
            "the relaunch leaves the killed instance's settled record unchanged"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves the relaunched instance running",
        );
    }

    #[test]
    fn standin_worker_kill_leaves_agent_two() {
        let mut standin = StandIn::new();
        let (first, second) = launch_two_running_ids(&mut standin);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("component-1", "component-2"),
            "the stand-in numbers agent 1 and agent 2"
        );
        let agent_one = Caller::Client {
            session_id: "component-1",
        };
        let agent_two = Caller::Client {
            session_id: "component-2",
        };
        for owner in [agent_one, agent_two] {
            standin
                .post_capability_request(owner, &request_client_body())
                .expect("each agent posts through its own route");
        }
        standin
            .delete_capsule(
                Caller::Shell,
                "component-1",
                &json!({ "reason": "worker killed" }),
            )
            .expect("the stand-in stops agent 1 as a worker kill");
        assert_eq!(
            standin.get_capability_request(agent_two, "request-2"),
            Ok(json!({ "status": "pending" })),
            "the stand-in leaves agent 2's request pending after agent 1 was killed"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-2", "component-2")],
            "the stand-in leaves agent 2's request record untouched"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves agent 2 running",
        );
        let agent_two_done = standin.post_capability_request(
            agent_two,
            &json!({ "resource": SHARED_RESOURCE, "action": "read", "reason": "still here" }),
        );
        assert_eq!(
            agent_two_done,
            Ok(json!({ "status": "pending", "request_id": "request-3" })),
            "the dead agent's settlement frees no id agent 2 could take"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![
                pending_request("request-2", "component-2"),
                json!({
                    "request_id": "request-3",
                    "session_id": "component-2",
                    "resource": SHARED_RESOURCE,
                    "action": "read",
                    "reason": "still here",
                    "status": "pending",
                    "decision_reason": "",
                    "settled_by": Value::Null,
                    "plan": Value::Null,
                }),
            ],
            "the stand-in stores agent 2's new request beside the untouched one"
        );
    }

    #[test]
    fn standin_failed_start_denies_that_sessions_pending() {
        let cases = [
            (Start::Error("start refused".to_owned()), "start refused"),
            (Start::Trap("start trapped".to_owned()), "start trapped"),
        ];
        for (start, cause) in cases {
            let mut standin = StandIn::new();
            let shared = Shared::new();
            admit_shared(&shared, &mut standin, start);
            launch_starting(&shared, &mut standin);
            seed_shared_request(&mut standin, "req-1", "component-1");
            standin
                .finish_start("component-1")
                .expect("the stand-in finishes a failed start");
            assert_eq!(
                request_entries(&standin, "component-1"),
                vec![denied_request("req-1", "component-1", cause)],
                "the stand-in denies the failed start's pending request with {cause}"
            );
            assert_capsule(
                &standin,
                "component-1",
                "failed",
                cause,
                "the stand-in stores the failed start cause",
            );
        }
    }

    #[test]
    fn standin_failed_start_leaves_the_siblings_request() {
        let failing_bundle = Shared::new();
        let sibling_bundle = other_bundle();
        let mut standin = StandIn::new();
        admit_shared(
            &failing_bundle,
            &mut standin,
            Start::Error("start refused".to_owned()),
        );
        admit_shared(&sibling_bundle, &mut standin, Start::Ok);
        let failing = failing_bundle
            .launch(&mut standin)
            .expect("the stand-in launches the failing bundle");
        let sibling = sibling_bundle
            .launch(&mut standin)
            .expect("the stand-in launches the sibling bundle");
        assert_eq!(
            failing["id"], "component-1",
            "the stand-in numbers the failing launch component-1"
        );
        assert_eq!(
            sibling["id"], "component-2",
            "the stand-in numbers the sibling launch component-2"
        );
        assert_eq!(
            failing["status"], "starting",
            "the stand-in answers starting for the failing launch"
        );
        assert_eq!(
            sibling["status"], "starting",
            "the stand-in answers starting for the sibling launch"
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the failing start");
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "start refused")],
            "the stand-in denies the failed instance's request with the failure cause"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's request pending after the failed start"
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in leaves the sibling starting",
        );
        standin
            .finish_start("component-2")
            .expect("the stand-in finishes the sibling start");
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's request pending after an Ok start"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves the sibling running after an Ok start",
        );
        assert!(
            standin.grants.is_empty(),
            "the stand-in mints no grant from a pending request"
        );
    }

    #[test]
    fn standin_refused_finish_start_preserves_requests() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");

        let second = standin.finish_start("component-1");
        assert!(
            matches!(&second, Err((400, reason)) if reason == "start already returned"),
            "the stand-in refuses a second start: {second:?}"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in leaves the request pending after a second start"
        );

        let unknown = standin.finish_start("component-9");
        assert!(
            matches!(&unknown, Err((400, reason)) if reason == "unknown instance: component-9"),
            "the stand-in refuses an unknown instance: {unknown:?}"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in leaves the request pending after an unknown instance"
        );

        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        seed_shared_request(&mut standin, "req-2", "component-1");
        let stopped = standin.finish_start("component-1");
        assert!(
            matches!(&stopped, Err((400, reason)) if reason == "instance is not live: stopped"),
            "the stand-in refuses a start after a stop: {stopped:?}"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                denied_request("req-1", "component-1", "stopped: stop one"),
                pending_request("req-2", "component-1"),
            ],
            "the stand-in keeps the stop settlement and leaves the later request pending"
        );

        let mut failed = StandIn::new();
        let shared = Shared::new();
        admit_shared(
            &shared,
            &mut failed,
            Start::Error("start refused".to_owned()),
        );
        launch_starting(&shared, &mut failed);
        seed_shared_request(&mut failed, "req-3", "component-1");
        failed
            .finish_start("component-1")
            .expect("the stand-in finishes the failing start");
        let second_failed = failed.finish_start("component-1");
        assert!(
            matches!(&second_failed, Err((400, reason)) if reason == "start already returned"),
            "the stand-in refuses a second failed start: {second_failed:?}"
        );
        assert_eq!(
            request_entries(&failed, "component-1"),
            vec![denied_request("req-3", "component-1", "start refused")],
            "the stand-in keeps the failure settlement after a refused second start"
        );
    }

    #[test]
    fn standin_requests_are_shell_only() {
        let mut standin = StandIn::new();
        seed_shared_request(&mut standin, "req-1", "component-1");
        for session in [Some("component-1"), None, Some("")] {
            let client = standin.get_capability_requests(
                Caller::Client {
                    session_id: "component-1",
                },
                session,
            );
            assert!(
                matches!(
                    &client,
                    Err((403, reason)) if reason == "This endpoint requires shell privileges"
                ),
                "the stand-in refuses a client request record for session {session:?}: {client:?}"
            );
        }
        for session in [None, Some("")] {
            let shell = standin.get_capability_requests(Caller::Shell, session);
            assert!(
                matches!(&shell, Err((400, reason)) if reason == "requests need a session"),
                "the stand-in refuses a shell request record without a session: {shell:?}"
            );
        }
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in returns a shell request record for a valid session"
        );
    }

    #[test]
    fn standin_shell_deny_fails_the_waiting_sibling() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let first = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launches the first read-shared instance");
        let second = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launches the second read-shared instance");
        assert_eq!(
            first["id"], "component-1",
            "the stand-in numbers the first launch component-1"
        );
        assert_eq!(
            second["id"], "component-2",
            "the stand-in numbers the second launch component-2"
        );
        assert_eq!(
            first["status"], "starting",
            "the stand-in answers starting for the first launch"
        );
        assert_eq!(
            second["status"], "starting",
            "the stand-in answers starting for the second launch"
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        seed_shared_request(&mut standin, "req-extra", "component-2");
        standin.seed_grant(
            "req-g",
            "component-1",
            SHARED_RESOURCE,
            "read",
            "session",
            0,
            Life::Live,
            false,
        );
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the granted instance start");

        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": "req-2", "reason": "sibling read denied" }),
            )
            .expect("the stand-in denies the waiting sibling request");
        assert_keys(&denied, &["success"], "the stand-in deny body has one key");
        assert_eq!(
            denied,
            json!({ "success": true }),
            "the stand-in answers success true for the shell deny"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![
                shell_denied_request("req-2", "component-2", "sibling read denied"),
                denied_request("req-extra", "component-2", "sibling read denied"),
            ],
            "the stand-in stores the shell deny and the runtime denial of req-extra with the failure cause"
        );
        assert_eq!(
            request_entries(&standin, "component-2")[1]["settled_by"],
            "runtime",
            "the stand-in settles the other sibling request as the runtime"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in leaves the first instance's request pending"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in keeps the first instance running with its grant",
        );
        assert_capsule(
            &standin,
            "component-2",
            "failed",
            "sibling read denied",
            "the stand-in ends the waiting instance failed with the deny reason",
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view");
        assert_eq!(
            request_ids(&live),
            BTreeSet::from(["req-g".to_owned()]),
            "the stand-in still shows exactly the first instance's live grant"
        );
        standin
            .post_capability_validate(
                Caller::Client {
                    session_id: "component-1",
                },
                &json!({ "request_id": "req-g" }),
            )
            .expect("the stand-in authorises the first instance with its grant");
        let sibling = standin.post_capability_validate(
            Caller::Client {
                session_id: "component-2",
            },
            &json!({ "request_id": "req-g" }),
        );
        assert!(
            matches!(&sibling, Err((403, reason)) if reason.contains("wrong capsule")),
            "the stand-in refuses the sibling presentation of the first instance's grant: {sibling:?}"
        );

        let refused_start = standin.finish_start("component-2");
        assert!(
            matches!(&refused_start, Err((400, reason)) if reason == "start already returned"),
            "the stand-in refuses finish_start for the denied instance: {refused_start:?}"
        );
        assert_capsule(
            &standin,
            "component-2",
            "failed",
            "sibling read denied",
            "the stand-in keeps the deny reason after the refused start",
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![
                shell_denied_request("req-2", "component-2", "sibling read denied"),
                denied_request("req-extra", "component-2", "sibling read denied"),
            ],
            "the stand-in keeps the shell deny and the runtime denial after the refused start"
        );

        let again = standin.post_capability_deny(
            Caller::Shell,
            &json!({ "request_id": "req-extra", "reason": "still denied" }),
        );
        assert_delete(
            &again,
            400,
            "request is not pending: req-extra",
            "the stand-in refuses a deny of the request the failed start settled",
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![
                shell_denied_request("req-2", "component-2", "sibling read denied"),
                denied_request("req-extra", "component-2", "sibling read denied"),
            ],
            "the stand-in keeps both settlements of the failed instance after the refused deny"
        );
        assert_capsule(
            &standin,
            "component-2",
            "failed",
            "sibling read denied",
            "the stand-in keeps a failed instance's phase and cause after a refused later deny",
        );
    }

    #[test]
    fn standin_deny_failure_revokes_the_failed_session_grants_through_routes() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let failed = launch_starting(&shared, &mut standin);
        let sibling = launch_starting(&shared, &mut standin);
        let first = standin
            .post_capability_request(
                Caller::Client {
                    session_id: &failed,
                },
                &request_client_body(),
            )
            .expect("the stand-in stores the first request of the session");
        let first_id = first["request_id"]
            .as_str()
            .expect("the stand-in names the first request")
            .to_owned();
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({ "request_id": first_id, "duration": "session" }),
            )
            .expect("the stand-in grants the first request");
        let second = standin
            .post_capability_request(
                Caller::Client {
                    session_id: &failed,
                },
                &request_client_body(),
            )
            .expect("the stand-in stores the second request of the session");
        let second_id = second["request_id"]
            .as_str()
            .expect("the stand-in names the second request")
            .to_owned();
        let sibling_request = standin
            .post_capability_request(
                Caller::Client {
                    session_id: &sibling,
                },
                &request_client_body(),
            )
            .expect("the stand-in stores the sibling request");
        let sibling_id = sibling_request["request_id"]
            .as_str()
            .expect("the stand-in names the sibling request")
            .to_owned();
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({ "request_id": sibling_id, "duration": "session" }),
            )
            .expect("the stand-in grants the sibling request");
        let before = standin
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("the stand-in shell live view before the deny");
        assert_eq!(
            request_ids(&before),
            BTreeSet::from([first_id.clone(), sibling_id.clone()]),
            "the stand-in shows the granted request and the sibling grant before the deny"
        );

        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": second_id, "reason": "second read denied" }),
            )
            .expect("the stand-in denies the second request of the starting session");
        assert_eq!(
            denied,
            json!({ "success": true }),
            "the stand-in answers success true for the deny that fails the session"
        );
        assert_capsule(
            &standin,
            &failed,
            "failed",
            "second read denied",
            "the stand-in stores the failed session from the deny",
        );
        let after = standin
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("the stand-in shell live view after the deny");
        assert_eq!(
            request_ids(&after),
            BTreeSet::from([sibling_id.clone()]),
            "the stand-in drops the failed session grant from the live view and keeps the sibling grant"
        );
        let own = standin
            .get_capability_list(
                Caller::Client {
                    session_id: &failed,
                },
                None,
            )
            .expect("the stand-in failed session client live view");
        assert_eq!(
            request_ids(&own),
            BTreeSet::new(),
            "the stand-in failed session client sees no live grant after the deny"
        );
    }

    #[test]
    fn standin_deny_failure_settles_the_sibling_request_and_its_grant_is_refused_through_routes() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let failed = launch_starting(&shared, &mut standin);
        let other = launch_starting(&shared, &mut standin);
        let denied = standin
            .post_capability_request(
                Caller::Client {
                    session_id: &failed,
                },
                &request_client_body(),
            )
            .expect("the stand-in stores the start-critical request of the failed session");
        assert_eq!(
            denied,
            json!({ "status": "pending", "request_id": "request-1" }),
            "the stand-in stores the start-critical request as pending"
        );
        let sibling = standin
            .post_capability_request(
                Caller::Client {
                    session_id: &failed,
                },
                &request_client_body(),
            )
            .expect("the stand-in stores the sibling request of the failed session");
        let sibling_id = sibling["request_id"]
            .as_str()
            .expect("the stand-in names the sibling request")
            .to_owned();
        assert_eq!(
            sibling_id, "request-2",
            "the stand-in names the second request of the failed session"
        );
        let bystander = standin
            .post_capability_request(
                Caller::Client { session_id: &other },
                &request_client_body(),
            )
            .expect("the stand-in stores the request of the bystander session");
        let bystander_id = bystander["request_id"]
            .as_str()
            .expect("the stand-in names the bystander request")
            .to_owned();
        assert_eq!(
            bystander_id, "request-3",
            "the stand-in names the request of the bystander session"
        );

        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": "request-1", "reason": "gate read denied" }),
            )
            .expect("the stand-in denies the start-critical request");
        assert_eq!(
            denied,
            json!({ "success": true }),
            "the stand-in answers success true for the deny that fails the starting session"
        );

        assert_eq!(
            request_entries(&standin, &failed),
            vec![
                shell_denied_request("request-1", "component-1", "gate read denied"),
                denied_request("request-2", "component-1", "gate read denied"),
            ],
            "the stand-in keeps the shell deny and settles the sibling request as the runtime"
        );
        assert_eq!(
            request_entries(&standin, &other),
            vec![pending_request("request-3", "component-2")],
            "the stand-in keeps the bystander session's request pending"
        );
        assert_capsule(
            &standin,
            &failed,
            "failed",
            "gate read denied",
            "the stand-in stores the failed session from the deny",
        );
        assert_capsule(
            &standin,
            &other,
            "starting",
            "",
            "the stand-in keeps the bystander session starting",
        );
        let failed_view = standin
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("the stand-in shell live view for the failed session");
        assert_eq!(
            request_ids(&failed_view),
            BTreeSet::new(),
            "the stand-in shell live view has no grant for the failed session"
        );

        let refused = standin.post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": sibling_id, "duration": "once" }),
        );
        assert_delete(
            &refused,
            400,
            "request is not pending: request-2",
            "the stand-in refuses a grant of the sibling request that the runtime settled",
        );
        let after = standin
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("the stand-in shell live view after the refused grant");
        assert_eq!(
            request_ids(&after),
            BTreeSet::new(),
            "the stand-in shell live view still has no grant for the failed session"
        );
        assert_eq!(
            request_entries(&standin, &failed),
            vec![
                shell_denied_request("request-1", "component-1", "gate read denied"),
                denied_request("request-2", "component-1", "gate read denied"),
            ],
            "the refused grant leaves both settlements of the failed session unchanged"
        );

        let granted = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({ "request_id": bystander_id, "duration": "once" }),
            )
            .expect("the stand-in grants the bystander request");
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in answers success true for the bystander grant"
        );
        let control = standin
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("the stand-in shell live view after the bystander grant");
        assert_eq!(
            request_ids(&control),
            BTreeSet::from([bystander_id]),
            "the stand-in live view carries only the bystander grant, so the refusal is specific"
        );
        assert_eq!(
            request_entries(&standin, &other),
            vec![granted_request(
                "request-3",
                "component-2",
                "Shell auto-grant"
            )],
            "the stand-in stores the bystander grant through the grant route"
        );
    }

    #[test]
    fn standin_shell_deny_refuses_a_bad_request() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = launch_finished(&shared, &mut standin);
        seed_shared_request(&mut standin, "req-1", &id);

        let client = standin.post_capability_deny(
            Caller::Client {
                session_id: "component-1",
            },
            &json!({ "request_id": "req-1" }),
        );
        assert!(
            matches!(&client, Err((403, reason)) if reason == "This endpoint requires shell privileges"),
            "the stand-in refuses a client deny before reading the body: {client:?}"
        );

        for body in [json!({}), json!("req-1")] {
            let refused = standin.post_capability_deny(Caller::Shell, &body);
            assert!(
                matches!(&refused, Err((400, reason)) if reason == "deny body needs request_id"),
                "the stand-in refuses a deny body without request_id: {refused:?}"
            );
        }
        for (body, reason) in [
            (
                json!({ "request_id": 4 }),
                "deny request_id must be a string",
            ),
            (
                json!({ "request_id": "req-1", "reason": 4 }),
                "deny reason must be a string",
            ),
        ] {
            let refused = standin.post_capability_deny(Caller::Shell, &body);
            assert!(
                matches!(&refused, Err((400, got)) if got == reason),
                "the stand-in refuses a non-string deny field: {refused:?}"
            );
        }
        let unknown =
            standin.post_capability_deny(Caller::Shell, &json!({ "request_id": "missing" }));
        assert!(
            matches!(
                &unknown,
                Err((400, reason)) if reason.starts_with("unknown request:") && reason.contains("missing")
            ),
            "the stand-in refuses an unknown deny request id: {unknown:?}"
        );
        assert_eq!(
            request_entries(&standin, &id),
            vec![pending_request("req-1", "component-1")],
            "the stand-in leaves the pending record after a refused deny"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in leaves the running instance after a refused deny",
        );

        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": "req-1", "reason": "shell said no" }),
            )
            .expect("the stand-in accepts the shell deny");
        assert_eq!(
            denied,
            json!({ "success": true }),
            "the stand-in answers success true for the accepted deny"
        );
        let settled = vec![shell_denied_request(
            "req-1",
            "component-1",
            "shell said no",
        )];
        assert_eq!(
            request_entries(&standin, &id),
            settled,
            "the stand-in stores the shell deny on the named record"
        );

        let again = standin.post_capability_deny(
            Caller::Shell,
            &json!({ "request_id": "req-1", "reason": "again" }),
        );
        assert!(
            matches!(
                &again,
                Err((400, reason)) if reason.starts_with("request is not pending:") && reason.contains("req-1")
            ),
            "the stand-in refuses a second deny of the settled request: {again:?}"
        );
        assert_eq!(
            request_entries(&standin, &id),
            settled,
            "the stand-in keeps the first shell deny after a refused second deny"
        );

        seed_shared_request(&mut standin, "req-2", &id);
        let extra = standin.post_capability_deny(
            Caller::Shell,
            &json!({ "request_id": "req-2", "token": "secret" }),
        );
        assert!(
            matches!(
                &extra,
                Err((400, reason)) if reason.starts_with("deny body rejects ") && reason.contains("token")
            ),
            "the stand-in refuses a deny body with an extra key: {extra:?}"
        );
        assert_eq!(
            request_entries(&standin, &id),
            vec![
                shell_denied_request("req-1", "component-1", "shell said no"),
                pending_request("req-2", "component-1"),
            ],
            "the stand-in changes nothing for a denied body with an extra key"
        );

        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops the first instance");
        seed_shared_request(&mut standin, "req-s", "component-1");
        standin
            .post_capability_deny(
                Caller::Shell,
                &json!({ "request_id": "req-s", "reason": "late deny" }),
            )
            .expect("the stand-in denies a request of the stopped instance");
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in keeps a stopped instance's phase and cause after a shell deny",
        );

        let waiting = launch_starting(&shared, &mut standin);
        seed_shared_request(&mut standin, "req-d", &waiting);
        standin
            .post_capability_deny(Caller::Shell, &json!({ "request_id": "req-d" }))
            .expect("the stand-in accepts a deny without a reason");
        assert_eq!(
            request_entries(&standin, &waiting),
            vec![shell_denied_request(
                "req-d",
                "component-2",
                "Denied by user"
            )],
            "the stand-in stores the default deny reason with the shell as settler"
        );
        assert_capsule(
            &standin,
            "component-2",
            "failed",
            "Denied by user",
            "the stand-in ends the starting instance failed with the default reason",
        );
    }

    #[test]
    fn standin_shell_grant_makes_one_live_grant() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let first = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launches the first read-shared instance");
        let second = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launches the second read-shared instance");
        assert_eq!(
            first["id"], "component-1",
            "the stand-in numbers the first launch component-1"
        );
        assert_eq!(
            second["id"], "component-2",
            "the stand-in numbers the second launch component-2"
        );
        assert_eq!(
            (first["status"].as_str(), second["status"].as_str()),
            (Some("starting"), Some("starting")),
            "the stand-in answers starting for both launches"
        );
        // Each live instance asks for the shared read through the route. The
        // route numbers them request-1 and request-2 in launch order.
        for id in ["component-1", "component-2"] {
            let requested = standin
                .post_capability_request(Caller::Client { session_id: id }, &request_client_body())
                .expect("the stand-in stores the instance's pending request");
            assert_eq!(
                requested["request_id"],
                if id == "component-1" {
                    "request-1"
                } else {
                    "request-2"
                },
                "the stand-in did the work: the request route names {id}'s request"
            );
        }
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("request-1", "component-1")],
            "the stand-in stores the first instance's request pending"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-2", "component-2")],
            "the stand-in stores the second instance's request pending"
        );
        standin.set_instant(4);

        let granted = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "request-1",
                    "duration": "Session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in grants the first instance's request");
        assert_keys(
            &granted,
            &["success"],
            "the stand-in grant body has one key",
        );
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in answers success true for the shell grant and stores no token"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![granted_request(
                "request-1",
                "component-1",
                "grant shared read"
            )],
            "the stand-in grants req-1 with the shell as settler and the rationale as decision"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-2", "component-2")],
            "the stand-in leaves the sibling request pending with no settler"
        );
        assert!(
            request_entries(&standin, "component-2")[0]["settled_by"].is_null(),
            "the stand-in leaves the sibling settler null"
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view");
        assert_eq!(
            request_ids(&live),
            BTreeSet::from(["request-1".to_owned()]),
            "the stand-in shows exactly the granted request as live"
        );
        assert_eq!(
            live["capabilities"][0],
            json!({
                "request_id": "request-1",
                "session_id": "component-1",
                "resource": SHARED_RESOURCE,
                "action": "read",
                "duration": "session",
                "granted_at": 4,
            }),
            "the stand-in stores the one live grant at the test instant with the lowercase duration"
        );
        let client = standin
            .get_capability_list(
                Caller::Client {
                    session_id: "component-2",
                },
                None,
            )
            .expect("the stand-in client list");
        assert_eq!(
            client["capabilities"].as_array().map(Vec::len),
            Some(0),
            "the stand-in shows the sibling client no grant"
        );
        standin
            .post_capability_validate(
                Caller::Client {
                    session_id: "component-1",
                },
                &json!({ "request_id": "request-1" }),
            )
            .expect("the stand-in authorises the granted instance");
        let sibling = standin.post_capability_validate(
            Caller::Client {
                session_id: "component-2",
            },
            &json!({ "request_id": "request-1" }),
        );
        assert!(
            matches!(&sibling, Err((403, reason)) if reason.contains("wrong capsule")),
            "the stand-in refuses the sibling presentation of the new grant: {sibling:?}"
        );
        assert_capsule(
            &standin,
            "component-1",
            "starting",
            "",
            "the stand-in keeps the granted instance starting before its start returns",
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in keeps the sibling starting",
        );

        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the granted instance start");
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in runs the granted instance after its start returns",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![granted_request(
                "request-1",
                "component-1",
                "grant shared read"
            )],
            "the stand-in keeps the granted record after the start returns"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live view")
            ),
            BTreeSet::from(["request-1".to_owned()]),
            "the stand-in keeps exactly the one live grant after the start returns"
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in keeps the sibling starting after the other start returns",
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-2", "component-2")],
            "the stand-in keeps the sibling request pending after the other start returns"
        );
        // The sibling resident's request-2 is pending from the request route
        // above and the shell grants it through the grant route, which stores
        // no token, so no route can produce a live grant here. This test
        // checks what any reader can see after the sibling's start finishes,
        // and that its grant leaves at its expiry instant.
        let sibling_granted = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({ "request_id": "request-2", "duration": "once" }),
            )
            .expect("the stand-in grants the sibling request");
        assert_eq!(
            sibling_granted,
            json!({ "success": true }),
            "the stand-in answers success true for the sibling grant and stores no token"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![granted_request(
                "request-2",
                "component-2",
                "Shell auto-grant"
            )],
            "the stand-in stores the sibling request granted by the grant route"
        );
        standin
            .finish_start("component-2")
            .expect("the sibling start finishes");
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![granted_request(
                "request-2",
                "component-2",
                "Shell auto-grant"
            )],
            "the stand-in keeps the started sibling's granted request-2"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in runs the sibling after its start returns",
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from(["request-1".to_owned(), "request-2".to_owned()]),
            "the stand-in lists the granted request-2 beside this test's grant"
        );
        assert_eq!(
            grant_record(&standin, "request-2"),
            (Life::Live, false),
            "the stand-in keeps the granted request-2 live: only its use spends it"
        );
        // One second before the granted request's expiry the live view still
        // lists it, and at the expiry instant it leaves through the one filter.
        let at_expiry = 4 + GRANT_LIFETIME_SECS;
        standin.set_instant(at_expiry - 1);
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from(["request-1".to_owned(), "request-2".to_owned()]),
            "the stand-in keeps the granted request live one second before its expiry"
        );
        standin.set_instant(at_expiry);
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from(["request-1".to_owned()]),
            "the stand-in drops the granted request at its expiry instant"
        );
    }

    #[test]
    fn standin_once_grant_expires_with_the_instant() {
        let shared = Shared::new();
        let mut standin = StandIn::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = shared
            .launch(&mut standin)
            .expect("the stand-in launches the read-shared instance")["id"]
            .as_str()
            .expect("the stand-in names the launched instance")
            .to_owned();
        let requested = standin
            .post_capability_request(
                Caller::Client { session_id: &id },
                &json!({
                    "resource": "localhost://Public/resident-instances/shared.txt",
                    "action": "read",
                    "reason": "read shared",
                }),
            )
            .expect("the stand-in stores the client request");
        let request_id = requested["request_id"]
            .as_str()
            .expect("the stand-in names the pending request")
            .to_owned();
        standin.set_instant(10);
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": request_id,
                    "duration": "once",
                    "rationale": "grant one read",
                }),
            )
            .expect("the stand-in grants the pending request for one use");
        let at_expiry = 10 + GRANT_LIFETIME_SECS;
        standin.set_instant(at_expiry - 1);
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live view one second before the expiry")
            ),
            BTreeSet::from([request_id.clone()]),
            "the stand-in keeps the grant live one second before its expiry"
        );
        assert_eq!(
            standin.post_capability_validate(
                Caller::Client { session_id: &id },
                &json!({ "request_id": request_id }),
            ),
            Ok(json!({ "valid": true })),
            "the stand-in authorises the grant one second before its expiry"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live view after spending the once grant")
            ),
            BTreeSet::new(),
            "the stand-in omits the once grant it just spent"
        );

        standin.set_instant(20);
        standin
            .post_capability_request(
                Caller::Client { session_id: &id },
                &json!({
                    "resource": "localhost://Public/resident-instances/shared.txt",
                    "action": "read",
                    "reason": "read shared",
                }),
            )
            .expect("the stand-in stores the client request");
        let request_id = request_entries(&standin, &id)
            .iter()
            .find(|entry| entry["status"] == "pending")
            .expect("the stand-in stored the second pending request")["request_id"]
            .as_str()
            .expect("the stand-in names the pending request")
            .to_owned();
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": request_id,
                    "duration": "once",
                    "rationale": "grant one read",
                }),
            )
            .expect("the stand-in grants the second request for one use");
        let at_expiry = 20 + GRANT_LIFETIME_SECS;
        standin.set_instant(at_expiry);
        assert_eq!(
            standin.post_capability_validate(
                Caller::Client { session_id: &id },
                &json!({ "request_id": request_id }),
            ),
            Err((400, "grant is not live: Expired".to_owned())),
            "the stand-in refuses the grant at its expiry instant"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Client { session_id: &id }, None)
                    .expect("the stand-in client live view at the expiry instant")
            ),
            BTreeSet::new(),
            "the stand-in drops the grant from the owning session view at its expiry instant"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live view at the expiry instant")
            ),
            BTreeSet::new(),
            "the stand-in drops the grant from the shell all-sessions view at its expiry instant"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, Some(LIVE_SCOPE))
                    .expect("the stand-in scoped live view at the expiry instant")
            ),
            BTreeSet::new(),
            "the stand-in drops the grant from the scoped all-sessions view at its expiry instant"
        );
        assert_eq!(
            request_entries(&standin, &id)
                .iter()
                .filter(|entry| entry["status"] == "granted")
                .count(),
            2,
            "the stand-in keeps both granted records after the expiry"
        );
    }

    #[test]
    fn standin_no_live_grant_after_stop_cancel_or_failed_start() {
        let start_cases = [
            (
                Start::Error("start refused".to_owned()),
                "failed start",
                "start refused",
            ),
            (
                Start::Trap("start trapped".to_owned()),
                "trapped start",
                "start trapped",
            ),
        ];
        for (start, label, cause) in start_cases {
            let mut standin = StandIn::new();
            let failing_bundle = Shared::new();
            let sibling_bundle = other_bundle();
            admit_shared(&failing_bundle, &mut standin, start);
            admit_shared(&sibling_bundle, &mut standin, Start::Ok);
            let failing = failing_bundle
                .launch(&mut standin)
                .expect("the stand-in launches the failing component");
            let failing = failing["id"]
                .as_str()
                .expect("the stand-in names the failing launch")
                .to_owned();
            let sibling = sibling_bundle
                .launch(&mut standin)
                .expect("the stand-in launches the sibling");
            let sibling = sibling["id"]
                .as_str()
                .expect("the stand-in names the sibling launch")
                .to_owned();
            let requested = standin
                .post_capability_request(
                    Caller::Client {
                        session_id: &failing,
                    },
                    &request_client_body(),
                )
                .expect("the stand-in stores the failing instance request");
            let requested_id = requested["request_id"]
                .as_str()
                .expect("the stand-in names the pending request")
                .to_owned();
            standin
                .post_capability_grant(
                    Caller::Shell,
                    &json!({ "request_id": requested_id, "duration": "session" }),
                )
                .expect("the stand-in grants the failing instance request");
            let sibling_request = standin
                .post_capability_request(
                    Caller::Client {
                        session_id: &sibling,
                    },
                    &request_client_body(),
                )
                .expect("the stand-in stores the sibling request");
            let sibling_id = sibling_request["request_id"]
                .as_str()
                .expect("the stand-in names the sibling request")
                .to_owned();
            standin
                .post_capability_grant(
                    Caller::Shell,
                    &json!({ "request_id": sibling_id, "duration": "session" }),
                )
                .expect("the stand-in grants the sibling request");
            let before = standin
                .get_capability_list(Caller::Shell, Some("all_sessions_live"))
                .expect("the stand-in shell live view before the failed start");
            assert_eq!(
                request_ids(&before),
                BTreeSet::from([requested_id.clone(), sibling_id.clone()]),
                "the stand-in shows both live grants before the {label}"
            );

            standin
                .finish_start(&failing)
                .expect("the stand-in finishes the failed start");
            let listed = shell_list(&standin);
            let entry = listed["capsules"]
                .as_array()
                .expect("the stand-in returns capsules")
                .iter()
                .find(|entry| entry["id"] == failing)
                .cloned();
            assert_eq!(
                entry,
                Some(json!({
                    "id": failing,
                    "name": SHARED_NAME,
                    "status": "failed",
                    "session_id": failing,
                    "cause": cause,
                })),
                "the stand-in stores the failed start"
            );
            let after = standin
                .get_capability_list(Caller::Shell, Some("all_sessions_live"))
                .expect("the stand-in shell live view after the failed start");
            assert_eq!(
                request_ids(&after),
                BTreeSet::from([sibling_id.clone()]),
                "the stand-in shows no live grant of the session after the {label}"
            );
            let own = standin
                .get_capability_list(
                    Caller::Client {
                        session_id: &failing,
                    },
                    None,
                )
                .expect("the stand-in failed session client live view");
            assert_eq!(
                request_ids(&own),
                BTreeSet::new(),
                "the stand-in failed session client sees no live grant after the {label}"
            );
        }
        for (label, stop, reason) in [
            ("stop", true, "shell stop"),
            ("cancel", false, "cancel from the shell"),
        ] {
            let mut standin = StandIn::new();
            let shared = Shared::new();
            admit_shared(&shared, &mut standin, Start::Ok);
            let launched = launch_starting(&shared, &mut standin);
            let sibling = launch_starting(&shared, &mut standin);
            let requested = standin
                .post_capability_request(
                    Caller::Client {
                        session_id: &launched,
                    },
                    &request_client_body(),
                )
                .expect("the stand-in stores the stopped instance request");
            let requested_id = requested["request_id"]
                .as_str()
                .expect("the stand-in names the pending request")
                .to_owned();
            standin
                .post_capability_grant(
                    Caller::Shell,
                    &json!({ "request_id": requested_id, "duration": "session" }),
                )
                .expect("the stand-in grants the stopped instance request");
            let sibling_request = standin
                .post_capability_request(
                    Caller::Client {
                        session_id: &sibling,
                    },
                    &request_client_body(),
                )
                .expect("the stand-in stores the sibling request");
            let sibling_id = sibling_request["request_id"]
                .as_str()
                .expect("the stand-in names the sibling request")
                .to_owned();
            standin
                .post_capability_grant(
                    Caller::Shell,
                    &json!({ "request_id": sibling_id, "duration": "session" }),
                )
                .expect("the stand-in grants the sibling request");
            if stop {
                standin
                    .finish_start(&launched)
                    .expect("the stand-in finishes the stopped instance start");
            }
            let stopped = standin
                .delete_capsule(Caller::Shell, &launched, &json!({ "reason": reason }))
                .expect("the stand-in ends the instance");
            assert!(
                stopped.is_null(),
                "the stand-in answers null for the {label} of a live instance"
            );
            assert_capsule(
                &standin,
                &launched,
                "stopped",
                &format!("stopped: {reason}"),
                &format!("the stand-in stores the {label}"),
            );
            let after = standin
                .get_capability_list(Caller::Shell, Some("all_sessions_live"))
                .expect("the stand-in shell live view after the end");
            assert_eq!(
                request_ids(&after),
                BTreeSet::from([sibling_id.clone()]),
                "the stand-in shows no live grant of the session after the {label} while the sibling grant stays live"
            );
            let own = standin
                .get_capability_list(
                    Caller::Client {
                        session_id: &launched,
                    },
                    None,
                )
                .expect("the stand-in ended session client live view");
            assert_eq!(
                request_ids(&own),
                BTreeSet::new(),
                "the stand-in ended session client sees no live grant after the {label}"
            );
        }
    }

    #[test]
    fn standin_shell_grant_refuses_a_bad_request() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = launch_starting(&shared, &mut standin);
        let sibling = launch_finished(&shared, &mut standin);
        let requested = standin
            .post_capability_request(Caller::Client { session_id: &id }, &request_client_body())
            .expect("the stand-in stores the requester's pending request");
        let req_d = requested["request_id"]
            .as_str()
            .expect("the stand-in names the request")
            .to_owned();
        assert_eq!(
            req_d, "request-1",
            "the stand-in did the work: the request route names request-1"
        );

        // The requesting instance and its sibling resident hold the pending
        // request id. Neither approves it, with or without a body.
        for session_id in [id.as_str(), sibling.as_str()] {
            for grant_body in [
                json!({ "request_id": req_d }),
                json!({ "request_id": req_d, "duration": "once", "rationale": "self" }),
                json!({}),
            ] {
                let client =
                    standin.post_capability_grant(Caller::Client { session_id }, &grant_body);
                assert!(
                    matches!(&client, Err((403, reason)) if reason == "This endpoint requires shell privileges"),
                    "the stand-in refuses {session_id} its own grant before reading the body: {client:?}"
                );
            }
            assert_eq!(
                request_entries(&standin, &id),
                vec![pending_request(&req_d, &id)],
                "the stand-in leaves {req_d} pending after {session_id} tried to approve it"
            );
            assert!(
                standin.grants.is_empty(),
                "the stand-in stores no grant after {session_id} tried to approve req-d"
            );
            assert_eq!(
                request_ids(
                    &standin
                        .get_capability_list(Caller::Shell, None)
                        .expect("the stand-in shell live view")
                ),
                BTreeSet::new(),
                "the stand-in shows no live grant after {session_id} tried to approve req-d"
            );
            assert_capsule(
                &standin,
                &id,
                "starting",
                "",
                "the stand-in leaves the requester starting after a client grant",
            );
        }

        for body in [json!({}), json!(req_d.clone())] {
            let refused = standin.post_capability_grant(Caller::Shell, &body);
            assert!(
                matches!(&refused, Err((400, reason)) if reason == "grant body needs request_id"),
                "the stand-in refuses a grant body without request_id: {refused:?}"
            );
        }
        for (body, reason) in [
            (
                json!({ "request_id": 4 }),
                "grant request_id must be a string",
            ),
            (
                json!({ "request_id": req_d, "duration": 4 }),
                "grant duration must be a string",
            ),
            (
                json!({ "request_id": req_d, "rationale": 4 }),
                "grant rationale must be a string",
            ),
        ] {
            let refused = standin.post_capability_grant(Caller::Shell, &body);
            assert!(
                matches!(&refused, Err((400, got)) if got == reason),
                "the stand-in refuses a non-string grant field: {refused:?}"
            );
        }

        let unknown =
            standin.post_capability_grant(Caller::Shell, &json!({ "request_id": "missing" }));
        assert!(
            matches!(
                &unknown,
                Err((400, reason)) if reason.starts_with("unknown request:") && reason.contains("missing")
            ),
            "the stand-in refuses an unknown grant request id: {unknown:?}"
        );
        let extra = standin.post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": req_d, "token": "secret" }),
        );
        assert!(
            matches!(
                &extra,
                Err((400, reason)) if reason.starts_with("grant body rejects ") && reason.contains("token")
            ),
            "the stand-in refuses a grant body with an extra key: {extra:?}"
        );
        let bad_duration = standin.post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": req_d, "duration": "minutes" }),
        );
        assert!(
            matches!(
                &bad_duration,
                Err((400, reason)) if reason == "Invalid duration: minutes. Expected 'once' or 'session'"
            ),
            "the stand-in refuses an unknown grant duration: {bad_duration:?}"
        );
        assert_eq!(
            request_entries(&standin, &id),
            vec![pending_request(&req_d, &id)],
            "the stand-in leaves the request pending after every refused grant"
        );
        assert!(
            standin.grants.is_empty(),
            "the stand-in stores no grant for a refused request"
        );
        assert_capsule(
            &standin,
            &id,
            "starting",
            "",
            "the stand-in leaves the instance starting after a refused grant",
        );

        let granted = standin
            .post_capability_grant(Caller::Shell, &json!({ "request_id": req_d }))
            .expect("the stand-in grants the request without duration or rationale");
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in answers success true for the defaulted grant"
        );
        assert_eq!(
            request_entries(&standin, &id),
            vec![granted_request(&req_d, &id, "Shell auto-grant")],
            "the stand-in stores the default rationale with the shell as settler"
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view");
        assert_eq!(
            live["capabilities"][0]["duration"], "session",
            "the stand-in stores the default duration as session"
        );

        let again = standin.post_capability_grant(Caller::Shell, &json!({ "request_id": req_d }));
        assert!(
            matches!(
                &again,
                Err((400, reason)) if reason.starts_with("request is not pending:") && reason.contains(&req_d)
            ),
            "the stand-in refuses a second grant of the settled request: {again:?}"
        );
        assert_eq!(
            request_entries(&standin, &id),
            vec![granted_request(&req_d, &id, "Shell auto-grant")],
            "the stand-in keeps the first granted record after a refused second grant"
        );

        // The route stores the request while the third instance is live. The
        // stop then settles it, so the late grant has a real settled record.
        let stopped = launch_starting(&shared, &mut standin);
        let requested = standin
            .post_capability_request(
                Caller::Client {
                    session_id: &stopped,
                },
                &request_client_body(),
            )
            .expect("the stand-in stores the third instance's pending request");
        let req_s = requested["request_id"]
            .as_str()
            .expect("the stand-in names the request")
            .to_owned();
        assert_eq!(
            req_s, "request-2",
            "the stand-in did the work: the request route names request-2"
        );
        assert_eq!(
            request_entries(&standin, &stopped),
            vec![pending_request(&req_s, &stopped)],
            "the stand-in stores the third instance's request pending before the stop"
        );
        standin
            .delete_capsule(Caller::Shell, &stopped, &stop_body())
            .expect("the stand-in stops the third instance");
        assert_eq!(
            request_entries(&standin, &stopped),
            vec![denied_request(&req_s, &stopped, "stopped: stop one")],
            "the stand-in keeps the runtime settlement of the stopped instance's request"
        );
        let late = standin.post_capability_grant(Caller::Shell, &json!({ "request_id": req_s }));
        assert!(
            matches!(
                &late,
                Err((400, reason)) if reason.starts_with("request is not pending:") && reason.contains(&req_s)
            ),
            "the stand-in refuses a grant of the stopped instance's request: {late:?}"
        );
        assert_eq!(
            request_entries(&standin, &stopped),
            vec![denied_request(&req_s, &stopped, "stopped: stop one")],
            "the stand-in keeps the settled record after the refused late grant"
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view");
        assert!(
            !request_ids(&live).contains(&req_s),
            "the stand-in shows no live grant for the stopped instance's request"
        );
    }

    #[test]
    fn standin_duplicate_request_is_refused() {
        let mut standin = StandIn::new();
        seed_shared_request(&mut standin, "req-1", "component-1");
        let second = standin.seed_request(
            "req-1",
            "component-2",
            "localhost://Public/other.txt",
            "write",
            "replace it",
        );
        assert!(
            matches!(
                &second,
                Err((400, reason))
                    if reason.starts_with("request already stored:") && reason.contains("req-1")
            ),
            "the stand-in refuses a duplicate request id: {second:?}"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in keeps the first pending record"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            Vec::<Value>::new(),
            "the stand-in stores no replacement record"
        );
    }

    #[test]
    fn standin_request_seed_validation() {
        let mut standin = StandIn::new();
        let empty = [
            ("", "component-1", SHARED_RESOURCE, "read"),
            ("req-1", "", SHARED_RESOURCE, "read"),
            ("req-1", "component-1", "", "read"),
            ("req-1", "component-1", SHARED_RESOURCE, ""),
        ];
        for (request_id, session_id, resource, action) in empty {
            let seeded =
                standin.seed_request(request_id, session_id, resource, action, "read shared");
            assert_request_refused(
                &seeded,
                "request needs an id, a session, a resource and an action",
                "the stand-in refuses a request missing a required field",
            );
            assert_eq!(
                request_entries(&standin, "component-1"),
                Vec::<Value>::new(),
                "the stand-in stores no record for a refused seed"
            );
        }
        standin
            .seed_request("req-1", "component-1", SHARED_RESOURCE, "read", "")
            .expect("the stand-in accepts an empty request reason");
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![json!({
                "request_id": "req-1",
                "session_id": "component-1",
                "resource": SHARED_RESOURCE,
                "action": "read",
                "reason": "",
                "status": "pending",
                "decision_reason": "",
                "settled_by": Value::Null,
                "plan": Value::Null,
            })],
            "the stand-in stores the accepted record pending with the given reason"
        );
    }

    #[test]
    fn standin_request_record_contract() {
        let mut standin = StandIn::new();
        standin
            .seed_request("req-z", "component-1", "res-z", "write", "later")
            .expect("the stand-in seeds req-z");
        standin
            .seed_request("req-a", "component-1", "res-a", "read", "first")
            .expect("the stand-in seeds req-a");
        standin
            .seed_request("req-b", "component-2", "res-b", "read", "other")
            .expect("the stand-in seeds req-b");
        let body = shell_requests(&standin, "component-1");
        assert_keys(
            &body,
            &["requests"],
            "the stand-in request body has one key",
        );
        for entry in body["requests"].as_array().unwrap() {
            assert_keys(
                entry,
                REQUEST_ENTRY,
                "the stand-in request entry carries the record fields",
            );
        }
        assert_eq!(
            body,
            json!({
                "requests": [
                    {
                        "request_id": "req-a",
                        "session_id": "component-1",
                        "resource": "res-a",
                        "action": "read",
                        "reason": "first",
                        "status": "pending",
                        "decision_reason": "",
                        "settled_by": Value::Null,
                        "plan": Value::Null,
                    },
                    {
                        "request_id": "req-z",
                        "session_id": "component-1",
                        "resource": "res-z",
                        "action": "write",
                        "reason": "later",
                        "status": "pending",
                        "decision_reason": "",
                        "settled_by": Value::Null,
                        "plan": Value::Null,
                    },
                ],
            }),
            "the stand-in returns that session's pending records sorted by request id"
        );
        assert_eq!(
            shell_requests(&standin, "component-3"),
            json!({ "requests": [] }),
            "the stand-in returns an empty list for an unknown session"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![json!({
                "request_id": "req-b",
                "session_id": "component-2",
                "resource": "res-b",
                "action": "read",
                "reason": "other",
                "status": "pending",
                "decision_reason": "",
                "settled_by": Value::Null,
                "plan": Value::Null,
            })],
            "the stand-in keeps another session's records out"
        );
    }

    #[test]
    fn standin_refused_stop_preserves_requests() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");
        let client = Caller::Client {
            session_id: "component-1",
        };
        let refused = [
            (
                client,
                "component-1",
                Value::Null,
                403u16,
                "This endpoint requires shell privileges",
            ),
            (
                Caller::Shell,
                "component-1",
                Value::Null,
                400,
                "stop body needs reason",
            ),
            (
                Caller::Shell,
                "component-9",
                stop_body(),
                400,
                "unknown instance: component-9",
            ),
            (Caller::Shell, "", stop_body(), 400, "unknown instance: "),
        ];
        for (caller, id, body, status, reason) in refused {
            let result = standin.delete_capsule(caller, id, &body);
            assert_delete(
                &result,
                status,
                reason,
                "the stand-in refuses this stop before any settlement",
            );
            assert_eq!(
                request_entries(&standin, "component-1"),
                vec![pending_request("req-1", "component-1")],
                "the stand-in leaves the pending request after a refused stop"
            );
        }
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        seed_shared_request(&mut standin, "req-2", "component-1");
        let ended = standin.delete_capsule(Caller::Shell, "component-1", &stop_body());
        assert_delete(
            &ended,
            400,
            "instance is not live: stopped",
            "the stand-in refuses a stop of the ended instance",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                denied_request("req-1", "component-1", "stopped: stop one"),
                pending_request("req-2", "component-1"),
            ],
            "the stand-in leaves the ended instance's new request pending after the refused stop"
        );
    }

    #[test]
    fn standin_stop_preserves_settled_requests() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        standin.requests.push(Request {
            request_id: "req-old".to_owned(),
            session_id: "component-1".to_owned(),
            resource: SHARED_RESOURCE.to_owned(),
            action: "read".to_owned(),
            reason: "earlier".to_owned(),
            requested_at: 0,
            status: RequestStatus::Denied,
            decision_reason: "denied earlier".to_owned(),
            settled_by: Some("shell"),
            plan: None,
        });
        seed_shared_request(&mut standin, "req-1", "component-1");
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                denied_request("req-1", "component-1", "stopped: stop one"),
                json!({
                    "request_id": "req-old",
                    "session_id": "component-1",
                    "resource": SHARED_RESOURCE,
                    "action": "read",
                    "reason": "earlier",
                    "status": "denied",
                    "decision_reason": "denied earlier",
                    "settled_by": "shell",
                    "plan": Value::Null,
                }),
            ],
            "the stand-in denies only pending requests and leaves the settled record"
        );
    }

    #[test]
    fn standin_unanswered_request_expires() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let first = launch_finished(&shared, &mut standin);
        let second = launch_finished(&shared, &mut standin);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("component-1", "component-2"),
            "the stand-in numbers the two finished launches component-1 and component-2"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in runs the first instance",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in runs the second instance",
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        let granted = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-2",
                    "duration": "session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in grants the second instance's request");
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in answers success true for the shell grant"
        );
        standin.set_instant(299);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in keeps the unanswered request pending below 300 seconds"
        );
        assert!(
            request_entries(&standin, "component-1")[0]["settled_by"].is_null(),
            "the stand-in leaves the unanswered settler null below 300 seconds"
        );
        standin.set_instant(300);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![expired_request("req-1", "component-1")],
            "the stand-in expires the unanswered request at 300 seconds with the runtime as settler"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in leaves the instance running when its request expires",
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![granted_request("req-2", "component-2", "grant shared read")],
            "the stand-in leaves the granted record from the shell"
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view after the expiry");
        assert_eq!(
            request_ids(&live),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in shows exactly the granted request as live after the expiry"
        );
        let denied = standin.post_capability_deny(
            Caller::Shell,
            &json!({ "request_id": "req-1", "reason": "too late" }),
        );
        assert_delete(
            &denied,
            400,
            "request is not pending: req-1",
            "the stand-in refuses a deny of the expired request",
        );
        let late = standin.post_capability_grant(Caller::Shell, &json!({ "request_id": "req-1" }));
        assert_delete(
            &late,
            400,
            "request is not pending: req-1",
            "the stand-in refuses a grant of the expired request",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![expired_request("req-1", "component-1")],
            "the stand-in leaves the expired record after both refusals"
        );
        let live = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live view after both refusals");
        assert_eq!(
            request_ids(&live),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in leaves exactly the granted request live after both refusals"
        );
        seed_shared_request(&mut standin, "req-3", "component-1");
        standin.set_instant(599);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                expired_request("req-1", "component-1"),
                pending_request("req-3", "component-1"),
            ],
            "the stand-in keeps a request seeded at 300 pending below its own 300 seconds"
        );
        assert!(
            request_entries(&standin, "component-1")[1]["settled_by"].is_null(),
            "the stand-in leaves the new request's settler null at 599 seconds"
        );
        standin.set_instant(600);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                expired_request("req-1", "component-1"),
                expired_request("req-3", "component-1"),
            ],
            "the stand-in expires the second request at 600 seconds and keeps the first expired record"
        );
        standin.requests.push(Request {
            request_id: "req-old".to_owned(),
            session_id: "component-1".to_owned(),
            resource: SHARED_RESOURCE.to_owned(),
            action: "read".to_owned(),
            reason: "earlier".to_owned(),
            requested_at: 0,
            status: RequestStatus::Denied,
            decision_reason: "denied earlier".to_owned(),
            settled_by: Some("shell"),
            plan: None,
        });
        standin.set_instant(300);
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                expired_request("req-1", "component-1"),
                expired_request("req-3", "component-1"),
                json!({
                    "request_id": "req-old",
                    "session_id": "component-1",
                    "resource": SHARED_RESOURCE,
                    "action": "read",
                    "reason": "earlier",
                    "status": "denied",
                    "decision_reason": "denied earlier",
                    "settled_by": "shell",
                    "plan": Value::Null,
                }),
            ],
            "the stand-in leaves the settled denied record as its own test stores it"
        );
    }

    #[test]
    fn standin_starting_stop_denies_that_sessions_pending() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_starting(&shared, &mut standin);
        seed_shared_request(&mut standin, "req-1", "component-1");
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops a starting instance");
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "stopped: stop one")],
            "the stand-in denies a starting instance's pending request"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in stores stopped with the stop cause",
        );
    }

    #[test]
    fn standin_stopped_stays_for_sixty_seconds() {
        let mut standin = StandIn::new();
        standin.set_instant(0);
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        launch_finished(&shared, &mut standin);
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 at instant 0");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it stops one instance"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in lists a stopped instance at instant 0",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in lists the running sibling at instant 0",
        );
        standin.set_instant(59);
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in lists a stopped instance at instant 59",
        );
        standin.set_instant(60);
        assert_eq!(
            shell_list(&standin),
            json!({
                "capsules": [{
                    "id": "component-2",
                    "name": SHARED_NAME,
                    "status": "running",
                    "session_id": "component-2",
                    "cause": "",
                }]
            }),
            "the stand-in omits a stopped instance at instant 60 and keeps the running sibling"
        );

        let mut later = StandIn::new();
        later.set_instant(1_000);
        let shared = Shared::new();
        admit_shared(&shared, &mut later, Start::Ok);
        launch_finished(&shared, &mut later);
        launch_finished(&shared, &mut later);
        later.set_instant(1_070);
        later
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 at instant 1070");
        assert_capsule(
            &later,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in lists a stopped instance at the stop instant",
        );
        later.set_instant(1_129);
        assert_capsule(
            &later,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in lists a stopped instance 59 seconds after the stop",
        );
        later.set_instant(1_130);
        assert_eq!(
            shell_list(&later),
            json!({
                "capsules": [{
                    "id": "component-2",
                    "name": SHARED_NAME,
                    "status": "running",
                    "session_id": "component-2",
                    "cause": "",
                }]
            }),
            "the stand-in omits a stopped instance 60 seconds after the stop and keeps the running sibling"
        );
    }

    #[test]
    fn standin_stopped_instance_makes_no_request() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let first = launch_finished(&shared, &mut standin);
        let second = launch_finished(&shared, &mut standin);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("component-1", "component-2"),
            "the stand-in numbers the two running launches component-1 and component-2"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in lists component-1 running before the stop",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in lists component-2 running before the stop",
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 at instant 0");
        standin.set_instant(2);
        let watched = standin.watch_ended("component-1", "stopped");
        assert!(
            watched.is_ok(),
            "the stand-in watch reports the stopped instance two seconds after the stop: {watched:?}"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in lists the stopped instance two seconds after the stop",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves the running sibling listed after the watch",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "stopped: stop one",)],
            "the stand-in request record for the stopped instance is not pending"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's request pending after the watch"
        );
        standin
            .seed_request(
                "req-retry",
                "component-1",
                SHARED_RESOURCE,
                "read",
                "read shared",
            )
            .expect("the stand-in seeds a pending request after the instance ended");
        let retried = standin.watch_ended("component-1", "stopped");
        assert_request_refused(
            &retried,
            "made a request after it ended: component-1",
            "the stand-in watch reports the pending request that appeared after the end",
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in leaves the stopped instance listed after the refusal",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                denied_request("req-1", "component-1", "stopped: stop one"),
                pending_request("req-retry", "component-1"),
            ],
            "the stand-in leaves req-1 denied and req-retry pending after the refusal"
        );
        let unchanged = request_entries(&standin, "component-1");
        let wrong_status = standin.watch_ended("component-1", "running");
        assert_request_refused(
            &wrong_status,
            "watch status must be stopped or failed",
            "the stand-in watch refuses a status other than stopped or failed",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            unchanged,
            "the refused watch status changes no request record"
        );
        let missing = standin.watch_ended("component-9", "stopped");
        assert_request_refused(
            &missing,
            "left the instance list: component-9",
            "the stand-in watch reports an instance that is not listed",
        );

        let mut later = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut later, Start::Ok);
        launch_finished(&shared, &mut later);
        launch_finished(&shared, &mut later);
        seed_shared_request(&mut later, "req-1", "component-1");
        later
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 at instant 0");
        later.set_instant(2);
        assert!(
            later.watch_ended("component-1", "stopped").is_ok(),
            "the stand-in watch reports the stopped instance two seconds after the stop"
        );
        later.set_instant(60);
        let left = later.watch_ended("component-1", "stopped");
        assert_request_refused(
            &left,
            "left the instance list: component-1",
            "the stand-in watch reports the stopped instance that left the list at 60 seconds",
        );
        assert_eq!(
            request_entries(&later, "component-1"),
            vec![denied_request("req-1", "component-1", "stopped: stop one",)],
            "the stand-in leaves the one denied request after the 60-second refusal"
        );
    }

    #[test]
    fn standin_failed_instance_makes_no_request() {
        let failing_bundle = Shared::new();
        let sibling_bundle = other_bundle();
        let mut standin = StandIn::new();
        admit_shared(
            &failing_bundle,
            &mut standin,
            Start::Error("start refused".to_owned()),
        );
        admit_shared(&sibling_bundle, &mut standin, Start::Ok);
        let failing = failing_bundle
            .launch(&mut standin)
            .expect("the stand-in launches the failing bundle");
        let sibling = sibling_bundle
            .launch(&mut standin)
            .expect("the stand-in launches the sibling bundle");
        assert_eq!(
            (failing["id"].as_str(), failing["status"].as_str()),
            (Some("component-1"), Some("starting")),
            "the stand-in answers starting for the failing launch component-1"
        );
        assert_eq!(
            (sibling["id"].as_str(), sibling["status"].as_str()),
            (Some("component-2"), Some("starting")),
            "the stand-in answers starting for the sibling launch component-2"
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the failing start at instant 0");
        standin.set_instant(2);
        let watched = standin.watch_ended("component-1", "failed");
        assert!(
            watched.is_ok(),
            "the stand-in watch reports the failed instance two seconds after the failure: {watched:?}"
        );
        let listed = shell_list(&standin);
        let ended = listed["capsules"]
            .as_array()
            .expect("the stand-in returns capsules")
            .iter()
            .find(|entry| entry["id"] == "component-1");
        assert_eq!(
            ended,
            Some(&json!({
                "id": "component-1",
                "name": SHARED_NAME,
                "status": "failed",
                "session_id": "component-1",
                "cause": "start refused",
            })),
            "the stand-in lists the failed instance two seconds after the failure"
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in leaves the sibling starting after the watch",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "start refused",)],
            "the stand-in request record for the failed instance is not pending"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in leaves the sibling's request pending after the watch"
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in stops no sibling of the failed instance",
        );

        let mut empty = StandIn::new();
        let failing_bundle = Shared::new();
        admit_shared(
            &failing_bundle,
            &mut empty,
            Start::Error("start refused".to_owned()),
        );
        let only = failing_bundle
            .launch(&mut empty)
            .expect("the stand-in launches the failing bundle once");
        assert_eq!(
            only["id"], "component-1",
            "the stand-in numbers the only failing launch component-1"
        );
        empty
            .finish_start("component-1")
            .expect("the stand-in finishes the failing start with no seeded request");
        empty.set_instant(2);
        let no_records = empty.watch_ended("component-1", "failed");
        assert_request_refused(
            &no_records,
            "component-1 has 0 request records after it ended",
            "the stand-in watch counts the failed instance's request records",
        );
        assert_eq!(
            shell_list(&empty),
            json!({
                "capsules": [{
                    "id": "component-1",
                    "name": SHARED_NAME,
                    "status": "failed",
                    "session_id": "component-1",
                    "cause": "start refused",
                }]
            }),
            "the stand-in leaves the failed entry listed after the count refusal"
        );
        assert!(
            empty.grants.is_empty(),
            "the stand-in mints no grant from the watch"
        );
    }

    #[test]
    fn standin_stop_during_start_blocks_finish() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let first = launch_starting(&shared, &mut standin);
        let second = launch_starting(&shared, &mut standin);
        assert_eq!(
            (first, second),
            ("component-1".to_owned(), "component-2".to_owned()),
            "the stand-in launches two starting instances"
        );
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        seed_at(&mut standin, "req-2", "component-2", Life::Live);
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops an instance during start");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it stops during start"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in stores stopped before start returns",
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Revoked, false),
            "the stand-in revokes the starting instance's live grant"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in drops the revoked grant and keeps the sibling grant"
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in leaves the starting sibling",
        );
        let finished = standin.finish_start("component-1");
        assert!(
            matches!(
                &finished,
                Err((400, reason)) if reason == "instance is not live: stopped"
            ),
            "the stand-in refuses finish_start after a stop during start: {finished:?}"
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in keeps stopped when finish_start follows the stop",
        );
        assert_capsule(
            &standin,
            "component-2",
            "starting",
            "",
            "the stand-in leaves the starting sibling after the refused finish",
        );
        assert_eq!(
            grant_record(&standin, "req-2"),
            (Life::Live, false),
            "the stand-in leaves the sibling grant live"
        );
    }

    #[test]
    fn standin_second_stop_is_refused() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        launch_finished(&shared, &mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        seed_at(&mut standin, "req-e", "component-1", Life::Exhausted);
        seed_at(&mut standin, "req-2", "component-2", Life::Live);
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 once");
        let second = standin.delete_capsule(Caller::Shell, "component-1", &stop_body());
        assert_delete(
            &second,
            400,
            "instance is not live: stopped",
            "the stand-in refuses a second stop",
        );
        assert_capsule(
            &standin,
            "component-1",
            "stopped",
            "stopped: stop one",
            "the stand-in keeps the first stop reason",
        );
        assert_eq!(
            grant_record(&standin, "req-1"),
            (Life::Revoked, false),
            "the stand-in leaves the revoked grant revoked"
        );
        assert_eq!(
            grant_record(&standin, "req-e"),
            (Life::Exhausted, false),
            "the stand-in leaves an exhausted grant exhausted"
        );
        assert_eq!(
            grant_record(&standin, "req-2"),
            (Life::Live, false),
            "the stand-in leaves the sibling grant live"
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves the sibling running",
        );
        assert_next_launch(&shared, &mut standin, "component-3");
    }

    #[test]
    fn standin_client_cannot_stop() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        launch_finished(&shared, &mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        let client = Caller::Client {
            session_id: "component-1",
        };
        let valid = stop_body();
        let attempts = [
            (
                "component-1",
                valid.clone(),
                "the stand-in refuses a client stop",
            ),
            (
                "component-1",
                Value::Null,
                "the stand-in refuses a client stop when the body is not an object",
            ),
            (
                "component-1",
                json!({}),
                "the stand-in refuses a client stop when reason is missing",
            ),
            (
                "component-1",
                json!({ "reason": 1 }),
                "the stand-in refuses a client stop when reason is not a string",
            ),
            (
                "component-1",
                json!({ "reason": "" }),
                "the stand-in refuses a client stop when reason is empty",
            ),
            (
                "component-9",
                valid.clone(),
                "the stand-in refuses a client stop of an unknown id",
            ),
            (
                "",
                valid,
                "the stand-in refuses a client stop of an empty id",
            ),
        ];
        for (id, body, message) in attempts {
            let result = standin.delete_capsule(client, id, &body);
            assert_delete(
                &result,
                403,
                "This endpoint requires shell privileges",
                message,
            );
            assert_capsule(
                &standin,
                "component-1",
                "running",
                "",
                "the stand-in leaves the running instance after a client stop",
            );
            assert_eq!(
                grant_record(&standin, "req-1"),
                (Life::Live, false),
                "the stand-in leaves the live grant after a client stop"
            );
        }
        let shell_body = standin.delete_capsule(Caller::Shell, "component-1", &Value::Null);
        assert_delete(
            &shell_body,
            400,
            "stop body needs reason",
            "the stand-in shell is refused for the body, not for shell privileges",
        );
        let shell_unknown = standin.delete_capsule(Caller::Shell, "component-9", &stop_body());
        assert_delete(
            &shell_unknown,
            400,
            "unknown instance: component-9",
            "the stand-in shell is refused for the unknown id, not for shell privileges",
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in leaves the running instance after the shell refusals",
        );
        assert_next_launch(&shared, &mut standin, "component-2");
    }

    fn launch_two_running(shared: &Shared, standin: &mut StandIn) {
        admit_shared(shared, standin, Start::Ok);
        launch_finished(shared, standin);
        launch_finished(shared, standin);
    }

    fn launch_two_running_ids(standin: &mut StandIn) -> (String, String) {
        let shared = Shared::new();
        admit_shared(&shared, standin, Start::Ok);
        (
            launch_finished(&shared, standin),
            launch_finished(&shared, standin),
        )
    }

    /// An absent grant id is status 400 with the fixed reason `unknown grant`.
    /// The absent-id reply omits the supplied id.
    fn assert_unknown(result: &Result<Value, (u16, String)>, request_id: &str, who: &str) {
        assert!(
            matches!(result, Err((400, reason)) if reason == "unknown grant"),
            "the stand-in refuses unknown grant {request_id:?} for {who}: {result:?}"
        );
    }

    fn assert_not_live(result: &Result<Value, (u16, String)>, life_name: &str, message: &str) {
        let expected = format!("grant is not live: {life_name}");
        assert!(
            matches!(
                result,
                Err((400, reason))
                    if reason.starts_with("grant is not live:")
                        && reason.contains(life_name)
                        && reason == &expected
            ),
            "{message}: {result:?}"
        );
    }

    fn assert_wrong_capsule(
        result: &Result<Value, (u16, String)>,
        grant_session: &str,
        caller_session: Option<&str>,
        message: &str,
    ) {
        assert!(
            matches!(
                result,
                Err((403, reason))
                    if reason.contains("wrong capsule")
                        && reason.contains(grant_session)
                        && caller_session.is_none_or(|session_id| reason.contains(session_id))
            ),
            "{message}: {result:?}"
        );
    }

    #[test]
    fn standin_sibling_cannot_use_the_grant() {
        let mut standin = StandIn::new();
        let (owner_id, sibling_id) = launch_two_running_ids(&mut standin);
        let owner = Caller::Client {
            session_id: &owner_id,
        };
        let sibling = Caller::Client {
            session_id: &sibling_id,
        };
        let requested = standin
            .post_capability_request(owner, &request_client_body())
            .expect("the stand-in stores the owner's pending request");
        let request_id = requested["request_id"]
            .as_str()
            .expect("the stand-in names the request")
            .to_owned();
        assert_eq!(
            request_id, "request-1",
            "the stand-in did the work: the request route names request-1"
        );
        // Ids are the stand-in's own sequence. Possession of one grants
        // nothing, and a guess that matches no record names nothing.
        for guessed in ["req-0", "request-0", "request-2", ""] {
            let refused =
                standin.post_capability_validate(sibling, &json!({ "request_id": guessed }));
            assert_unknown(&refused, guessed, "sibling");
        }
        let guessed_grant =
            standin.post_capability_grant(sibling, &json!({ "request_id": request_id }));
        assert!(
            matches!(&guessed_grant, Err((403, reason)) if reason == "This endpoint requires shell privileges"),
            "the stand-in refuses a sibling grant of the owner's request id: {guessed_grant:?}"
        );
        assert!(
            standin.grants.is_empty(),
            "the stand-in stores no grant after a sibling tried to grant the owner's request"
        );
        let granted = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({ "request_id": request_id, "duration": "once" }),
            )
            .expect("the stand-in shell grants the owner's request");
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in answers success true for the shell grant"
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from([request_id.clone()]),
            "the stand-in lists exactly the one live grant"
        );
        assert_eq!(
            plain["capabilities"][0]["session_id"], owner_id,
            "the stand-in binds that grant to the requester"
        );
        let sibling_list = standin
            .get_capability_list(sibling, None)
            .expect("the stand-in client view");
        assert_eq!(
            request_ids(&sibling_list),
            BTreeSet::new(),
            "the stand-in client list for the sibling is empty"
        );
        let refused =
            standin.post_capability_validate(sibling, &json!({ "request_id": request_id }));
        assert_wrong_capsule(
            &refused,
            &owner_id,
            Some(&sibling_id),
            "the stand-in refuses the requester's grant for its sibling resident",
        );
        assert_eq!(
            grant_record(&standin, &request_id),
            (Life::Live, false),
            "the stand-in did the work: the sibling refusal spends nothing"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from([request_id.clone()]),
            "the stand-in did the work: the refused sibling leaves the grant in the live view"
        );
        let owner_use =
            standin.post_capability_validate(owner, &json!({ "request_id": request_id }));
        assert!(
            owner_use.is_ok(),
            "the stand-in authorises the owning client: {owner_use:?}"
        );
        assert_capsule(
            &standin,
            &owner_id,
            "running",
            "",
            "the stand-in leaves the requester running",
        );
        assert_capsule(
            &standin,
            &sibling_id,
            "running",
            "",
            "the stand-in leaves the sibling running",
        );
        assert_eq!(
            grant_record(&standin, &request_id),
            (Life::Exhausted, false),
            "the stand-in did the work: the owner's one use stores Exhausted"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::new(),
            "the stand-in did the work: the live view omits the spent grant"
        );
    }

    #[test]
    fn standin_use_path_spends_one_once_grant_and_refuses_the_second() {
        let mut standin = StandIn::new();
        let (owner_id, sibling_id) = launch_two_running_ids(&mut standin);
        let owner = Caller::Client {
            session_id: &owner_id,
        };
        let sibling = Caller::Client {
            session_id: &sibling_id,
        };
        let posted = standin
            .post_capability_request(owner, &request_client_body())
            .expect("the agent route stores its pending request");
        let request_id = posted["request_id"]
            .as_str()
            .expect("the stand-in names the request")
            .to_owned();
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({ "request_id": request_id, "duration": "once" }),
            )
            .expect("the shell grants the pending request once");
        assert_eq!(
            grant_record(&standin, &request_id),
            (Life::Live, false),
            "the stand-in stores the once grant live"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from([request_id.clone()]),
            "the stand-in lists the once grant live before its use"
        );

        let sibling_use =
            standin.post_capability_validate(sibling, &json!({ "request_id": request_id.clone() }));
        assert_wrong_capsule(
            &sibling_use,
            &owner_id,
            Some(&sibling_id),
            "the use route refuses the sibling resident of the once grant",
        );
        let shell_use =
            standin.post_capability_validate(Caller::Shell, &json!({ "request_id": request_id }));
        assert_delete(
            &shell_use,
            403,
            "capability validate needs an instance session",
            "the use route refuses a shell before the body is read",
        );
        assert_eq!(
            grant_record(&standin, &request_id),
            (Life::Live, false),
            "the stand-in did the work: the two refusals spend nothing"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from([request_id.clone()]),
            "the stand-in did the work: the two refusals leave the once grant live"
        );

        let first_use =
            standin.post_capability_validate(owner, &json!({ "request_id": request_id.clone() }));
        assert_eq!(
            first_use,
            Ok(json!({ "valid": true })),
            "the use route authorises the owner's one use"
        );
        assert_eq!(
            grant_record(&standin, &request_id),
            (Life::Exhausted, false),
            "the stand-in did the work: the owner's one use stores Exhausted"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::new(),
            "the stand-in omits the spent once grant from the live view"
        );

        let second_use =
            standin.post_capability_validate(owner, &json!({ "request_id": request_id }));
        assert_not_live(
            &second_use,
            "Exhausted",
            "the use route refuses the second use of the spent once grant",
        );
        assert_eq!(
            grant_record(&standin, &request_id),
            (Life::Exhausted, false),
            "the stand-in keeps the spent life after the refused second use"
        );
        for id in [&owner_id, &sibling_id] {
            assert_capsule(
                &standin,
                id,
                "running",
                "",
                "the stand-in leaves both residents running through the use path",
            );
        }
    }

    #[test]
    fn standin_validate_refuses_a_malformed_body_without_spending() {
        let mut standin = StandIn::new();
        let (owner_id, _sibling_id) = launch_two_running_ids(&mut standin);
        let pending = standin
            .post_capability_request(
                Caller::Client {
                    session_id: &owner_id,
                },
                &json!({ "resource": SHARED_RESOURCE, "action": "read", "reason": "read shared" }),
            )
            .expect("the stand-in stores the guest request");
        let request_id = pending["request_id"]
            .as_str()
            .expect("the stand-in names the request")
            .to_owned();
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({ "request_id": request_id, "duration": "once" }),
            )
            .expect("the shell grants the pending request once");
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::from([request_id.clone()]),
            "the stand-in did the work: the live view lists the granted once request"
        );
        let owner = Caller::Client {
            session_id: &owner_id,
        };
        let attempts = [
            (
                json!({ "request_id": request_id, "extra": true }),
                "validate body rejects extra",
                "the stand-in refuses a body with an extra key",
            ),
            (
                json!({}),
                "validate body needs request_id",
                "the stand-in refuses a body with no request_id",
            ),
            (
                json!({ "request_id": 1 }),
                "validate request_id must be a string",
                "the stand-in refuses a non-string request_id",
            ),
        ];
        for (body, reason, message) in attempts {
            let refused = standin.post_capability_validate(owner, &body);
            assert_delete(&refused, 400, reason, message);
            assert_eq!(
                grant_record(&standin, &request_id),
                (Life::Live, false),
                "{message}: the refusal spends nothing"
            );
            assert_eq!(
                request_ids(&shell_pair(&standin).0),
                BTreeSet::from([request_id.clone()]),
                "{message}: the live view still lists the once grant"
            );
            assert_capsule(
                &standin,
                "component-1",
                "running",
                "",
                &format!("{message}: the owner instance keeps running"),
            );
        }
        let spent = standin.post_capability_validate(owner, &json!({ "request_id": request_id }));
        assert!(
            spent.is_ok(),
            "the stand-in did the work: the owner spends the once grant after the refusals: {spent:?}"
        );
        assert_eq!(
            grant_record(&standin, &request_id),
            (Life::Exhausted, false),
            "the stand-in did the work: that one use stores Exhausted"
        );
        assert_eq!(
            request_ids(&shell_pair(&standin).0),
            BTreeSet::new(),
            "the stand-in did the work: the spent once grant leaves the live view"
        );
        let again = standin.post_capability_validate(owner, &json!({ "request_id": request_id }));
        assert_not_live(
            &again,
            "Exhausted",
            "the stand-in did the work: the spent grant is not live for a second use",
        );
    }

    #[test]
    fn standin_stop_clears_that_sessions_grant() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        launch_two_running(&shared, &mut standin);
        seed_at(&mut standin, "req-1", "component-1", Life::Live);
        seed_at(&mut standin, "req-2", "component-2", Life::Live);
        let stopped = standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1");
        assert!(
            stopped.is_null(),
            "the stand-in answers null when it stops one instance"
        );
        let owner = standin.post_capability_validate(
            Caller::Client {
                session_id: "component-1",
            },
            &json!({ "request_id": "req-1" }),
        );
        assert_not_live(
            &owner,
            "Revoked",
            "the stand-in refuses the stopped session's grant",
        );
        let (plain, query) = shell_pair(&standin);
        assert_eq!(
            plain, query,
            "the stand-in returns one shell body for both route forms"
        );
        assert_eq!(
            request_ids(&plain),
            BTreeSet::from(["req-2".to_owned()]),
            "the stand-in lists exactly the sibling grant"
        );
        let sibling_own = standin.post_capability_validate(
            Caller::Client {
                session_id: "component-2",
            },
            &json!({ "request_id": "req-2" }),
        );
        assert!(
            sibling_own.is_ok(),
            "the stand-in authorises instance 2's own grant: {sibling_own:?}"
        );
        let sibling_other = standin.post_capability_validate(
            Caller::Client {
                session_id: "component-2",
            },
            &json!({ "request_id": "req-1" }),
        );
        assert_not_live(
            &sibling_other,
            "Revoked",
            "the stand-in refuses the stopped grant before the caller check",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in leaves instance 2 running",
        );
    }

    #[test]
    fn standin_authorise_unknown_grant() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-1",
            "component-1",
            "res",
            "read",
            "once",
            1,
            Life::Live,
            false,
        );
        let callers = [
            (
                "owner",
                Caller::Client {
                    session_id: "component-1",
                },
            ),
            (
                "sibling",
                Caller::Client {
                    session_id: "component-2",
                },
            ),
        ];
        for (who, caller) in callers {
            for request_id in ["", "req-missing"] {
                let result =
                    standin.post_capability_validate(caller, &json!({ "request_id": request_id }));
                assert_unknown(&result, request_id, who);
            }
        }
        let owner = standin.post_capability_validate(
            Caller::Client {
                session_id: "component-1",
            },
            &json!({ "request_id": "req-1" }),
        );
        assert!(
            owner.is_ok(),
            "the stand-in authorises the owning client of a known live grant: {owner:?}"
        );
        let shell =
            standin.post_capability_validate(Caller::Shell, &json!({ "request_id": "req-1" }));
        assert_delete(
            &shell,
            403,
            "capability validate needs an instance session",
            "the stand-in refuses a shell before it reads the use body",
        );
    }

    #[test]
    fn standin_authorise_dead_grants() {
        let mut standin = StandIn::new();
        let rows = [
            ("req-exhausted", Life::Exhausted, "Exhausted"),
            ("req-revoked", Life::Revoked, "Revoked"),
            ("req-expired", Life::Expired, "Expired"),
        ];
        for (request_id, life, _) in rows {
            standin.seed_grant(
                request_id,
                "component-1",
                "res",
                "read",
                "once",
                1,
                life,
                false,
            );
        }
        let callers = [
            Caller::Client {
                session_id: "component-1",
            },
            Caller::Client {
                session_id: "component-2",
            },
        ];
        for (request_id, life, life_name) in rows {
            for caller in callers {
                let result =
                    standin.post_capability_validate(caller, &json!({ "request_id": request_id }));
                assert_not_live(
                    &result,
                    life_name,
                    "the stand-in refuses a grant that is not live before the caller check",
                );
            }
            assert_eq!(
                grant_record(&standin, request_id),
                (life, false),
                "the stand-in leaves a {life_name} grant unchanged"
            );
        }
    }

    /// Finding 3 of the Cursor review: `create_storage` and
    /// `confirm_storage` name no Home. Each takes the one Home `set_home`
    /// named, so after `set_home(A)` no caller can create a file under `B`,
    /// and the file lands under `A` with `B` left empty.
    #[test]
    fn standin_storage_lands_under_the_home_set_home_named() {
        use crate::harness::ThrowawayHome;

        let home = ThrowawayHome::new().expect("a throwaway Home for the Home binding row");
        let other = ThrowawayHome::new().expect("a second throwaway Home for the Home binding row");
        let mut standin = StandIn::new();
        standin.set_home(home.home());
        standin
            .create_storage("notes.txt")
            .expect("the stand-in creates the file under the selected Home");
        assert_eq!(
            standin.confirm_storage("notes.txt"),
            Ok(()),
            "the stand-in did the work: the check reads the same selected Home"
        );
        let under = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");
        assert!(
            std::fs::read(under.join("notes.txt")).is_ok(),
            "the stand-in did the work: the file lands under the Home set_home named"
        );
        let elsewhere = StandIn::storage_for_home(other.home())
            .expect("the stand-in returns the other Home's storage path");
        assert!(
            !elsewhere.exists(),
            "the stand-in did the work: nothing is created under another Home"
        );
        // A stand-in with no `set_home` has no Home to use.
        let mut unset = StandIn::new();
        assert_eq!(
            unset.create_storage("notes.txt"),
            Err((400, "storage needs a selected Home".to_owned())),
            "the stand-in did the work: a creation without a selected Home is refused"
        );
        home.finish().expect("the throwaway Home finishes");
        other.finish().expect("the second throwaway Home finishes");
    }

    #[test]
    fn standin_storage_follows_the_selected_home() {
        use crate::harness::ThrowawayHome;

        let first = ThrowawayHome::new().expect("a throwaway Home for the first storage row");
        let second = ThrowawayHome::new().expect("a throwaway Home for the second storage row");
        let mut paths = Vec::new();
        for home in [&first, &second] {
            let storage = StandIn::storage_for_home(home.home())
                .expect("the stand-in follows the selected Home's data directory");
            assert_eq!(
                storage,
                home.data().join("storage"),
                "the stand-in returns the selected Home's data directory plus storage"
            );
            assert!(
                !storage.exists(),
                "the stand-in returns that path and creates no storage directory"
            );
            paths.push(storage);
        }
        assert_ne!(
            paths[0], paths[1],
            "the stand-in gives two selected Homes two storage directories"
        );
        let again = StandIn::storage_for_home(first.home())
            .expect("the stand-in follows a selected Home on a second call");
        assert_eq!(
            again, paths[0],
            "the stand-in returns one directory for one selected Home"
        );
        first.finish().expect("the first throwaway Home finishes");
        second.finish().expect("the second throwaway Home finishes");

        for (home, text) in [
            ("", "an empty Home"),
            ("standin-a9", "a relative Home"),
            ("/var/standin-a9/../other", "a Home with a parent component"),
        ] {
            let refused = StandIn::storage_for_home(Path::new(home));
            assert!(
                matches!(&refused, Err((400, reason)) if reason == "storage needs a selected Home"),
                "the stand-in refuses {text} and names the missing selected Home: {refused:?}"
            );
        }
    }

    #[test]
    fn standin_shared_temp_storage_is_refused() {
        let shared = Path::new("/tmp/elastos/storage");
        let existed = shared.exists();
        let refused = StandIn::storage_for_home(shared);
        assert!(
            matches!(&refused, Err((400, reason)) if reason == "shared temp directory is not agent storage"),
            "the stand-in refuses the fixed shared temp path before the Home rule: {refused:?}"
        );
        assert_eq!(
            shared.exists(),
            existed,
            "the stand-in creates nothing at the shared temp path"
        );
    }

    #[test]
    fn standin_shell_cannot_authorise() {
        let mut standin = StandIn::new();
        standin.seed_grant(
            "req-1",
            "component-1",
            "res",
            "read",
            "once",
            1,
            Life::Live,
            false,
        );
        let shell =
            standin.post_capability_validate(Caller::Shell, &json!({ "request_id": "req-1" }));
        assert_delete(
            &shell,
            403,
            "capability validate needs an instance session",
            "the stand-in refuses a shell presentation of a live grant",
        );
        let owner = standin.post_capability_validate(
            Caller::Client {
                session_id: "component-1",
            },
            &json!({ "request_id": "req-1" }),
        );
        assert!(
            owner.is_ok(),
            "the stand-in authorises the owning client of that live grant: {owner:?}"
        );
    }

    #[test]
    fn standin_storage_refuses_root_symlink_swap() {
        use crate::harness::ThrowawayHome;
        use std::os::unix::fs::symlink;

        let home = ThrowawayHome::new().expect("a throwaway Home for the root symlink row");
        let storage = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");
        let mut standin = StandIn::new();
        standin.set_home(home.home());

        // The data directory itself is a symbolic link: the walk's first
        // step fails and nothing under the link is created or read.
        let elsewhere = home.home().join("swapped-root");
        std::fs::create_dir(&elsewhere).expect("the test makes another directory");
        std::fs::remove_dir_all(home.data()).expect("the test removes the empty data directory");
        symlink(&elsewhere, home.data()).expect("the test makes the data directory a link");
        assert_eq!(
            standin.confirm_storage(""),
            Err((400, LINK_REASON.to_owned())),
            "the stand-in did the work: it refuses a data directory that is a symbolic link"
        );
        assert_eq!(
            std::fs::read_dir(&elsewhere)
                .expect("the linked directory stays readable")
                .count(),
            0,
            "the stand-in did the work: it creates nothing through the data link"
        );
        std::fs::remove_file(home.data()).expect("the test removes the data link");
        std::fs::create_dir_all(home.data()).expect("the test makes the data directory again");

        assert_eq!(
            standin.confirm_storage(""),
            Ok(()),
            "the stand-in did the work: it accepts the absent storage directory before a link"
        );
        assert!(
            !storage.exists(),
            "the stand-in did the work: it creates no storage directory"
        );

        symlink(&elsewhere, &storage).expect("the test makes the storage path a symbolic link");
        assert_eq!(
            standin.confirm_storage(""),
            Err((400, LINK_REASON.to_owned())),
            "the stand-in did the work: it refuses a storage directory that is a symbolic link"
        );
        let meta =
            std::fs::symlink_metadata(&storage).expect("the storage path is still a symbolic link");
        assert!(
            meta.file_type().is_symlink(),
            "the stand-in did the work: it does not follow the storage link"
        );
        assert_eq!(
            std::fs::read_dir(&elsewhere)
                .expect("the linked directory stays readable")
                .count(),
            0,
            "the stand-in did the work: it creates nothing through the link"
        );
        home.finish().expect("the throwaway Home finishes");
    }

    /// Task 112, M1 check A9: every step from the Home down is opened one
    /// component at a time with `O_NOFOLLOW`, so a symbolic link at an
    /// INTERMEDIATE step is refused and not followed. One multi-component
    /// `openat` on the data path, or a walk that drops `O_NOFOLLOW` on an
    /// intermediate step, follows `Home/x` into the outside directory and
    /// turns this test red at the first assertion below.
    #[test]
    fn standin_storage_refuses_an_intermediate_symlink_step() {
        use crate::harness::ThrowawayHome;
        use std::os::unix::fs::symlink;

        let home = ThrowawayHome::new().expect("a throwaway Home for the intermediate link row");
        let mut standin = StandIn::new();
        standin.set_home(home.home());
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = launch_finished(&shared, &mut standin);
        assert!(!id.is_empty(), "the launched instance names its session");
        let storage = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");

        // The first step below the Home is a link to an outside directory
        // that really exists and really holds a file.
        let outside = home.root().join("outside");
        std::fs::create_dir(&outside).expect("the test makes the outside directory");
        std::fs::write(outside.join("notes.txt"), b"outside bytes")
            .expect("the test writes the outside file");
        let step = home
            .data()
            .strip_prefix(home.home())
            .unwrap()
            .components()
            .next()
            .unwrap();
        let linked = home.home().join(step.as_os_str());
        std::fs::remove_dir_all(&linked).expect("the test removes the real first step");
        symlink(&outside, &linked).expect("the test makes the first step a link");
        let before =
            std::fs::read(outside.join("notes.txt")).expect("the outside file stays readable");

        assert_eq!(
            standin.create_storage("notes.txt"),
            Err((400, LINK_REASON.to_owned())),
            "the stand-in did the work: it refuses an intermediate link step"
        );
        assert_eq!(
            standin.confirm_storage("notes.txt"),
            Err((400, LINK_REASON.to_owned())),
            "the stand-in did the work: the check refuses that link step too"
        );
        assert_eq!(
            std::fs::read(outside.join("notes.txt")).expect("the outside file stays readable"),
            before,
            "the stand-in did the work: the outside file is unchanged"
        );
        let mut names = std::fs::read_dir(&outside)
            .expect("the outside directory stays readable")
            .map(|entry| entry.expect("the outside entry reads").file_name())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("notes.txt")],
            "the stand-in did the work: it creates nothing outside"
        );

        // Restore the real step: the route then works, so the refusal above
        // came from the link step and nothing else.
        std::fs::remove_file(&linked).expect("the test removes the link");
        std::fs::create_dir(&linked).expect("the test makes the real first step again");
        assert_eq!(
            standin.create_storage("notes.txt"),
            Ok(()),
            "the stand-in did the work: the real step accepts the file"
        );
        assert!(
            storage.join("notes.txt").is_file(),
            "the file lands under the Home"
        );
        home.finish().expect("the throwaway Home finishes");
    }

    /// Task 112, M1 check A9: an absent storage directory is its own case
    /// with its own reason. A read needs the directory and says so; a read
    /// never falls back to the "not created" file reason for a missing
    /// directory.
    #[test]
    fn standin_storage_read_refuses_an_absent_storage_directory() {
        use crate::harness::ThrowawayHome;

        let home = ThrowawayHome::new().expect("a throwaway Home for the absent directory row");
        let mut standin = StandIn::new();
        standin.set_home(home.home());
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = launch_finished(&shared, &mut standin);
        let agent = Caller::Client { session_id: &id };
        let storage = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");
        assert!(
            !storage.exists(),
            "the test starts with no storage directory"
        );

        assert_eq!(
            standin.read_storage(agent, "notes.txt"),
            Err((400, MISSING_STORAGE_REASON.to_owned())),
            "the stand-in did the work: an absent storage directory has its own reason"
        );
        assert_eq!(
            standin.write_storage(agent, "notes.txt", b"bytes"),
            Err((400, MISSING_STORAGE_REASON.to_owned())),
            "the stand-in did the work: a write says the directory is absent too"
        );
        assert!(
            !storage.exists(),
            "the stand-in did the work: the refusal creates no directory"
        );
        home.finish().expect("the throwaway Home finishes");
    }

    #[test]
    fn standin_storage_refuses_parent_symlink_after_selection() {
        use crate::harness::ThrowawayHome;
        use std::os::unix::fs::symlink;

        let home = ThrowawayHome::new().expect("a throwaway Home for the parent swap row");
        let mut standin = StandIn::new();
        standin.set_home(home.home());
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = launch_finished(&shared, &mut standin);
        let agent = Caller::Client { session_id: &id };
        standin
            .create_storage("notes.txt")
            .expect("the stand-in creates agent 1's file");
        assert_eq!(
            standin.write_storage(agent, "notes.txt", b"agent 1 bytes"),
            Ok(()),
            "the stand-in did the work: agent 1 writes its own file"
        );
        let storage = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");
        let saved = home.home().join("saved-storage");
        std::fs::rename(&storage, &saved).expect("the test moves agent 1's storage aside");
        let outside = home.home().join("outside");
        std::fs::create_dir_all(&outside).expect("the test makes an outside directory");
        std::fs::write(outside.join("notes.txt"), b"outside bytes")
            .expect("the test writes the outside file");
        symlink(&outside, &storage).expect("the test makes the storage path a symbolic link");
        assert_eq!(
            standin.read_storage(agent, "notes.txt"),
            Err((400, LINK_REASON.to_owned())),
            "the stand-in did the work: the read refuses the swapped parent"
        );
        assert_eq!(
            standin.write_storage(agent, "notes.txt", b"crossed"),
            Err((400, LINK_REASON.to_owned())),
            "the stand-in did the work: the write refuses the swapped parent"
        );
        assert_eq!(
            std::fs::read(outside.join("notes.txt")).expect("the outside file stays readable"),
            b"outside bytes",
            "the stand-in did the work: the outside file is unchanged"
        );
        assert_eq!(
            std::fs::read(saved.join("notes.txt")).expect("agent 1's file stays readable"),
            b"agent 1 bytes",
            "the stand-in did the work: agent 1's own file is unchanged"
        );
        home.finish().expect("the throwaway Home finishes");
    }

    /// Task 112, M1 check A9: `set_home` opens the Home once and every
    /// storage call walks from that held handle, so an ancestor swapped AFTER
    /// startup is not followed: no call opens the Home by path again. Stage 1
    /// swaps `base` for a link, stage 2 renames the other tree's real `base`
    /// into its place. In both stages the creation succeeds in the ORIGINAL
    /// tree (the moved `scratch/real-base`) and the other tree is unchanged.
    /// Re-opening the Home by a `/` walk inside `storage_directory` turns
    /// stage 2 red at its `create_storage` assertion, because that walk
    /// follows the real directory now named `base` and creates the file
    /// under the other tree.
    #[test]
    fn standin_storage_holds_the_home_after_an_ancestor_swap() {
        use std::os::unix::fs::symlink;

        let scratch = TempDir::new().expect("a scratch directory for the ancestor swap row");
        let base = scratch.path().join("base");
        let real_base = scratch.path().join("real-base");
        let home = base.join("mid").join("holder").join("thehome");
        std::fs::create_dir_all(&home).expect("the test makes the real Home tree");
        let storage = StandIn::storage_for_home(&home)
            .expect("the stand-in returns the selected Home's storage path");
        let other = scratch.path().join("other");
        let other_home = other.join("mid").join("holder").join("thehome");
        let other_storage = StandIn::storage_for_home(&other_home)
            .expect("the stand-in returns the other Home's storage path");

        let mut standin = StandIn::new();
        standin.set_home(&home);
        assert_eq!(
            standin.create_storage("first.txt"),
            Ok(()),
            "the stand-in did the work: the real Home accepts the first file"
        );
        assert!(
            storage.join("first.txt").is_file(),
            "the first file lands under the Home"
        );

        // The other tree has the same shape, a real storage directory and a
        // real file, so the victim exists before the swap.
        std::fs::create_dir_all(&other_storage).expect("the test makes the other storage");
        std::fs::write(other_storage.join("notes.txt"), b"outside bytes")
            .expect("the test writes the other file");
        // The victim directory is held by handle before either swap, so the
        // assertions below see the same directory the stand-in could reach.
        let victim = std::fs::File::open(&other_storage).expect("the other storage stays readable");

        // Stage 1: `base` becomes a symbolic link to the other tree.
        std::fs::rename(&base, &real_base).expect("the test moves the real base aside");
        symlink(&other, &base).expect("the test makes the base an ancestor link");
        assert_eq!(
            standin.create_storage("second.txt"),
            Ok(()),
            "the stand-in did the work: a link on base after startup is not followed"
        );
        assert!(
            real_base
                .join(
                    storage
                        .strip_prefix(&base)
                        .expect("the storage path is under the base")
                )
                .join("second.txt")
                .is_file(),
            "the stand-in did the work: the second file lands in the original tree"
        );

        // Stage 2: the other tree's REAL base is renamed into `base`'s place,
        // so only a fresh open of the Home path reaches it.
        std::fs::remove_file(&base).expect("the test removes the base link");
        std::fs::rename(&other, &base).expect("the test renames the other real base in");
        assert_eq!(
            standin.create_storage("third.txt"),
            Ok(()),
            "the stand-in did the work: a real base renamed in after startup is not entered"
        );
        assert!(
            real_base
                .join(
                    storage
                        .strip_prefix(&base)
                        .expect("the storage path is under the base")
                )
                .join("third.txt")
                .is_file(),
            "the stand-in did the work: the third file lands in the original tree"
        );

        // The other tree is checked through its own directory handle, opened
        // once here, so the assertion sees the directory the rename put at
        // `base`, whatever `base` names now. It holds one name, and the file
        // read through that handle keeps its bytes.
        use std::os::fd::AsFd;
        use std::os::unix::ffi::OsStrExt;
        // The directory is listed through its handle with rustix, which works
        // on every Unix target; a `/proc/self/fd` or `/dev/fd` path would need
        // Linux or would re-open a path.
        let mut held_dir =
            rustix::fs::Dir::read_from(victim.as_fd()).expect("the other storage lists");
        let mut names = Vec::new();
        while let Some(entry) = held_dir.read() {
            let entry = entry.expect("the other entry reads");
            let name = entry.file_name();
            if name == c"." || name == c".." {
                continue;
            }
            names.push(Path::new(std::ffi::OsStr::from_bytes(name.to_bytes())).to_owned());
        }
        names.sort();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("notes.txt")],
            "the stand-in did the work: it creates nothing in the other tree"
        );
        let held = rustix::fs::openat(
            victim.as_fd(),
            "notes.txt",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("the other file opens on the held handle");
        let mut kept = Vec::new();
        std::io::Read::read_to_end(&mut std::fs::File::from(held), &mut kept)
            .expect("the other file reads");
        assert_eq!(
            kept, b"outside bytes",
            "the stand-in did the work: the other file is unchanged"
        );
    }

    /// Task 112, M1 check A9, K5 ruling: the Home's ancestors are resolved
    /// once, at holder creation, so a Home under a linked ancestor (macOS
    /// `/var -> /private/var`) is accepted. The Home itself must not be a
    /// link, and no later call opens the Home by path. `scratch/link` points
    /// at `scratch/real`; the Home is `scratch/link/home` and its storage
    /// directory is created through it. A walk from `/` with `O_NOFOLLOW`
    /// per component refuses `link` and turns this red at its first
    /// `create_storage` assertion.
    #[test]
    fn standin_storage_follows_a_linked_ancestor_once_at_set_home() {
        use std::os::unix::fs::symlink;

        let scratch = TempDir::new().expect("a scratch directory for the linked ancestor row");
        let real = scratch.path().join("real");
        let link = scratch.path().join("link");
        std::fs::create_dir(&real).expect("the test makes the real ancestor");
        symlink(&real, &link).expect("the test makes the ancestor a symbolic link");
        let home = link.join("home");
        std::fs::create_dir(&home).expect("the test makes the Home through the link");
        let linked_storage = StandIn::storage_for_home(&home)
            .expect("the stand-in returns the selected Home's storage path");
        assert!(
            !linked_storage.exists(),
            "the test starts with no storage directory"
        );

        let mut standin = StandIn::new();
        standin.set_home(&home);
        assert_eq!(
            standin.create_storage("a.txt"),
            Ok(()),
            "the stand-in did the work: a linked ancestor is resolved once and accepted"
        );
        assert!(
            real.join("home")
                .join(
                    linked_storage
                        .strip_prefix(&home)
                        .expect("the storage path is under the Home")
                )
                .join("a.txt")
                .is_file(),
            "the stand-in did the work: the file lands in the real tree through the link"
        );
        assert_eq!(
            std::fs::read_dir(&linked_storage)
                .expect("the storage directory lists")
                .map(|entry| entry.expect("the entry reads").file_name())
                .collect::<Vec<_>>(),
            vec![std::ffi::OsString::from("a.txt")],
            "the stand-in did the work: the storage directory holds the one created file"
        );
    }

    /// Task 112, M1 check A9, K6 fix: a Home must be absolute. A relative
    /// Home such as `a/b` would open `a` from the current directory, so it
    /// is refused with the data reason before any open. Dropping the
    /// `is_absolute` check turns this red.
    #[test]
    fn standin_storage_refuses_a_relative_home() {
        let scratch = TempDir::new().expect("a scratch directory for the relative Home row");
        let cwd = std::env::current_dir().expect("the test reads the current directory");
        assert_ne!(
            scratch
                .path()
                .canonicalize()
                .expect("the scratch path resolves"),
            cwd.canonicalize().expect("the current directory resolves"),
            "the test runs outside its scratch directory"
        );
        let relative = Path::new("a/b");

        let mut standin = StandIn::new();
        standin.set_home(relative);
        assert_eq!(
            standin.create_storage("a.txt"),
            Err((400, DATA_REASON.to_owned())),
            "the stand-in did the work: a relative Home is refused"
        );
        assert_eq!(
            standin.confirm_storage("a.txt"),
            Err((400, DATA_REASON.to_owned())),
            "the stand-in did the work: the check refuses a relative Home too"
        );
        assert!(
            !cwd.join("a").exists(),
            "the stand-in did the work: nothing is created from the current directory"
        );
    }

    /// Task 112, M1 check A9, K5 ruling: the Home ITSELF is still refused
    /// when it is a symbolic link, even to a real directory. Ancestors are
    /// resolved once; the Home's own final component is opened with
    /// `O_NOFOLLOW`. Dropping `O_NOFOLLOW` on that step turns this red.
    #[test]
    fn standin_storage_refuses_a_home_that_is_itself_a_symlink() {
        use std::os::unix::fs::symlink;

        let scratch = TempDir::new().expect("a scratch directory for the Home link row");
        let real = scratch.path().join("real-home");
        let link = scratch.path().join("home-link");
        std::fs::create_dir(&real).expect("the test makes the real Home");
        symlink(&real, &link).expect("the test makes the Home a symbolic link");
        let storage = StandIn::storage_for_home(&link)
            .expect("the stand-in returns the selected Home's storage path");

        let mut standin = StandIn::new();
        standin.set_home(&link);
        assert_eq!(
            standin.create_storage("a.txt"),
            Err((400, LINK_REASON.to_owned())),
            "the stand-in did the work: a Home that is itself a link is refused"
        );
        assert!(
            !storage.exists() && !real.join("storage").exists(),
            "the stand-in did the work: nothing is created under the linked Home"
        );
    }

    #[test]
    fn standin_storage_refuses_a_file_it_did_not_create() {
        use crate::harness::ThrowawayHome;
        use std::os::unix::fs::PermissionsExt;

        let home = ThrowawayHome::new().expect("a throwaway Home for the outsider row");
        let mut standin = StandIn::new();
        standin.set_home(home.home());
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = launch_finished(&shared, &mut standin);
        let storage = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");
        std::fs::create_dir_all(&storage).expect("the test creates the storage directory");
        let entry = storage.join("outsider.txt");
        std::fs::write(&entry, b"outside bytes")
            .expect("the test writes one regular file the stand-in did not create");
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o444))
            .expect("the test makes the outsider file read-only");
        assert_eq!(
            standin.confirm_storage("outsider.txt"),
            Err((400, NOT_CREATED_REASON.to_owned())),
            "the stand-in did the work: it refuses a file it did not create"
        );
        assert_eq!(
            standin.write_storage(
                Caller::Client { session_id: &id },
                "outsider.txt",
                b"crossed"
            ),
            Err((400, NOT_CREATED_REASON.to_owned())),
            "the stand-in did the work: a write route refuses that file too"
        );
        assert_eq!(
            std::fs::read(&entry).expect("the outsider file stays readable"),
            b"outside bytes",
            "the stand-in did the work: it leaves the outsider file unchanged"
        );
        for name in ["..", "a/b"] {
            assert_eq!(
                standin.confirm_storage(name),
                Err((400, ENTRY_REASON.to_owned())),
                "the stand-in did the work: entry {name:?} keeps its own rule"
            );
        }
        home.finish().expect("the throwaway Home finishes");
    }

    /// Falsifier 1 of the A9 ruling, identity form: the recorded name is
    /// replaced by a different regular file with exactly one link, so only
    /// the recorded `(st_dev, st_ino)` pair catches the swap. Removing that
    /// compare turns this test red.
    #[test]
    fn standin_storage_refuses_a_replaced_file_at_the_recorded_name() {
        use crate::harness::ThrowawayHome;

        let home = ThrowawayHome::new().expect("a throwaway Home for the swap row");
        let mut standin = StandIn::new();
        standin.set_home(home.home());
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = launch_finished(&shared, &mut standin);
        let agent = Caller::Client { session_id: &id };
        standin
            .create_storage("notes.txt")
            .expect("the stand-in creates agent 1's file");
        assert_eq!(
            standin.write_storage(agent, "notes.txt", b"agent 1 bytes"),
            Ok(()),
            "the stand-in did the work: agent 1 writes its own file"
        );
        let storage = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");
        let entry = storage.join("notes.txt");
        // A different regular file with exactly one link takes the name, so
        // the type and link-count checks both pass and only the recorded pair
        // shows the swap.
        let outsider = home.home().join("outsider.txt");
        std::fs::write(&outsider, b"outsider bytes").expect("the test writes a different file");
        std::fs::rename(&outsider, &entry).expect("the test puts it at the recorded name");
        let stat = rustix::fs::fstat(
            std::fs::File::open(&entry).expect("the swapped file stays readable"),
        )
        .expect("the swapped file has a status");
        assert_eq!(
            stat.st_nlink, 1,
            "the test did the work: the swapped file has one link"
        );
        assert_eq!(
            standin.read_storage(agent, "notes.txt"),
            Err((400, SWAPPED_REASON.to_owned())),
            "the stand-in did the work: the recorded pair is the file it created"
        );
        assert_eq!(
            std::fs::read(&entry).expect("the swapped file stays readable"),
            b"outsider bytes",
            "the stand-in did the work: it reads neither file and repairs nothing"
        );
        home.finish().expect("the throwaway Home finishes");
    }

    /// Falsifier 2 of the A9 ruling, link form: a file whose only name is
    /// gone, so its link count is 0, was refused by the `st_nlink` check at
    /// 0cca42a3 only when the name was still present (a file it did not
    /// create, or a file whose pair was still recorded). This test now
    /// proves the recorded-input refusal it can reach here, and the link
    /// rule itself is proven on both paths by
    /// `standin_storage_refuses_a_second_link` (read) and
    /// `standin_storage_create_refuses_a_second_link` (create). A host that
    /// allows `open_by_handle_at` reaches the no-link inode itself and gets
    /// `NOT_ONE_LINK_REASON`; this host refuses that call, so it reports
    /// SKIP for that part and gives the `st_nlink` rule no credit there.
    #[test]
    fn standin_storage_refuses_a_file_with_no_link_left() {
        use crate::harness::ThrowawayHome;

        let home = ThrowawayHome::new().expect("a throwaway Home for the no-link row");
        let mut standin = StandIn::new();
        standin.set_home(home.home());
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = launch_finished(&shared, &mut standin);
        let agent = Caller::Client { session_id: &id };
        standin
            .create_storage("notes.txt")
            .expect("the stand-in creates agent 1's file");
        assert_eq!(
            standin.write_storage(agent, "notes.txt", b"agent 1 bytes"),
            Ok(()),
            "the stand-in did the work: agent 1 writes its own file"
        );
        let storage = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");
        let entry = storage.join("notes.txt");
        // The test takes the recorded file's only name away. The bytes stay
        // on the test's own open handle and the inode has no link left.
        let held = std::fs::File::open(&entry).expect("the test opens the file first");
        std::fs::remove_file(&entry).expect("the test unlinks the only name");
        assert_eq!(
            rustix::fs::fstat(&held)
                .expect("the held handle has a status")
                .st_nlink,
            0,
            "the test did the work: the file kept open has no link left"
        );
        assert_eq!(
            standin.read_storage(agent, "notes.txt"),
            Err((400, NOT_CREATED_REASON.to_owned())),
            "the stand-in did the work: the recorded name is gone, so the record refuses first"
        );
        assert_eq!(
            rustix::fs::fstat(&held)
                .expect("the held handle has a status")
                .st_nlink,
            0,
            "the stand-in did the work: it restores no name for the refused file"
        );
        // A fresh file takes the name. It is regular with one link, so only
        // the recorded pair refuses it, and the stand-in reads neither file.
        std::fs::write(&entry, b"successor bytes").expect("the test puts a new file there");
        assert_eq!(
            standin.read_storage(agent, "notes.txt"),
            Err((400, SWAPPED_REASON.to_owned())),
            "the stand-in did the work: the record refuses the successor file"
        );
        assert_eq!(
            std::fs::read(&entry).expect("the successor file stays readable"),
            b"successor bytes",
            "the stand-in did the work: it reads neither file and repairs nothing"
        );
        // The file with no link keeps its own bytes: the stand-in repaired
        // nothing and wrote nothing.
        assert_eq!(
            rustix::fs::fstat(&held)
                .expect("the held handle has a status")
                .st_size,
            "agent 1 bytes".len() as i64,
            "the stand-in did the work: the file with no link keeps its bytes"
        );
        home.finish().expect("the throwaway Home finishes");
    }

    /// Falsifier 3 of the A9 ruling: a second name for the recorded file is
    /// refused by the `st_nlink == 1` check, not by the recorded pair (both
    /// names name the recorded inode), the link is not read through, and the
    /// recorded file keeps its bytes. Weakening that check to `> 1` turns
    /// this test red on this read path.
    #[test]
    fn standin_storage_refuses_a_second_link() {
        use crate::harness::ThrowawayHome;

        let home = ThrowawayHome::new().expect("a throwaway Home for the second link row");
        let mut standin = StandIn::new();
        standin.set_home(home.home());
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = launch_finished(&shared, &mut standin);
        let agent = Caller::Client { session_id: &id };
        standin
            .create_storage("notes.txt")
            .expect("the stand-in creates agent 1's file");
        assert_eq!(
            standin.write_storage(agent, "notes.txt", b"agent 1 bytes"),
            Ok(()),
            "the stand-in did the work: agent 1 writes its own file"
        );
        let storage = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");
        let entry = storage.join("notes.txt");
        let second = home.home().join("second-name.txt");
        std::fs::hard_link(&entry, &second).expect("the test makes a second name");
        assert_eq!(
            standin.read_storage(agent, "notes.txt"),
            Err((400, NOT_ONE_LINK_REASON.to_owned())),
            "the stand-in did the work: it refuses a recorded file with a second name"
        );
        assert_eq!(
            standin.write_storage(agent, "notes.txt", b"crossed"),
            Err((400, NOT_ONE_LINK_REASON.to_owned())),
            "the stand-in did the work: the write refuses it too"
        );
        assert_eq!(
            std::fs::read(&entry).expect("the recorded file stays readable"),
            b"agent 1 bytes",
            "the stand-in did the work: the recorded file keeps its bytes"
        );
        assert_eq!(
            std::fs::read(&second).expect("the second name stays readable"),
            b"agent 1 bytes",
            "the stand-in did the work: the second name keeps its bytes"
        );
        home.finish().expect("the throwaway Home finishes");
    }

    /// Falsifier 3 of the A9 ruling on the create path: the file this call
    /// made is refused by the same `st_nlink == 1` rule that `storage_file`
    /// uses, because a second name joined it between the open call and the
    /// `fstat`. The record stays empty, so a later read refuses the name as
    /// not created, and both names keep their empty bytes.
    ///
    /// Disabling the `st_nlink` rule turns this test red at its first
    /// assertion. The measured form is: delete this rule, because a rule
    /// written `stat.st_nlink > 1` left both second-name tests green at
    /// this head and is therefore not the `st_nlink == 1` rule.
    #[test]
    fn standin_storage_create_refuses_a_second_link() {
        use crate::harness::ThrowawayHome;

        let home = ThrowawayHome::new().expect("a throwaway Home for the create second link row");
        let mut standin = StandIn::new();
        standin.set_home(home.home());
        standin
            .create_storage("notes.txt")
            .expect("the stand-in creates its first file");
        // The test makes this name after that creation, so the next created
        // file joins it between the open call and the `fstat`.
        let joined = home.home().join("joined.txt");
        standin.join_next_create(&joined);
        assert_eq!(
            standin.create_storage("moved.txt"),
            Err((400, NOT_ONE_LINK_REASON.to_owned())),
            "the stand-in did the work: the file it just made is refused at the shared link rule"
        );
        let storage = StandIn::storage_for_home(home.home())
            .expect("the stand-in returns the selected Home's storage path");
        let made = storage.join("moved.txt");
        assert_eq!(
            rustix::fs::fstat(std::fs::File::open(&made).expect("the refused file stays readable"))
                .expect("the refused file has a status")
                .st_nlink,
            2,
            "the stand-in did the work: the refused file keeps both names"
        );
        for path in [&made, &joined] {
            assert_eq!(
                std::fs::read(path).expect("the refused file stays readable"),
                Vec::<u8>::new(),
                "the stand-in did the work: the refused file keeps its empty bytes"
            );
        }
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let id = launch_finished(&shared, &mut standin);
        assert_eq!(
            standin.read_storage(Caller::Client { session_id: &id }, "moved.txt"),
            Err((400, NOT_CREATED_REASON.to_owned())),
            "the stand-in did the work: a refused creation leaves no record"
        );
        home.finish().expect("the throwaway Home finishes");
    }

    fn request_client_body() -> Value {
        json!({
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
        })
    }

    fn assert_live_request_ids_empty(standin: &StandIn, message: &str) {
        let listed = standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in shell live-grant view");
        assert!(
            request_ids(&listed).is_empty(),
            "the stand-in did the work: {message}"
        );
    }

    #[test]
    fn standin_ended_instance_request_is_refused() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let first = launch_finished(&shared, &mut standin);
        let second = launch_finished(&shared, &mut standin);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("component-1", "component-2"),
            "the stand-in did the work: it numbers the two launches component-1 and component-2"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: it lists component-1 running before the stop",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it lists component-2 running before the stop",
        );
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 with the stop reason");
        let stopped = standin.post_capability_request(
            Caller::Client {
                session_id: "component-1",
            },
            &request_client_body(),
        );
        assert_eq!(
            stopped,
            Err((400, "instance is not live: stopped".to_owned())),
            "the stand-in did the work: it refuses a new request from the stopped instance"
        );
        assert_eq!(
            shell_requests(&standin, "component-1"),
            json!({ "requests": [] }),
            "the stand-in did the work: the stopped instance stores no request"
        );
        standin.set_instant(60);
        let after_instant = standin.post_capability_request(
            Caller::Client {
                session_id: "component-1",
            },
            &request_client_body(),
        );
        assert_eq!(
            after_instant,
            Err((400, "instance is not live: stopped".to_owned())),
            "the stand-in did the work: it refuses the stopped instance that left the list at instant 60"
        );
        assert_eq!(
            shell_requests(&standin, "component-1"),
            json!({ "requests": [] }),
            "the stand-in did the work: the stopped instance stores no request at instant 60"
        );

        let sibling = standin.post_capability_request(
            Caller::Client {
                session_id: "component-2",
            },
            &request_client_body(),
        );
        assert_eq!(
            sibling,
            Ok(json!({ "status": "pending", "request_id": "request-1" })),
            "the stand-in did the work: it answers pending and request-1 for the running sibling"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-1", "component-2")],
            "the stand-in did the work: it stores one pending request for component-2"
        );
        assert_live_request_ids_empty(
            &standin,
            "the request route stores no live grant for component-2",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it leaves component-2 running after the request",
        );

        let unknown = standin.post_capability_request(
            Caller::Client {
                session_id: "component-9",
            },
            &request_client_body(),
        );
        assert_eq!(
            unknown,
            Err((400, "unknown instance: component-9".to_owned())),
            "the stand-in did the work: it refuses a client whose instance is unknown"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("request-1", "component-2")],
            "the stand-in did the work: the unknown client leaves the sibling's request as it was"
        );

        let mut failed = StandIn::new();
        let failing_bundle = Shared::new();
        admit_shared(
            &failing_bundle,
            &mut failed,
            Start::Error("start refused".to_owned()),
        );
        let only = failing_bundle
            .launch(&mut failed)
            .expect("the stand-in launches the failing bundle once");
        assert_eq!(
            only["id"], "component-1",
            "the stand-in did the work: it numbers the only failing launch component-1"
        );
        failed
            .finish_start("component-1")
            .expect("the stand-in finishes the failing start");
        let refused = failed.post_capability_request(
            Caller::Client {
                session_id: "component-1",
            },
            &request_client_body(),
        );
        assert_eq!(
            refused,
            Err((400, "instance is not live: failed".to_owned())),
            "the stand-in did the work: it refuses a new request from the failed instance"
        );
        assert_eq!(
            shell_requests(&failed, "component-1"),
            json!({ "requests": [] }),
            "the stand-in did the work: the failed instance stores no request"
        );
        assert_eq!(
            shell_list(&failed),
            json!({
                "capsules": [{
                    "id": "component-1",
                    "name": SHARED_NAME,
                    "status": "failed",
                    "session_id": "component-1",
                    "cause": "start refused",
                }]
            }),
            "the stand-in did the work: it leaves the failed entry listed with its cause"
        );
    }

    #[test]
    fn standin_live_instance_request_stays_pending() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let launched = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launches once");
        assert_eq!(
            (launched["id"].as_str(), launched["status"].as_str()),
            (Some("component-1"), Some("starting")),
            "the stand-in did the work: it launches component-1 starting"
        );
        let shell = standin.post_capability_request(Caller::Shell, &Value::Null);
        assert_eq!(
            shell,
            Err((
                403,
                "capability request needs an instance session".to_owned()
            )),
            "the stand-in did the work: it refuses a shell before the body is read"
        );
        assert_eq!(
            shell_requests(&standin, "component-1"),
            json!({ "requests": [] }),
            "the stand-in did the work: the shell request stores nothing"
        );

        let first = standin.post_capability_request(
            Caller::Client {
                session_id: "component-1",
            },
            &request_client_body(),
        );
        assert_eq!(
            first,
            Ok(json!({ "status": "pending", "request_id": "request-1" })),
            "the stand-in did the work: it answers pending and request-1 for component-1"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("request-1", "component-1")],
            "the stand-in did the work: it stores one pending request for component-1"
        );
        assert_capsule(
            &standin,
            "component-1",
            "starting",
            "",
            "the stand-in did the work: the starting instance stays starting after the request",
        );
        assert_live_request_ids_empty(
            &standin,
            "the request route stores no live grant for the starting instance",
        );

        standin
            .finish_start("component-1")
            .expect("the stand-in finishes the start");
        let second = standin.post_capability_request(
            Caller::Client {
                session_id: "component-1",
            },
            &json!({
                "resource": SHARED_RESOURCE,
                "action": "Write",
                "reason": "read shared",
            }),
        );
        assert_eq!(
            second,
            Ok(json!({ "status": "pending", "request_id": "request-2" })),
            "the stand-in did the work: it mints request-2 for the running instance"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![
                pending_request("request-1", "component-1"),
                json!({
                    "request_id": "request-2",
                    "session_id": "component-1",
                    "resource": SHARED_RESOURCE,
                    "action": "write",
                    "reason": "read shared",
                    "status": "pending",
                    "decision_reason": "",
                    "settled_by": Value::Null,
                    "plan": Value::Null,
                }),
            ],
            "the stand-in did the work: it stores both pending requests and lowercases the second action"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: the running instance stays running after the second request",
        );
    }

    #[test]
    fn standin_capability_request_refuses_a_bad_body() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let launched = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launches once");
        assert_eq!(
            (launched["id"].as_str(), launched["status"].as_str()),
            (Some("component-1"), Some("starting")),
            "the stand-in did the work: it launches component-1 starting"
        );
        let caller = Caller::Client {
            session_id: "component-1",
        };
        for (body, reason, message) in [
            (
                json!({}),
                "request body needs resource",
                "a body with no resource",
            ),
            (
                json!({ "resource": "https://example", "action": "read" }),
                "Unsupported resource scheme. Allowed: elastos://, localhost://",
                "a resource without an allowed scheme",
            ),
            (
                json!({ "resource": SHARED_RESOURCE, "action": "mint" }),
                "Invalid action: mint. Expected: read, write, execute, delete, message, admin",
                "an action outside the six names",
            ),
            (
                json!({ "resource": SHARED_RESOURCE, "action": "read", "token": "x" }),
                "request body rejects token",
                "an extra body key",
            ),
        ] {
            let refused = standin.post_capability_request(caller, &body);
            assert_eq!(
                refused,
                Err((400, reason.to_owned())),
                "the stand-in did the work: it refuses {message} and stores nothing"
            );
        }
        assert_eq!(
            shell_requests(&standin, "component-1"),
            json!({ "requests": [] }),
            "the stand-in did the work: every refused body stores no request"
        );
        let accepted = standin.post_capability_request(caller, &request_client_body());
        assert_eq!(
            accepted,
            Ok(json!({ "status": "pending", "request_id": "request-1" })),
            "the stand-in did the work: the refused bodies do not advance the request id"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("request-1", "component-1")],
            "the stand-in did the work: the valid body stores request-1"
        );
    }

    fn assert_other_session_refused(
        result: &Result<Value, (u16, String)>,
        caller: &str,
        message: &str,
    ) {
        assert_eq!(
            result,
            &Err((403, "Cannot access another session's request".to_owned())),
            "the stand-in did the work: it refuses {caller} on another session's request ({message})"
        );
    }

    #[test]
    fn standin_guest_reads_its_request_later() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let first = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launches the first read-shared instance");
        let second = standin
            .post_capsules(Caller::Shell, &shared.body())
            .expect("the stand-in launches the second read-shared instance");
        assert_eq!(
            (first["id"].as_str(), second["id"].as_str()),
            (Some("component-1"), Some("component-2")),
            "the stand-in did the work: it numbers the launches component-1 and component-2"
        );
        assert_eq!(
            (first["status"].as_str(), second["status"].as_str()),
            (Some("starting"), Some("starting")),
            "the stand-in did the work: it answers starting for both launches"
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        seed_shared_request(&mut standin, "req-2", "component-2");
        let owner = Caller::Client {
            session_id: "component-1",
        };
        let sibling = Caller::Client {
            session_id: "component-2",
        };

        assert_eq!(
            standin.get_capability_request(owner, "req-1"),
            Ok(json!({ "status": "pending" })),
            "the stand-in did the work: the owning client reads req-1 pending before any decision"
        );
        assert_other_session_refused(
            &standin.get_capability_request(Caller::Shell, "req-1"),
            "the shell caller",
            "req-1 is the client's record",
        );
        assert_other_session_refused(
            &standin.get_capability_request(sibling, "req-1"),
            "the component-2 client",
            "req-1 belongs to component-1",
        );
        assert_eq!(
            standin.get_capability_request(sibling, "missing"),
            Err((404, "Request not found: missing".to_owned())),
            "the stand-in did the work: it answers 404 for an id that matches no record"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![pending_request("req-1", "component-1")],
            "the stand-in did the work: the refused reads leave req-1 pending"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![pending_request("req-2", "component-2")],
            "the stand-in did the work: the refused reads leave the sibling request pending"
        );

        standin.set_instant(4);
        let granted = standin
            .post_capability_grant(
                Caller::Shell,
                &json!({
                    "request_id": "req-1",
                    "duration": "session",
                    "rationale": "grant shared read",
                }),
            )
            .expect("the stand-in grants the first instance's request");
        assert_eq!(
            granted,
            json!({ "success": true }),
            "the stand-in did the work: the shell grant answers success true"
        );
        assert_eq!(
            standin.get_capability_request(owner, "req-1"),
            Ok(json!({ "status": "granted" })),
            "the stand-in did the work: the owning client reads req-1 granted on a later call"
        );
        assert_eq!(
            standin.get_capability_request(owner, "req-1"),
            Ok(json!({ "status": "granted" })),
            "the stand-in did the work: a second read of req-1 is the same body"
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![granted_request("req-1", "component-1", "grant shared read")],
            "the stand-in did the work: the shell record for req-1 is granted with the rationale"
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live-grant view")
            ),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in did the work: the live-grant set is exactly req-1 after the grant"
        );

        let denied = standin
            .post_capability_deny(
                Caller::Shell,
                &json!({
                    "request_id": "req-2",
                    "reason": "sibling read denied",
                }),
            )
            .expect("the stand-in denies the sibling's request");
        assert_eq!(
            denied,
            json!({ "success": true }),
            "the stand-in did the work: the shell deny answers success true"
        );
        assert_eq!(
            standin.get_capability_request(sibling, "req-2"),
            Ok(json!({ "status": "denied", "reason": "sibling read denied" })),
            "the stand-in did the work: the sibling client reads its denial reason on a later call"
        );
        assert_other_session_refused(
            &standin.get_capability_request(owner, "req-2"),
            "the component-1 client",
            "req-2 belongs to component-2",
        );
        let sibling_read = standin
            .get_capability_request(sibling, "req-2")
            .expect("the stand-in sibling denial read");
        assert_keys(
            &sibling_read,
            &["status", "reason"],
            "the stand-in did the work: a denied body has status and reason only",
        );
        assert_capsule(
            &standin,
            "component-1",
            "starting",
            "",
            "the stand-in did the work: the deny leaves the granted instance starting",
        );
        assert_capsule(
            &standin,
            "component-2",
            "failed",
            "sibling read denied",
            "the stand-in did the work: the deny fails the starting sibling with its reason",
        );
        assert_eq!(
            request_ids(
                &standin
                    .get_capability_list(Caller::Shell, None)
                    .expect("the stand-in shell live-grant view")
            ),
            BTreeSet::from(["req-1".to_owned()]),
            "the stand-in did the work: the reads leave the live-grant set exactly req-1"
        );
    }

    #[test]
    fn standin_guest_reads_a_runtime_denial() {
        let mut standin = StandIn::new();
        let shared = Shared::new();
        admit_shared(&shared, &mut standin, Start::Ok);
        let first = launch_finished(&shared, &mut standin);
        let second = launch_finished(&shared, &mut standin);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("component-1", "component-2"),
            "the stand-in did the work: it numbers the two launches component-1 and component-2"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: it lists component-1 running before the stop",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: it lists component-2 running before the stop",
        );
        seed_shared_request(&mut standin, "req-1", "component-1");
        standin
            .delete_capsule(Caller::Shell, "component-1", &stop_body())
            .expect("the stand-in stops component-1 with the stop reason");
        let owner = Caller::Client {
            session_id: "component-1",
        };
        let sibling = Caller::Client {
            session_id: "component-2",
        };
        let denial = json!({ "status": "denied", "reason": "stopped: stop one" });
        assert_eq!(
            standin.get_capability_request(owner, "req-1"),
            Ok(denial.clone()),
            "the stand-in did the work: the stopped owner reads its request denied by the runtime"
        );
        standin.set_instant(60);
        assert_eq!(
            standin.get_capability_request(owner, "req-1"),
            Ok(denial),
            "the stand-in did the work: the same read stays that denial at instant 60"
        );
        assert_other_session_refused(
            &standin.get_capability_request(sibling, "req-1"),
            "the component-2 client",
            "req-1 belongs to component-1",
        );
        assert_other_session_refused(
            &standin.get_capability_request(Caller::Shell, "req-1"),
            "the shell caller",
            "req-1 is the client's record",
        );
        assert_eq!(
            request_entries(&standin, "component-1"),
            vec![denied_request("req-1", "component-1", "stopped: stop one")],
            "the stand-in did the work: the reads leave the runtime denial record as it was"
        );
        assert_live_request_ids_empty(&standin, "the denial read leaves no live grant");
    }

    const PENDING_ENTRY: &[&str] = &[
        "action",
        "expires_at",
        "reason",
        "request_id",
        "requested_at",
        "resource",
        "session_id",
    ];

    fn shell_pending(standin: &StandIn) -> Value {
        standin
            .get_capability_pending(Caller::Shell)
            .expect("the stand-in did the work: the shell pending list")
    }

    fn pending_rows(body: &Value) -> Vec<Value> {
        body["requests"]
            .as_array()
            .expect("the stand-in did the work: the pending body lists requests")
            .clone()
    }

    fn pending_ids(body: &Value) -> Vec<String> {
        pending_rows(body)
            .iter()
            .map(|row| {
                row["request_id"]
                    .as_str()
                    .expect("the stand-in did the work: a pending entry names request_id")
                    .to_owned()
            })
            .collect()
    }

    fn owned_ids(names: &[&str]) -> Vec<String> {
        names.iter().copied().map(str::to_owned).collect()
    }

    fn live_grants(standin: &StandIn) -> Value {
        standin
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("the stand-in did the work: the shell live view")
    }

    fn assert_pending_client_refused(standin: &StandIn, session_id: &str) {
        let client = standin.get_capability_pending(Caller::Client { session_id });
        assert_eq!(
            client,
            Err((403, "This endpoint requires shell privileges".to_owned())),
            "the stand-in did the work: the {session_id} client is refused"
        );
    }

    fn assert_pending_row(
        row: &Value,
        request_id: &str,
        session_id: &str,
        resource: &str,
        action: &str,
        reason: &str,
        requested_at: u64,
        expires_at: u64,
    ) {
        assert_keys(
            row,
            PENDING_ENTRY,
            "the stand-in did the work: a pending entry has the seven keys",
        );
        assert_eq!(
            row,
            &json!({
                "request_id": request_id,
                "session_id": session_id,
                "resource": resource,
                "action": action,
                "reason": reason,
                "requested_at": requested_at,
                "expires_at": expires_at,
            }),
            "the stand-in did the work: the pending entry keeps the seeded request"
        );
    }

    fn assert_pending_read_settles_nothing(standin: &StandIn, message: &str) {
        let grants = live_grants(standin);
        let first = request_entries(standin, "component-1");
        let second = request_entries(standin, "component-2");
        let _listed = shell_pending(standin);
        assert_eq!(
            live_grants(standin),
            grants,
            "the stand-in did the work: the pending list leaves every grant ({message})"
        );
        assert_eq!(
            request_entries(standin, "component-1"),
            first,
            "the stand-in did the work: the pending list leaves component-1's record ({message})"
        );
        assert_eq!(
            request_entries(standin, "component-2"),
            second,
            "the stand-in did the work: the pending list leaves component-2's record ({message})"
        );
        assert_capsule(
            standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: the pending list leaves component-1 running",
        );
        assert_capsule(
            standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: the pending list leaves component-2 running",
        );
    }

    #[test]
    fn standin_shell_lists_every_pending_request() {
        let mut standin = StandIn::new();
        let (first, second) = launch_two_running_ids(&mut standin);
        assert_eq!(
            (first.as_str(), second.as_str()),
            ("component-1", "component-2"),
            "the stand-in did the work: the ids are component-1 and component-2"
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: component-1 is running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 is running",
        );

        let empty = shell_pending(&standin);
        assert_keys(
            &empty,
            &["requests"],
            "the stand-in did the work: the pending body has one key",
        );
        assert_eq!(
            empty,
            json!({ "requests": [] }),
            "the stand-in did the work: the shell list starts empty"
        );
        assert_pending_client_refused(&standin, "component-1");

        standin
            .seed_request(
                "req-c",
                "component-1",
                "localhost://Public/resident-instances/c.txt",
                "write",
                "reason-c",
            )
            .expect("the stand-in did the work: req-c is stored");
        standin
            .seed_request(
                "req-a",
                "component-1",
                "localhost://Public/resident-instances/a.txt",
                "read",
                "reason-a",
            )
            .expect("the stand-in did the work: req-a is stored");
        standin
            .seed_request(
                "req-b",
                "component-2",
                "localhost://Public/resident-instances/b.txt",
                "read",
                "reason-b",
            )
            .expect("the stand-in did the work: req-b is stored");

        assert_pending_read_settles_nothing(&standin, "three pending requests");
        let listed = shell_pending(&standin);
        assert_keys(
            &listed,
            &["requests"],
            "the stand-in did the work: the pending body has one key",
        );
        assert_eq!(
            pending_ids(&listed),
            owned_ids(&["req-a", "req-c", "req-b"]),
            "the stand-in did the work: the shell request_id order is req-a, req-c, req-b"
        );
        let rows = pending_rows(&listed);
        assert_pending_row(
            &rows[0],
            "req-a",
            "component-1",
            "localhost://Public/resident-instances/a.txt",
            "read",
            "reason-a",
            0,
            300,
        );
        assert_pending_row(
            &rows[1],
            "req-c",
            "component-1",
            "localhost://Public/resident-instances/c.txt",
            "write",
            "reason-c",
            0,
            300,
        );
        assert_pending_row(
            &rows[2],
            "req-b",
            "component-2",
            "localhost://Public/resident-instances/b.txt",
            "read",
            "reason-b",
            0,
            300,
        );
        assert_pending_client_refused(&standin, "component-2");
        assert_eq!(
            pending_ids(&shell_pending(&standin)),
            owned_ids(&["req-a", "req-c", "req-b"]),
            "the stand-in did the work: the client refusal leaves the shell order"
        );

        let denied = standin.post_capability_deny(
            Caller::Shell,
            &json!({ "request_id": "req-b", "reason": "keep this deny" }),
        );
        assert_eq!(
            denied,
            Ok(json!({ "success": true })),
            "the stand-in did the work: the shell deny of req-b succeeds"
        );
        assert_eq!(
            pending_ids(&shell_pending(&standin)),
            owned_ids(&["req-a", "req-c"]),
            "the stand-in did the work: the shell request_id order is req-a, req-c"
        );
        assert_eq!(
            request_entries(&standin, "component-2"),
            vec![json!({
                "request_id": "req-b",
                "session_id": "component-2",
                "resource": "localhost://Public/resident-instances/b.txt",
                "action": "read",
                "reason": "reason-b",
                "status": "denied",
                "decision_reason": "keep this deny",
                "settled_by": "shell",
                "plan": Value::Null,
            })],
            "the stand-in did the work: req-b stays denied on its session record"
        );

        let granted = standin.post_capability_grant(
            Caller::Shell,
            &json!({
                "request_id": "req-c",
                "duration": "once",
                "rationale": "grant once"
            }),
        );
        assert_eq!(
            granted,
            Ok(json!({ "success": true })),
            "the stand-in did the work: the shell grant of req-c succeeds"
        );
        assert_pending_read_settles_nothing(&standin, "after the grant");
        let remaining = shell_pending(&standin);
        assert_eq!(
            pending_ids(&remaining),
            owned_ids(&["req-a"]),
            "the stand-in did the work: the shell request_id order is req-a"
        );
        assert_pending_row(
            &pending_rows(&remaining)[0],
            "req-a",
            "component-1",
            "localhost://Public/resident-instances/a.txt",
            "read",
            "reason-a",
            0,
            300,
        );

        standin.set_instant(299);
        let at_299 = shell_pending(&standin);
        assert_eq!(
            pending_ids(&at_299),
            owned_ids(&["req-a"]),
            "the stand-in did the work: instant 299 leaves req-a listed"
        );
        assert_pending_row(
            &pending_rows(&at_299)[0],
            "req-a",
            "component-1",
            "localhost://Public/resident-instances/a.txt",
            "read",
            "reason-a",
            0,
            300,
        );

        standin.set_instant(300);
        assert_eq!(
            shell_pending(&standin),
            json!({ "requests": [] }),
            "the stand-in did the work: instant 300 expires req-a"
        );

        standin
            .seed_request(
                "req-late",
                "component-2",
                "localhost://Public/resident-instances/late.txt",
                "read",
                "reason-late",
            )
            .expect("the stand-in did the work: req-late is stored");
        let late = shell_pending(&standin);
        assert_eq!(
            pending_ids(&late),
            owned_ids(&["req-late"]),
            "the stand-in did the work: req-late is the one pending entry"
        );
        assert_pending_row(
            &pending_rows(&late)[0],
            "req-late",
            "component-2",
            "localhost://Public/resident-instances/late.txt",
            "read",
            "reason-late",
            300,
            600,
        );

        standin.set_instant(u64::MAX - 10);
        standin
            .seed_request(
                "req-sat",
                "component-1",
                "localhost://Public/resident-instances/sat.txt",
                "read",
                "reason-sat",
            )
            .expect("the stand-in did the work: req-sat is stored");
        let saturated = shell_pending(&standin);
        assert_eq!(
            pending_ids(&saturated),
            owned_ids(&["req-sat"]),
            "the stand-in did the work: req-sat is the one pending entry"
        );
        assert_pending_row(
            &pending_rows(&saturated)[0],
            "req-sat",
            "component-1",
            "localhost://Public/resident-instances/sat.txt",
            "read",
            "reason-sat",
            u64::MAX - 10,
            u64::MAX,
        );
        assert_capsule(
            &standin,
            "component-1",
            "running",
            "",
            "the stand-in did the work: component-1 stays running",
        );
        assert_capsule(
            &standin,
            "component-2",
            "running",
            "",
            "the stand-in did the work: component-2 stays running",
        );
    }
}
