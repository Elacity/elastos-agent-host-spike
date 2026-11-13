//! Launches kept for their page.
//!
//! A start by CID of content runs the program its page pins (the core), and the
//! program's own hold on the launch ends with its start (`runtime.rs`,
//! `LaunchHeld`). The page comes later, and reads what the program wrote and
//! the content's files. So a launch opened for a page is kept here, by a launch
//! id of its own, for the person who opened it and the page the content pins,
//! for a short while. Nothing here is ever written: a kept launch is read
//! through [`Runtime::read_kept_launch`] only, and the bridge never looks
//! here.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use elastos_compute::CapsuleHandle;

use crate::bundle_admission::{AcceptedSignature, BundleRefusal};
use crate::resource_bridge::{LaunchContent, LAUNCH_CONTENT, LAUNCH_OUTPUT};
use crate::runtime::Runtime;

/// How many launches one person may have kept at once. The next open is
/// refused; none is dropped to make room.
pub const KEPT_PER_PRINCIPAL: usize = 8;
/// How many launches the Runtime keeps at once, for everyone together. Each
/// holds at most one walk's files (64 MiB), so this bounds their memory too.
pub const KEPT_IN_ALL: usize = 16;
/// How long the start of an open may take, by the clock on the wall. Fuel
/// counts only the program's own instructions, not a call it makes to the
/// Runtime that does not come back; past this the open is refused and its
/// place given back. The program may run on in its own thread, reading
/// nothing of the launch, as after any cancelled start.
pub const START_DEADLINE: Duration = Duration::from_secs(60);
/// How long a launch is kept after it is opened.
pub const KEPT_FOR: Duration = Duration::from_secs(15 * 60);

/// What a start by CID gives back (`Runtime::start_by_bundle`).
pub(crate) struct Started {
    pub handle: CapsuleHandle,
    pub accepted: AcceptedSignature,
    /// The launch, for a start of content.
    pub launch: Option<Arc<LaunchContent>>,
    /// The name of the page the content pins, for a start of content.
    pub page: Option<String>,
}

/// One place in the table: taken by an open before its start runs, and
/// holding the launch once the start is over.
pub(crate) struct Kept {
    principal: String,
    page: String,
    /// `None` while the open's start runs.
    launch: Option<Arc<LaunchContent>>,
    until: Instant,
}

/// The kept launches, by launch id.
pub(crate) type PageLaunches = Arc<Mutex<HashMap<String, Kept>>>;

/// A launch opened for its page.
#[derive(Debug, PartialEq, Eq)]
pub struct Opened {
    pub id: String,
    pub page: String,
}

/// Why a launch was not opened for a page.
#[derive(Debug)]
pub enum OpenRefusal {
    /// The start by CID refused it.
    Start(BundleRefusal),
    /// It started, but it is not content: there is no page to keep it for.
    NotContent,
    /// This person has [`KEPT_PER_PRINCIPAL`] launches kept already.
    TooManyOpen,
    /// The Runtime keeps [`KEPT_IN_ALL`] launches already.
    TooManyInAll,
    /// The place the open took was gone when its start was over.
    PlaceLost,
    /// The start took longer than [`START_DEADLINE`].
    StartTimedOut,
    /// No person to keep it for.
    NoPrincipal,
}

/// What of a kept launch is read.
pub enum KeptRead<'a> {
    /// What the program wrote under this one name.
    Output(&'a str),
    /// The content's file at exactly this path.
    Content(&'a str),
}

/// A content path a kept launch is read at: one or more plain parts joined by
/// `/`. Not empty (that would be the listing), no empty, `.` or `..` part, no
/// leading `/`, no `\`. The path is then looked up as text among the files the
/// walk read; it is joined onto no folder.
pub fn plain_content_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn kept_ones(table: &PageLaunches) -> std::sync::MutexGuard<'_, HashMap<String, Kept>> {
    // A poisoned lock still holds the map.
    let mut kept = table.lock().unwrap_or_else(|it| it.into_inner());
    let now = Instant::now();
    // Only a filled place expires, 15 minutes after it was filled. A place an
    // open has taken lasts until its start is over: it is then filled, or
    // given back by its `Place`.
    kept.retain(|_, one| one.launch.is_none() || one.until > now);
    kept
}

/// A place an open has taken. Dropped before the open keeps its launch (the
/// start refused, the content was not content, the open was cancelled), it
/// gives the place back.
pub(crate) struct Place {
    table: PageLaunches,
    id: String,
    filled: bool,
}

impl Place {
    #[cfg(test)]
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        if !self.filled {
            let mut kept = self.table.lock().unwrap_or_else(|it| it.into_inner());
            kept.remove(&self.id);
        }
    }
}

/// Take a place for `principal`, under the one lock every place is taken and
/// filled under: refused when the person or the Runtime is full.
pub(crate) fn take_place(table: &PageLaunches, principal: &str) -> Result<Place, OpenRefusal> {
    let mut kept = kept_ones(table);
    if kept.len() >= KEPT_IN_ALL {
        return Err(OpenRefusal::TooManyInAll);
    }
    if held_by(&kept, principal) >= KEPT_PER_PRINCIPAL {
        return Err(OpenRefusal::TooManyOpen);
    }
    // A new id, drawn again in the (128-bit) case it is already in the table.
    let mut id = hex::encode(rand::random::<[u8; 16]>());
    while kept.contains_key(&id) {
        id = hex::encode(rand::random::<[u8; 16]>());
    }
    let one = Kept {
        principal: principal.to_string(),
        page: String::new(),
        launch: None,
        until: Instant::now() + KEPT_FOR,
    };
    kept.insert(id.clone(), one);
    Ok(Place {
        table: table.clone(),
        id,
        filled: false,
    })
}

fn held_by(kept: &HashMap<String, Kept>, principal: &str) -> usize {
    kept.values()
        .filter(|one| one.principal == principal)
        .count()
}

impl Runtime {
    /// Start the content at `cid` for `principal` and keep its launch for the
    /// page it pins. The program runs as in any start by CID, and its own hold
    /// on the launch ends with its start; what is kept is read by
    /// [`Runtime::read_kept_launch`] only.
    pub(crate) async fn open_for_page(
        &self,
        data_dir: &Path,
        cid: &str,
        principal: &str,
    ) -> Result<Opened, OpenRefusal> {
        if principal.trim().is_empty() {
            return Err(OpenRefusal::NoPrincipal);
        }
        // The place is taken before anything is walked or run: a full person
        // or a full Runtime is refused here, and two opens at once cannot
        // both take the last place. The place goes back if no launch fills it.
        let mut place = take_place(&self.page_launches, principal)?;
        let person = Some(principal.to_string());
        // The one walk budget of every start by CID, as `run_by_bundle` hands it over.
        let budget = crate::bundle_admission::BUNDLE_WALK_BUDGET;
        let start = self.start_by_bundle(data_dir, cid, Vec::new(), person, budget, |_| {});
        let deadline = self.page_start_deadline_ms.load(Ordering::Relaxed);
        let started = tokio::time::timeout(Duration::from_millis(deadline), start)
            .await
            .map_err(|_| OpenRefusal::StartTimedOut)?
            .map_err(OpenRefusal::Start)?;
        let (Some(launch), Some(page)) = (started.launch, started.page) else {
            return Err(OpenRefusal::NotContent);
        };
        let mut kept = kept_ones(&self.page_launches);
        // The place this open took is filled and its time starts now. It is
        // still there: an unfilled place does not expire, and only its own
        // `Place` gives it back. Were it gone, the open says so by name.
        let one = kept.get_mut(&place.id).ok_or(OpenRefusal::PlaceLost)?;
        one.page = page.clone();
        one.launch = Some(launch);
        one.until = Instant::now() + KEPT_FOR;
        place.filled = true;
        Ok(Opened {
            id: place.id.clone(),
            page,
        })
    }

    /// Read a kept launch: for `principal`, for its `page`, one name of what
    /// the program wrote or one file of the content. `None` for anything else
    /// alike: no such launch, a gone one, another person's or page's, a path
    /// that is not plain, a name or file that is not there.
    pub(crate) fn read_kept_launch(
        &self,
        id: &str,
        principal: &str,
        page: &str,
        what: KeptRead<'_>,
    ) -> Option<Vec<u8>> {
        let launch = {
            let kept = kept_ones(&self.page_launches);
            let one = kept.get(id)?;
            if one.principal != principal || one.page != page {
                return None;
            }
            one.launch.clone()?
        };
        match what {
            // An output name with a `/` names nothing: the output's write rule
            // keeps one plain name per entry, so no key holds one.
            KeptRead::Output(name) => launch.read(&format!("{LAUNCH_OUTPUT}{name}")),
            KeptRead::Content(path) if plain_content_path(path) => {
                launch.read(&format!("{LAUNCH_CONTENT}{path}"))
            }
            _ => None,
        }
    }

    /// The page a kept launch was opened for, while it is kept.
    pub(crate) fn kept_launch_page(&self, id: &str) -> Option<String> {
        let kept = kept_ones(&self.page_launches);
        let one = kept.get(id)?;
        one.launch.as_ref().map(|_| one.page.clone())
    }

    #[cfg(test)]
    pub(crate) fn set_page_start_deadline(&self, deadline: Duration) {
        let millis = deadline.as_millis() as u64;
        self.page_start_deadline_ms.store(millis, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn kept_launch_count(&self) -> usize {
        kept_ones(&self.page_launches).len()
    }

    #[cfg(test)]
    pub(crate) fn write_kept_output(&self, id: &str, name: &str, bytes: &[u8]) {
        let kept = kept_ones(&self.page_launches);
        let name = format!("{LAUNCH_OUTPUT}{name}");
        let launch = kept[id].launch.as_ref().expect("a filled place");
        launch.write_for_test(&name, bytes.to_vec()).unwrap();
    }

    #[cfg(test)]
    pub(crate) fn expire_kept_launches(&self) {
        let mut kept = self
            .page_launches
            .lock()
            .unwrap_or_else(|it| it.into_inner());
        let past = Instant::now() - Duration::from_secs(1);
        kept.values_mut().for_each(|one| one.until = past);
    }
}
