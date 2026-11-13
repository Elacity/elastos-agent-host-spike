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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use elastos_compute::CapsuleHandle;

use crate::bundle_admission::{AcceptedSignature, BundleRefusal};
use crate::resource_bridge::{LaunchContent, LAUNCH_CONTENT, LAUNCH_OUTPUT};
use crate::runtime::Runtime;

/// How many launches one person may have kept at once. The next open is
/// refused; none is dropped to make room.
pub const KEPT_PER_PRINCIPAL: usize = 8;
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

/// One kept launch.
pub(crate) struct Kept {
    principal: String,
    page: String,
    launch: Arc<LaunchContent>,
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
    kept.retain(|_, one| one.until > now);
    kept
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
        // Refused before anything is walked or run when the person is full.
        if held_by(&kept_ones(&self.page_launches), principal) >= KEPT_PER_PRINCIPAL {
            return Err(OpenRefusal::TooManyOpen);
        }
        let person = Some(principal.to_string());
        // The one walk budget of every start by CID, as `run_by_bundle` hands it over.
        let budget = crate::bundle_admission::BUNDLE_WALK_BUDGET;
        let started = self
            .start_by_bundle(data_dir, cid, Vec::new(), person, budget, |_| {})
            .await
            .map_err(OpenRefusal::Start)?;
        let (Some(launch), Some(page)) = (started.launch, started.page) else {
            return Err(OpenRefusal::NotContent);
        };
        let id = hex::encode(rand::random::<[u8; 16]>());
        let mut kept = kept_ones(&self.page_launches);
        // Checked again under the one lock that inserts: two opens at once
        // cannot both take the last place.
        if held_by(&kept, principal) >= KEPT_PER_PRINCIPAL {
            return Err(OpenRefusal::TooManyOpen);
        }
        let until = Instant::now() + KEPT_FOR;
        let one = Kept {
            principal: principal.to_string(),
            page: page.clone(),
            launch,
            until,
        };
        kept.insert(id.clone(), one);
        Ok(Opened { id, page })
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
            one.launch.clone()
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
        kept_ones(&self.page_launches)
            .get(id)
            .map(|one| one.page.clone())
    }

    #[cfg(test)]
    pub(crate) fn kept_launch_count(&self) -> usize {
        kept_ones(&self.page_launches).len()
    }

    #[cfg(test)]
    pub(crate) fn write_kept_output(&self, id: &str, name: &str, bytes: &[u8]) {
        let kept = kept_ones(&self.page_launches);
        let name = format!("{LAUNCH_OUTPUT}{name}");
        kept[id]
            .launch
            .write_for_test(&name, bytes.to_vec())
            .unwrap();
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
