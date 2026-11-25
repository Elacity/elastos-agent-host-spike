//! Local apps stay off with one sentence. This provider has no key and no process.
//!
//! The sentence is stored for one data folder. A bad file in one Home does not
//! turn off another Home in the same process. A route reads the folder on that
//! Home's own state. The registry's heap address is not a key.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use elastos_runtime::provider::{Provider, ProviderError, ResourceRequest, ResourceResponse};

/// The provider error starts with this mark and a newline, then the sentence.
pub const LOCAL_APPS_REFUSAL_MARK: &str = "local-apps-off\n";

pub fn marked_local_apps_refusal(sentence: &str) -> String {
    format!("{LOCAL_APPS_REFUSAL_MARK}{sentence}")
}

pub fn sentence_from_local_apps_provider_error(message: &str) -> Option<&str> {
    message.strip_prefix(LOCAL_APPS_REFUSAL_MARK)
}

static LOCAL_APPS_REFUSAL: LazyLock<Mutex<HashMap<PathBuf, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn refusal_key(data_dir: &Path) -> PathBuf {
    std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf())
}

fn test_override() -> Option<String> {
    #[cfg(test)]
    {
        TEST_REFUSAL.with(|slot| slot.borrow().clone())
    }
    #[cfg(not(test))]
    {
        None
    }
}

pub fn set_local_apps_refusal(data_dir: &Path, sentence: Option<String>) {
    let mut refusals = LOCAL_APPS_REFUSAL.lock().expect("local apps refusal");
    let key = refusal_key(data_dir);
    match sentence {
        Some(sentence) => {
            refusals.insert(key, sentence);
        }
        None => {
            refusals.remove(&key);
        }
    }
}

pub fn clear_local_apps_refusals() {
    LOCAL_APPS_REFUSAL
        .lock()
        .expect("local apps refusal")
        .clear();
}

pub fn local_apps_refusal(data_dir: &Path) -> Option<String> {
    if let Some(sentence) = test_override() {
        return Some(sentence);
    }
    LOCAL_APPS_REFUSAL
        .lock()
        .expect("local apps refusal")
        .get(&refusal_key(data_dir))
        .cloned()
}

#[cfg(test)]
thread_local! {
    static TEST_REFUSAL: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_local_apps_refusal_for_test(sentence: Option<String>) {
    TEST_REFUSAL.with(|slot| *slot.borrow_mut() = sentence);
}

pub struct RefusingLocalhostProvider {
    sentence: String,
}

impl RefusingLocalhostProvider {
    pub fn new(sentence: String) -> Self {
        Self { sentence }
    }
}

#[async_trait::async_trait]
impl Provider for RefusingLocalhostProvider {
    async fn handle(&self, _request: ResourceRequest) -> Result<ResourceResponse, ProviderError> {
        Err(ProviderError::Provider(marked_local_apps_refusal(
            &self.sentence,
        )))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["localhost"]
    }

    fn name(&self) -> &'static str {
        "localhost"
    }

    async fn send_raw(
        &self,
        _request: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderError> {
        Err(ProviderError::Provider(marked_local_apps_refusal(
            &self.sentence,
        )))
    }
}

#[cfg(test)]
pub(crate) struct LocalAppsTestGuard(std::sync::MutexGuard<'static, ()>);

#[cfg(test)]
impl Drop for LocalAppsTestGuard {
    fn drop(&mut self) {
        let _kept = &self.0;
        clear_local_apps_refusals();
        set_local_apps_refusal_for_test(None);
    }
}

#[cfg(test)]
pub(crate) fn lock_local_apps_for_test() -> LocalAppsTestGuard {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LocalAppsTestGuard(LOCK.lock().unwrap_or_else(|err| err.into_inner()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_runtime::provider::ProviderRegistry;

    #[test]
    fn refusal_is_keyed_by_the_data_folder() {
        let _guard = lock_local_apps_for_test();
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        set_local_apps_refusal(
            first.path(),
            Some("Users/secret.bin is not readable.".into()),
        );
        set_local_apps_refusal(second.path(), None);
        assert_eq!(
            local_apps_refusal(first.path()).as_deref(),
            Some("Users/secret.bin is not readable.")
        );
        assert_eq!(local_apps_refusal(second.path()), None);
        set_local_apps_refusal(second.path(), Some("other".into()));
        assert_eq!(
            local_apps_refusal(first.path()).as_deref(),
            Some("Users/secret.bin is not readable.")
        );
        assert_eq!(local_apps_refusal(second.path()).as_deref(), Some("other"));
    }

    #[test]
    fn a_dropped_registry_does_not_hand_its_refusal_to_the_next() {
        let _guard = lock_local_apps_for_test();
        let old_home = tempfile::tempdir().unwrap();
        let sentence = "Users/secret.bin is not readable.";
        set_local_apps_refusal(old_home.path(), Some(sentence.into()));
        let old = Box::new(ProviderRegistry::new());
        let old_addr = std::ptr::from_ref(old.as_ref()) as usize;
        drop(old);
        let new_home = tempfile::tempdir().unwrap();
        let new = Box::new(ProviderRegistry::new());
        let new_addr = std::ptr::from_ref(new.as_ref()) as usize;
        assert!(local_apps_refusal(new_home.path()).is_none());
        assert_eq!(
            local_apps_refusal(old_home.path()).as_deref(),
            Some(sentence)
        );
        if old_addr == new_addr {
            assert!(local_apps_refusal(new_home.path()).is_none());
        }
        drop(new);
        assert_eq!(
            local_apps_refusal(old_home.path()).as_deref(),
            Some(sentence)
        );
    }
}
