//! Local apps stay off with one sentence. This provider has no key and no process.
//!
//! The sentence is stored for one data folder. A bad file in one Home does not
//! turn off another Home in the same process. A route reads the folder bound to
//! its own provider registry.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use elastos_runtime::provider::{
    Provider, ProviderError, ProviderRegistry, ResourceRequest, ResourceResponse,
};

static LOCAL_APPS_REFUSAL: Mutex<HashMap<PathBuf, String>> = Mutex::new(HashMap::new());
static LOCAL_APPS_HOMES: Mutex<HashMap<usize, PathBuf>> = Mutex::new(HashMap::new());

fn refusal_key(data_dir: &Path) -> PathBuf {
    std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf())
}

fn registry_key(registry: &ProviderRegistry) -> usize {
    std::ptr::from_ref(registry) as usize
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

/// Remember which data folder this Home's registry serves.
pub fn bind_local_apps_home(registry: &ProviderRegistry, data_dir: &Path) {
    LOCAL_APPS_HOMES
        .lock()
        .expect("local apps homes")
        .insert(registry_key(registry), refusal_key(data_dir));
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
    LOCAL_APPS_HOMES.lock().expect("local apps homes").clear();
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

pub fn local_apps_refusal_for_registry(registry: &ProviderRegistry) -> Option<String> {
    if let Some(sentence) = test_override() {
        return Some(sentence);
    }
    let data_dir = {
        let homes = LOCAL_APPS_HOMES.lock().expect("local apps homes");
        homes.get(&registry_key(registry))?.clone()
    };
    LOCAL_APPS_REFUSAL
        .lock()
        .expect("local apps refusal")
        .get(&data_dir)
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
        Err(ProviderError::Provider(self.sentence.clone()))
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
        Err(ProviderError::Provider(self.sentence.clone()))
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

    #[test]
    fn refusal_is_keyed_by_the_data_folder() {
        let _guard = lock_local_apps_for_test();
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let first_registry = ProviderRegistry::new();
        let second_registry = ProviderRegistry::new();
        bind_local_apps_home(&first_registry, first.path());
        bind_local_apps_home(&second_registry, second.path());
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
        assert_eq!(
            local_apps_refusal_for_registry(&first_registry).as_deref(),
            Some("Users/secret.bin is not readable.")
        );
        assert_eq!(local_apps_refusal_for_registry(&second_registry), None);
        set_local_apps_refusal(second.path(), Some("other".into()));
        assert_eq!(
            local_apps_refusal(first.path()).as_deref(),
            Some("Users/secret.bin is not readable.")
        );
        assert_eq!(
            local_apps_refusal_for_registry(&second_registry).as_deref(),
            Some("other")
        );
    }
}
