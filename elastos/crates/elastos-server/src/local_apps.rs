//! Local apps stay off with one sentence. This provider has no key and no process.

use std::sync::Mutex;

use elastos_runtime::provider::{Provider, ProviderError, ResourceRequest, ResourceResponse};

static LOCAL_APPS_REFUSAL: Mutex<Option<String>> = Mutex::new(None);

pub fn set_local_apps_refusal(sentence: Option<String>) {
    *LOCAL_APPS_REFUSAL.lock().expect("local apps refusal") = sentence;
}

#[cfg(test)]
thread_local! {
    static TEST_REFUSAL: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

pub fn local_apps_refusal() -> Option<String> {
    #[cfg(test)]
    if let Some(sentence) = TEST_REFUSAL.with(|slot| slot.borrow().clone()) {
        return Some(sentence);
    }
    LOCAL_APPS_REFUSAL
        .lock()
        .expect("local apps refusal")
        .clone()
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
        set_local_apps_refusal(None);
        set_local_apps_refusal_for_test(None);
    }
}

#[cfg(test)]
pub(crate) fn lock_local_apps_for_test() -> LocalAppsTestGuard {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LocalAppsTestGuard(LOCK.lock().unwrap_or_else(|err| err.into_inner()))
}
