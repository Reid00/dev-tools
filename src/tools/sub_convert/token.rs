use super::generator::TargetFormat;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Clone)]
pub struct SubscribeTokenEntry {
    pub content: String,
    pub format: TargetFormat,
    pub include_direct: bool,
    pub include_dns: bool,
    pub expires_at: Instant,
}

pub fn token_store() -> &'static Mutex<HashMap<String, SubscribeTokenEntry>> {
    static STORE: OnceLock<Mutex<HashMap<String, SubscribeTokenEntry>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn build_token_subscription_path(
    content: &str,
    format: &TargetFormat,
    include_direct: bool,
    include_dns: bool,
) -> Result<String, String> {
    let id = Uuid::now_v7().to_string();
    let expires_at = Instant::now() + Duration::from_secs(24 * 60 * 60);

    let mut store = token_store()
        .lock()
        .map_err(|_| "Subscription store is unavailable".to_string())?;

    store.retain(|_, entry| entry.expires_at > Instant::now());
    store.insert(
        id.clone(),
        SubscribeTokenEntry {
            content: content.to_string(),
            format: format.clone(),
            include_direct,
            include_dns,
            expires_at,
        },
    );

    Ok(format!("/api/sub/subscribe/{}", id))
}

pub fn get_token_entry(id: &str) -> Result<Option<SubscribeTokenEntry>, String> {
    let mut store = token_store()
        .lock()
        .map_err(|_| "Subscription store is unavailable".to_string())?;

    store.retain(|_, entry| entry.expires_at > Instant::now());
    Ok(store.get(id).cloned())
}
