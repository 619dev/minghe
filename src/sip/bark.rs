//! Optional Bark delivery for calls to extensions without a live SIP connection.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use super::parser;

const WAIT: Duration = Duration::from_secs(30);
const MAX_PENDING: usize = 128;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BarkTarget {
    pub endpoint: String,
    pub device_key_env: String,
}

impl BarkTarget {
    pub fn valid(&self) -> bool {
        self.endpoint.strip_prefix("https://").is_some_and(|url| {
            url.ends_with("/push")
                && !url.starts_with('/')
                && !url
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b"@?#".contains(&b))
        }) && !self.device_key_env.is_empty()
            && self
                .device_key_env
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    }

    fn device_key(&self) -> Option<String> {
        std::env::var(&self.device_key_env)
            .ok()
            .filter(|key| !key.is_empty())
    }
}

async fn notify(endpoint: &str, key: &str, test: bool) -> bool {
    let body = serde_json::json!({
        "device_key": key,
        "title": "Minghe",
        "body": if test { "Bark test succeeded. Tap to open Minghe." } else { "Incoming SIP call. Tap to open Minghe." },
        "sound": "minuet",
        "level": "timeSensitive",
        "group": "Minghe",
        "url": "minghe://incoming",
    });
    // Keep the key out of the process arguments, logs and redirects.
    let Ok(mut child) = tokio::process::Command::new("curl")
        .args([
            "-q",
            "--fail",
            "--silent",
            "--globoff",
            "--proto",
            "=https",
            "--max-time",
            "5",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            "--url",
            endpoint,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    else {
        return false;
    };
    let Some(mut stdin) = child.stdin.take() else {
        return false;
    };
    if stdin.write_all(body.to_string().as_bytes()).await.is_err() {
        return false;
    }
    drop(stdin);
    // Bound the response as Bark's success envelope is small.
    use tokio::io::AsyncReadExt;
    let Some(stdout) = child.stdout.take() else {
        return false;
    };
    let mut response = Vec::new();
    if stdout.take(8193).read_to_end(&mut response).await.is_err() || response.len() > 8192 {
        return false;
    }
    child.wait().await.is_ok_and(|status| status.success())
        && serde_json::from_slice::<serde_json::Value>(&response)
            .is_ok_and(|body| body["code"].as_u64() == Some(200))
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Subscriptions(HashMap<String, Option<String>>);

/// Endpoints contain device keys. Keep them out of Debug and SIP response headers.
pub struct BarkSubscriptions {
    path: Option<std::path::PathBuf>,
    saved: Mutex<Subscriptions>,
    tests: Mutex<HashMap<String, (String, Instant, String)>>,
}

impl BarkSubscriptions {
    pub fn load(path: std::path::PathBuf) -> std::io::Result<Self> {
        let saved = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| std::io::Error::other("Invalid Bark subscription store"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Subscriptions::default(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            path: Some(path),
            saved: Mutex::new(saved),
            tests: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        Self {
            path: None,
            saved: Mutex::new(Subscriptions::default()),
            tests: Mutex::new(HashMap::new()),
        }
    }

    pub fn endpoint(&self, extension: &str) -> Option<Option<String>> {
        self.saved.lock().unwrap().0.get(extension).cloned()
    }

    fn save(&self, extension: &str, endpoint: Option<String>) -> bool {
        let mut saved = self.saved.lock().unwrap();
        let mut next = saved.clone();
        next.0.insert(extension.to_string(), endpoint);
        if let Some(path) = &self.path {
            let result = (|| -> std::io::Result<()> {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                use std::io::Write;
                let temp = path.with_extension("json.tmp");
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(&temp)?;
                file.write_all(&serde_json::to_vec(&next)?)?;
                file.sync_all()?;
                std::fs::rename(temp, path)?;
                Ok(())
            })();
            if result.is_err() {
                return false;
            }
        }
        *saved = next;
        true
    }

    pub fn configured(&self, extension: &str, fallback: Option<&BarkTarget>) -> bool {
        match self.endpoint(extension) {
            Some(endpoint) => endpoint.is_some(),
            None => fallback.and_then(BarkTarget::device_key).is_some(),
        }
    }

    pub async fn notify(&self, extension: &str, fallback: Option<&BarkTarget>, test: bool) -> bool {
        match self.endpoint(extension) {
            Some(Some(endpoint)) => {
                let Some((url, key)) = split_endpoint(&endpoint) else {
                    return false;
                };
                notify(&url, &key, test).await
            }
            Some(None) => false,
            None => {
                if let Some(target) = fallback {
                    let Some(key) = target.device_key() else {
                        return false;
                    };
                    notify(&target.endpoint, &key, test).await
                } else {
                    false
                }
            }
        }
    }

    /// Called only after a successful Digest-authenticated REGISTER.
    pub async fn register(
        &self,
        extension: &str,
        request: &str,
        fallback: Option<&BarkTarget>,
    ) -> (String, String) {
        let id = parser::extract_header_value(request, "X-Minghe-Bark-ID").unwrap_or_default();
        if id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return (String::new(), "invalid".into());
        }
        let action =
            parser::extract_header_value(request, "X-Minghe-Bark-Action").unwrap_or_default();
        let result = match action.as_str() {
            "" | "status" => {
                if self.configured(extension, fallback) {
                    "enabled"
                } else {
                    "disabled"
                }
            }
            "set" => {
                let endpoint = parser::extract_header_value(request, "X-Minghe-Bark-Endpoint")
                    .unwrap_or_default();
                if split_endpoint(&endpoint).is_none() {
                    "invalid"
                } else if self.save(extension, Some(endpoint)) {
                    "enabled"
                } else {
                    "storage-error"
                }
            }
            "disable" => {
                if self.save(extension, None) {
                    "disabled"
                } else {
                    "storage-error"
                }
            }
            "test" => {
                if id.is_empty() {
                    return (id, "invalid".into());
                }
                {
                    let mut tests = self.tests.lock().unwrap();
                    if let Some((last_id, when, result)) = tests.get(extension) {
                        if last_id == &id {
                            return (id, result.clone());
                        }
                        if when.elapsed() < Duration::from_secs(10) {
                            return (id, "rate-limited".into());
                        }
                    }
                    tests.insert(
                        extension.into(),
                        (id.clone(), Instant::now(), "testing".into()),
                    );
                }
                let result = if self.notify(extension, fallback, true).await {
                    "sent"
                } else {
                    "delivery-error"
                };
                self.tests.lock().unwrap().insert(
                    extension.into(),
                    (id.clone(), Instant::now(), result.into()),
                );
                result
            }
            _ => "invalid",
        };
        (id, result.into())
    }
}

/// A copied Bark URL contains a single device key after an optional reverse-proxy path.
fn split_endpoint(endpoint: &str) -> Option<(String, String)> {
    if endpoint.len() > 2048
        || endpoint
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b"@?#%\\".contains(&b))
    {
        return None;
    }
    let rest = endpoint.strip_prefix("https://")?;
    let (authority, path) = rest.split_once('/')?;
    let mut host_port = authority.split(':');
    let host = host_port.next()?;
    if host.is_empty()
        || host.starts_with('.')
        || host.starts_with('-')
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    {
        return None;
    }
    if let Some(port) = host_port.next() {
        if port.parse::<u16>().ok().filter(|p| *p != 0).is_none() {
            return None;
        }
    }
    if host_port.next().is_some() {
        return None;
    }
    let (prefix, key) = path.rsplit_once('/').unwrap_or(("", path));
    if key.is_empty()
        || key.len() > 256
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        || prefix.split('/').any(|part| part == "." || part == "..")
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./~".contains(&b))
    {
        return None;
    }
    let base = if prefix.is_empty() {
        format!("https://{authority}")
    } else {
        format!("https://{authority}/{prefix}")
    };
    Some((format!("{base}/push"), key.into()))
}

pub struct PendingInvite {
    pub request: String,
    pub caller: mpsc::Sender<Vec<u8>>,
    call_id: String,
    branch: String,
    deadline: Instant,
}

#[derive(Default)]
pub struct BarkQueue(Mutex<HashMap<String, PendingInvite>>);

pub enum Enqueue {
    Queued(Instant),
    Retransmission,
    Rejected,
}

impl BarkQueue {
    pub fn enqueue(&self, callee: &str, request: &str, caller: &mpsc::Sender<Vec<u8>>) -> Enqueue {
        let (Some(call_id), Some(branch), Some(_)) = (
            parser::extract_call_id(request),
            parser::extract_via_branch(request),
            parser::extract_from_tag(request),
        ) else {
            return Enqueue::Rejected;
        };
        let mut pending = self.0.lock().unwrap();
        if let Some(existing) = pending.get(callee) {
            return if existing.call_id == call_id
                && existing.branch == branch
                && existing.caller.same_channel(caller)
            {
                Enqueue::Retransmission
            } else {
                Enqueue::Rejected
            };
        }
        if pending.len() >= MAX_PENDING
            || pending.values().any(|p| p.call_id == call_id)
            || pending
                .values()
                .filter(|p| p.caller.same_channel(caller))
                .count()
                >= 2
        {
            return Enqueue::Rejected;
        }
        let deadline = Instant::now() + WAIT;
        pending.insert(
            callee.to_string(),
            PendingInvite {
                request: request.to_string(),
                caller: caller.clone(),
                call_id,
                branch,
                deadline,
            },
        );
        Enqueue::Queued(deadline)
    }

    pub fn take_for_registration(&self, callee: &str) -> Option<PendingInvite> {
        let mut pending = self.0.lock().unwrap();
        if pending
            .get(callee)
            .is_some_and(|p| p.deadline > Instant::now())
        {
            return pending.remove(callee);
        }
        None
    }

    pub fn take_if_current(&self, callee: &str, deadline: Instant) -> Option<PendingInvite> {
        let mut pending = self.0.lock().unwrap();
        if pending.get(callee).is_some_and(|p| p.deadline == deadline) {
            return pending.remove(callee);
        }
        None
    }

    pub fn cancel(&self, request: &str, caller: &mpsc::Sender<Vec<u8>>) -> Option<PendingInvite> {
        let call_id = parser::extract_call_id(request)?;
        let branch = parser::extract_via_branch(request)?;
        let mut pending = self.0.lock().unwrap();
        let callee = pending.iter().find_map(|(callee, p)| {
            (p.call_id == call_id
                && p.branch == branch
                && p.caller.same_channel(caller)
                && parser::extract_from_tag(&p.request) == parser::extract_from_tag(request))
            .then(|| callee.clone())
        })?;
        pending.remove(&callee)
    }

    pub fn disconnect(&self, caller: &mpsc::Sender<Vec<u8>>) {
        self.0
            .lock()
            .unwrap()
            .retain(|_, p| !p.caller.same_channel(caller));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_urls_require_https_and_preserve_proxy_prefix() {
        assert_eq!(
            split_endpoint("https://api.day.app/device_key"),
            Some(("https://api.day.app/push".into(), "device_key".into()))
        );
        assert_eq!(
            split_endpoint("https://bark.example.org:8443/notify/device-key"),
            Some((
                "https://bark.example.org:8443/notify/push".into(),
                "device-key".into()
            ))
        );
        for endpoint in [
            "http://api.day.app/key",
            "https://api.day.app/",
            "https://user@host/key",
            "https://host/key?url=other",
            "https://host/../key",
            "https://host/%0dkey",
            "https://host/key\r\nInjected: x",
            "https://host:0/key",
            "https://host/key#fragment",
        ] {
            assert!(split_endpoint(endpoint).is_none(), "Accepted invalid URL");
        }
    }

    #[tokio::test]
    async fn saves_and_disables_subscriptions_across_restart_without_returning_keys() {
        let directory = std::env::temp_dir().join(format!("minghe-bark-{}", uuid::Uuid::new_v4()));
        let path = directory.join("subscriptions.json");
        let store = BarkSubscriptions::load(path.clone()).unwrap();
        let set = "X-Minghe-Bark-ID: request-1\r\nX-Minghe-Bark-Action: set\r\nX-Minghe-Bark-Endpoint: https://api.day.app/private-device-key\r\n\r\n";
        assert_eq!(
            store.register("1001", set, None).await,
            ("request-1".into(), "enabled".into())
        );
        let reloaded = BarkSubscriptions::load(path.clone()).unwrap();
        assert!(reloaded.configured("1001", None));
        assert!(!reloaded.configured("1002", None));
        let invalid = set.replace(
            "https://api.day.app/private-device-key",
            "https://host/key?x=1",
        );
        assert_eq!(reloaded.register("1001", &invalid, None).await.1, "invalid");
        assert!(reloaded.configured("1001", None));
        let disable = "X-Minghe-Bark-ID: request-2\r\nX-Minghe-Bark-Action: disable\r\n\r\n";
        assert_eq!(reloaded.register("1001", disable, None).await.1, "disabled");
        let reloaded = BarkSubscriptions::load(path).unwrap();
        let fallback = BarkTarget {
            endpoint: "https://example.org/push".into(),
            device_key_env: "UNUSED".into(),
        };
        assert!(!reloaded.configured("1001", Some(&fallback)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(directory.join("subscriptions.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn failed_storage_does_not_report_enabled_and_tests_are_deduplicated() {
        let path =
            std::env::temp_dir().join(format!("minghe-bark-blocked-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"not a directory").unwrap();
        let store = BarkSubscriptions::load(path.join("subscriptions.json"));
        assert!(store.is_err());
        let store = BarkSubscriptions {
            path: Some(path.join("subscriptions.json")),
            saved: Mutex::new(Subscriptions::default()),
            tests: Mutex::new(HashMap::new()),
        };
        let set = "X-Minghe-Bark-ID: request-1\r\nX-Minghe-Bark-Action: set\r\nX-Minghe-Bark-Endpoint: https://api.day.app/device-key\r\n\r\n";
        assert_eq!(store.register("1001", set, None).await.1, "storage-error");
        assert!(!store.configured("1001", None));
        std::fs::remove_file(path).unwrap();
        let store = BarkSubscriptions::memory();
        let test = "X-Minghe-Bark-ID: test-1\r\nX-Minghe-Bark-Action: test\r\n\r\n";
        assert_eq!(store.register("1001", test, None).await.1, "delivery-error");
        assert_eq!(store.register("1001", test, None).await.1, "delivery-error");
        assert_eq!(
            store
                .register("1001", &test.replace("test-1", "test-2"), None)
                .await
                .1,
            "rate-limited"
        );
    }

    const INVITE: &str = "INVITE sip:1002@example.com SIP/2.0\r\nVia: SIP/2.0/TLS example.com;branch=z9hG4bK-test\r\nFrom: <sip:1001@example.com>;tag=from-test\r\nTo: <sip:1002@example.com>\r\nCall-ID: test@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";

    #[test]
    fn authenticates_cancellation_and_keeps_one_invite_per_extension() {
        let queue = BarkQueue::default();
        let (caller, _rx) = mpsc::channel(1);
        let (other, _other_rx) = mpsc::channel(1);
        assert!(matches!(
            queue.enqueue("1002", INVITE, &caller),
            Enqueue::Queued(_)
        ));
        assert!(matches!(
            queue.enqueue("1002", INVITE, &caller),
            Enqueue::Retransmission
        ));
        assert!(matches!(
            queue.enqueue("1002", INVITE, &other),
            Enqueue::Rejected
        ));
        let cancel = INVITE
            .replacen("INVITE", "CANCEL", 1)
            .replace("1 INVITE", "1 CANCEL");
        assert!(queue.cancel(&cancel, &other).is_none());
        assert!(queue.cancel(&cancel, &caller).is_some());
        assert!(queue.take_for_registration("1002").is_none());
    }

    #[test]
    fn registration_consumes_pending_invite_only_once() {
        let queue = BarkQueue::default();
        let (caller, _rx) = mpsc::channel(1);
        let Enqueue::Queued(deadline) = queue.enqueue("1002", INVITE, &caller) else {
            panic!("expected pending call")
        };
        assert!(queue.take_for_registration("1003").is_none());
        assert_eq!(queue.take_for_registration("1002").unwrap().request, INVITE);
        assert!(queue.take_if_current("1002", deadline).is_none());
    }
}
