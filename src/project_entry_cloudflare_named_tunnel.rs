//! Persistent Cloudflare named Tunnel runtime.
//!
//! This is deliberately a separate entry point from `share`. A share is a
//! temporary, project-scoped session whose public hostname Cloudflare assigns
//! on the fly; a named Tunnel is a long-lived Server transport whose hostname,
//! ingress rules and credentials the operator owns in the Cloudflare
//! dashboard. The two only share the verified `cloudflared` binary and its
//! process-tree handling, which is reused rather than duplicated.
//!
//! A remotely-managed named Tunnel needs exactly one local input — the tunnel
//! token — because ingress and the public hostname never leave Cloudflare. The
//! token is passed through the child environment instead of argv so it cannot
//! leak through `ps`.

use super::client_handoff_service::mcp_url;
use super::regular_tunnel_service::{
    probe_local_mcp, tunnel_auth_error, validate_local_server_url,
    wait_for_regular_tunnel_stop_signal, HealthEvents,
};
use super::setup_service::create_private_dir;
use super::share_service::{configure_cloudflare_process_tree, terminate_cloudflare_process_tree};
use super::{remove_npm_wrapper_network_environment, ProductError};
use serde_json::{json, Value};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::task::JoinHandle;

/// cloudflared logs one of these per established edge connection. A
/// remotely-managed named Tunnel publishes no local URL to discover, so the
/// connection log is the readiness signal.
const REGISTERED_CONNECTION_MARKER: &str = "Registered tunnel connection";
/// Production startup allows a slow edge handshake. Tests keep the same code
/// path but use a short deadline so timeout cases finish without sleeping.
#[cfg(not(test))]
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(test)]
const STARTUP_TIMEOUT: Duration = Duration::from_millis(400);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CloudflareNamedTunnelOptions {
    pub(crate) local_server_url: String,
    pub(crate) bootstrap_token: String,
    pub(crate) tunnel_token: String,
    pub(crate) runtime_parent: PathBuf,
    pub(crate) stop_on_stdin_eof: bool,
}

/// Per-run scratch directory. cloudflared writes its own runtime state here so
/// nothing lands in the operator's home directory, and it is removed when the
/// runtime ends.
struct NamedTunnelSession {
    directory: PathBuf,
}

impl NamedTunnelSession {
    fn create(runtime_parent: &Path) -> Result<Self, ProductError> {
        let root = runtime_parent.join("cloudflare-tunnel-runtime");
        create_private_dir(&root)?;
        let directory = root.join(format!("named-{}", uuid::Uuid::new_v4().simple()));
        create_private_dir(&directory)?;
        Ok(Self { directory })
    }
}

impl Drop for NamedTunnelSession {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn tunnel_runtime_error() -> ProductError {
    ProductError::new(
        "tunnel_unavailable",
        "The Cloudflare Tunnel process could not be supervised",
        Some("Check the cloudflared installation and retry."),
    )
}

pub(crate) async fn run_cloudflare_named_tunnel_with_stop(
    options: &CloudflareNamedTunnelOptions,
    stop: impl Future<Output = ()>,
) -> Result<(), ProductError> {
    match run_cloudflare_named_tunnel_inner(options, stop).await {
        Ok(()) => Ok(()),
        Err(error) => {
            println!("{}", machine_failure_event(&error));
            Err(error)
        }
    }
}

async fn run_cloudflare_named_tunnel_inner(
    options: &CloudflareNamedTunnelOptions,
    stop: impl Future<Output = ()>,
) -> Result<(), ProductError> {
    let local_server_url = validate_local_server_url(&options.local_server_url)?;
    let tunnel_token = options.tunnel_token.trim();
    if tunnel_token.is_empty() {
        return Err(ProductError::new(
            "tunnel_configuration",
            "the Cloudflare Tunnel token is unavailable",
            Some("Reconfigure the Tunnel profile with a Cloudflare Tunnel token, then retry."),
        ));
    }
    let session = NamedTunnelSession::create(&options.runtime_parent)?;
    let binary = super::cloudflared_service::resolve_cloudflared().await?;
    tokio::pin!(stop);

    let mut command = Command::new(&binary);
    remove_npm_wrapper_network_environment(&mut command);
    command
        .arg("tunnel")
        .arg("run")
        .current_dir(&session.directory)
        .env("TUNNEL_TOKEN", tunnel_token)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_cloudflare_process_tree(&mut command);
    // `Command::spawn` is synchronous, so it cannot be a `select!` branch: the
    // process is either created now or the call returns an error. Racing it
    // against `stop` would be meaningless. The stop signal is honoured
    // immediately after — in the readiness loop below and in the supervision
    // `select!` at the end of this function. This mirrors
    // `project_entry_share.rs`, which spawns cloudflared the same way.
    let mut child = command.spawn().map_err(|error| {
        ProductError::new(
            "tunnel_unavailable",
            format!("cloudflared could not start ({:?})", error.kind()),
            Some("Check the cloudflared executable and retry."),
        )
    })?;
    let process_group_id = child.id();
    let stdout = child.stdout.take().ok_or_else(tunnel_runtime_error)?;
    let stderr = child.stderr.take().ok_or_else(tunnel_runtime_error)?;
    let registered = Arc::new(AtomicBool::new(false));
    let stdout_task = spawn_registration_reader(stdout, registered.clone());
    let stderr_task = spawn_registration_reader(stderr, registered.clone());

    // Wait for the first registered edge connection. A named Tunnel publishes
    // no local URL, so the connection log is the only readiness evidence.
    let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
    loop {
        if registered.load(Ordering::Relaxed) {
            break;
        }
        if let Some(status) = child.try_wait().map_err(|_| tunnel_runtime_error())? {
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            return Err(ProductError::new(
                "tunnel_not_ready",
                format!("cloudflared exited before registering a Tunnel connection ({status})"),
                Some(
                    "Check the Cloudflare Tunnel token, its ingress configuration and network connectivity, then retry.",
                ),
            ));
        }
        if tokio::time::Instant::now() >= deadline {
            terminate_cloudflare_process_tree(&mut child, process_group_id).await;
            return Err(ProductError::new(
                "tunnel_not_ready",
                "cloudflared did not register a Tunnel connection before the startup deadline",
                Some("Check network connectivity and the Cloudflare Tunnel token, then retry."),
            ));
        }
        tokio::select! {
            _ = &mut stop => {
                terminate_cloudflare_process_tree(&mut child, process_group_id).await;
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
    }

    let mcp_endpoint = mcp_url(&local_server_url);
    let managed = std::env::var("WEBCODEX_TUNNEL_PROFILE_ID").is_ok();
    let readiness_path = options.runtime_parent.join("readiness.json");
    let service_readiness = managed
        .then_some(readiness_path)
        .filter(|path| path.is_file());
    // There is no clipboard handoff for a named Tunnel: the public hostname is
    // owned by the Cloudflare dashboard, so WebCodex reports local readiness
    // only and never claims to have completed a client handoff.
    println!("{}", machine_named_tunnel_ready_event(&mcp_endpoint));

    let outcome = tokio::select! {
        _ = wait_for_regular_tunnel_stop_signal(options.stop_on_stdin_eof) => Ok(()),
        _ = &mut stop => Ok(()),
        result = child.wait() => result.map(|_| ()).map_err(|_| tunnel_runtime_error()),
        result = report_named_tunnel_health(&mcp_endpoint, &options.bootstrap_token, service_readiness.as_deref(), options.stop_on_stdin_eof) => result,
    };
    if let Some(path) = service_readiness {
        let _ = webcodex_environment::write_tunnel_health(&path, false, false);
    }
    terminate_cloudflare_process_tree(&mut child, process_group_id).await;
    outcome
}

fn spawn_registration_reader<R>(reader: R, registered: Arc<AtomicBool>) -> JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.contains(REGISTERED_CONNECTION_MARKER) {
                registered.store(true, Ordering::Relaxed);
            }
        }
    })
}

/// A running cloudflared is not sufficient proof of a usable local MCP
/// endpoint, so the local MCP probe is the second half of readiness. The tunnel
/// half stays true while this process is supervising a cloudflared that has
/// registered: the outer `select!` ends the runtime the moment it exits. No
/// response body, credential or network error text crosses the machine channel.
///
/// Sampling and the machine channel have different lifetimes: a parent-owned
/// pipe keeps the 2s heartbeat (`stop_on_stdin_eof`), while a standalone
/// service emits changes immediately and one 60s summary otherwise — the same
/// `HealthEvents` policy the OpenAI regular Tunnel uses.
async fn report_named_tunnel_health(
    local_mcp_url: &str,
    bootstrap: &str,
    service_readiness: Option<&Path>,
    parent_heartbeat: bool,
) -> Result<(), ProductError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| tunnel_auth_error("Local connection health monitoring is unavailable"))?;
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut events = HealthEvents::new(parent_heartbeat);
    loop {
        interval.tick().await;
        let local_mcp_ready = probe_local_mcp(&client, local_mcp_url, bootstrap).await;
        if let Some(path) = service_readiness {
            webcodex_environment::write_tunnel_health(path, true, local_mcp_ready)
                .map_err(|_| tunnel_auth_error("Could not persist service connection health"))?;
        }
        if events.should_emit(std::time::Instant::now(), true, local_mcp_ready) {
            println!(
                "{}",
                json!({
                    "event": "health",
                    "schema_version": 1,
                    "tunnel_ready": true,
                    "local_mcp_ready": local_mcp_ready,
                })
            );
        }
    }
}

/// The ready event for a remotely-managed named Tunnel.
///
/// It deliberately reports no clipboard handoff and no public hostname: both
/// belong to the Cloudflare dashboard, so claiming `ready_for_chatgpt` here
/// would tell the client that a handoff happened when nothing was handed over.
fn machine_named_tunnel_ready_event(local_mcp_url: &str) -> Value {
    json!({
        "event": "ready",
        "schema_version": 1,
        "provider": "cloudflare",
        "ready_for_chatgpt": false,
        "connection": {
            "kind": "cloudflare_named_tunnel",
            "hostname_source": "cloudflare_dashboard",
            "local_mcp_url": local_mcp_url,
        }
    })
}

fn machine_failure_event(error: &ProductError) -> serde_json::Value {
    json!({
        "event": "failure",
        "schema_version": 1,
        "provider": "cloudflare",
        "failure_stage": "tunnel",
        "reason_code": error.code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(
        local_server_url: &str,
        tunnel_token: &str,
        runtime_parent: &Path,
    ) -> CloudflareNamedTunnelOptions {
        CloudflareNamedTunnelOptions {
            local_server_url: local_server_url.into(),
            bootstrap_token: "wc_boot_fixture".into(),
            tunnel_token: tunnel_token.into(),
            runtime_parent: runtime_parent.to_path_buf(),
            stop_on_stdin_eof: false,
        }
    }

    /// A named Tunnel only ever fronts the loopback local Server. Anything else
    /// would mean WebCodex is proxying a remote origin it does not own.
    #[test]
    fn named_tunnel_rejects_non_loopback_server_origins() {
        assert!(validate_local_server_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_local_server_url("http://localhost:8080").is_ok());
        for origin in ["https://example.test", "http://0.0.0.0:8080", "not a url"] {
            let error = validate_local_server_url(origin).unwrap_err();
            assert_eq!(error.code, "unsupported_topology", "{origin}");
        }
    }

    /// The token check must run before any session directory or process exists,
    /// so a misconfigured profile cannot leave scratch state behind.
    #[tokio::test]
    async fn named_tunnel_requires_a_cloudflare_tunnel_token() {
        let temp = tempfile::tempdir().unwrap();
        for token in ["", "   ", "\t\n"] {
            let error = run_cloudflare_named_tunnel_inner(
                &options("http://127.0.0.1:8080", token, temp.path()),
                std::future::pending::<()>(),
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, "tunnel_configuration", "{token:?}");
            assert_eq!(
                error.message, "the Cloudflare Tunnel token is unavailable",
                "{token:?}"
            );
        }
        assert!(
            !temp.path().join("cloudflare-tunnel-runtime").exists(),
            "no runtime state may be created before the token is validated"
        );
    }

    #[tokio::test]
    async fn named_tunnel_rejects_a_remote_local_server_before_spawning_cloudflared() {
        let temp = tempfile::tempdir().unwrap();
        let error = run_cloudflare_named_tunnel_inner(
            &options("https://example.test", "cf-token", temp.path()),
            std::future::pending::<()>(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "unsupported_topology");
        assert!(!temp.path().join("cloudflare-tunnel-runtime").exists());
    }

    /// cloudflared writes its own state, so the run directory must be private
    /// and must be removed when the runtime ends.
    #[test]
    fn named_tunnel_session_is_private_and_cleaned_up() {
        let temp = tempfile::tempdir().unwrap();
        let session = NamedTunnelSession::create(temp.path()).unwrap();
        let directory = session.directory.clone();
        assert!(directory.starts_with(temp.path().join("cloudflare-tunnel-runtime")));
        assert!(
            directory
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("named-"),
            "{directory:?}"
        );
        drop(session);
        assert!(!directory.exists());
        // Only this run's directory is removed; the shared root is reused.
        assert!(temp.path().join("cloudflare-tunnel-runtime").exists());
    }

    #[cfg(unix)]
    #[test]
    fn named_tunnel_runtime_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let session = NamedTunnelSession::create(temp.path()).unwrap();
        let mode = std::fs::metadata(&session.directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "tunnel runtime state must not be world readable"
        );
    }

    /// Readiness is the `Registered tunnel connection` log line and nothing
    /// looser — a near miss must not be reported as a live tunnel.
    #[tokio::test]
    async fn only_the_registered_connection_line_marks_the_tunnel_ready() {
        let registered = Arc::new(AtomicBool::new(false));
        spawn_registration_reader(
            b"INF Starting tunnel\n\
              INF Registering tunnel connection\n\
              ERR connection registered but unusable\n"
                .as_slice(),
            registered.clone(),
        )
        .await
        .unwrap();
        assert!(!registered.load(Ordering::Relaxed));

        let registered = Arc::new(AtomicBool::new(false));
        spawn_registration_reader(
            b"INF Starting tunnel\n\
              INF Registered tunnel connection connIndex=0\n"
                .as_slice(),
            registered.clone(),
        )
        .await
        .unwrap();
        assert!(registered.load(Ordering::Relaxed));
    }

    #[test]
    fn named_tunnel_ready_event_never_claims_a_client_handoff() {
        let event = machine_named_tunnel_ready_event("http://127.0.0.1:8080/mcp");
        assert_eq!(event["event"], "ready");
        assert_eq!(event["schema_version"], 1);
        assert_eq!(event["provider"], "cloudflare");
        assert_eq!(event["connection"]["kind"], "cloudflare_named_tunnel");
        assert_eq!(
            event["connection"]["hostname_source"],
            "cloudflare_dashboard"
        );
        assert_eq!(
            event["connection"]["local_mcp_url"],
            "http://127.0.0.1:8080/mcp"
        );
        // The hostname lives in the Cloudflare dashboard, so there is nothing
        // for WebCodex to hand over.
        assert_eq!(event["ready_for_chatgpt"], false);
        let encoded = serde_json::to_string(&event).unwrap();
        assert!(!encoded.contains("TUNNEL_TOKEN"), "{encoded}");
        assert!(!encoded.contains("Bearer"), "{encoded}");
        assert!(!encoded.contains("wc_boot_"), "{encoded}");
    }

    #[test]
    fn named_tunnel_failure_event_is_typed_bounded_and_secret_free() {
        let error = ProductError::new(
            "tunnel_not_ready",
            "private cloudflare token must never cross the machine channel",
            Some("private recovery text"),
        );
        let event = machine_failure_event(&error);
        assert_eq!(event["event"], "failure");
        assert_eq!(event["schema_version"], 1);
        assert_eq!(event["provider"], "cloudflare");
        assert_eq!(event["failure_stage"], "tunnel");
        assert_eq!(event["reason_code"], "tunnel_not_ready");
        let encoded = serde_json::to_string(&event).unwrap();
        assert!(!encoded.contains("private cloudflare token"), "{encoded}");
        assert!(!encoded.contains("private recovery"), "{encoded}");
        assert!(!encoded.contains("Authorization"), "{encoded}");
        assert!(!encoded.contains("Bearer"), "{encoded}");
    }

    /// Same throttle policy the OpenAI regular Tunnel uses: a parent-owned
    /// pipe heartbeats every tick; a standalone service emits changes and one
    /// 60s summary. Named Tunnel must not spam the machine channel.
    #[test]
    fn named_tunnel_health_events_throttle_like_the_regular_tunnel() {
        let start = std::time::Instant::now();
        let mut events = HealthEvents::new(false);
        assert!(events.should_emit(start, true, false));
        assert!(!events.should_emit(start + Duration::from_secs(2), true, false));
        assert!(events.should_emit(start + Duration::from_secs(4), true, true));
        assert!(!events.should_emit(start + Duration::from_secs(6), true, true));
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: &std::ffi::OsStr) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// Process environment is process-wide. Share the crate-wide test env lock
    /// so these cases cannot race `WEBCODEX_CLOUDFLARED_BIN` with other tests.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::admin_cli::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Point `WEBCODEX_CLOUDFLARED_BIN` at a disposable script so the runtime
    /// code under test is the real spawn/supervise path, not a mock.
    #[cfg(unix)]
    fn fake_cloudflared(script: &str) -> (tempfile::TempDir, PathBuf, EnvGuard) {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cloudflared");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let guard = EnvGuard::set("WEBCODEX_CLOUDFLARED_BIN", path.as_os_str());
        (temp, path, guard)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn named_tunnel_startup_deadline_is_reported_when_the_edge_never_registers() {
        let _lock = env_lock();
        // Never prints the registration marker: the only outcome is the
        // startup deadline.
        let (_bin_dir, _bin, _guard) = fake_cloudflared("#!/bin/sh\nsleep 30\n");
        let temp = tempfile::tempdir().unwrap();
        let error = run_cloudflare_named_tunnel_inner(
            &options("http://127.0.0.1:8080", "cf-token", temp.path()),
            std::future::pending::<()>(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "tunnel_not_ready");
        assert!(
            error.message.contains("did not register"),
            "{:?}",
            error.message
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn named_tunnel_reports_child_exit_before_the_edge_registers() {
        let _lock = env_lock();
        let (_bin_dir, _bin, _guard) = fake_cloudflared("#!/bin/sh\nexit 3\n");
        let temp = tempfile::tempdir().unwrap();
        let error = run_cloudflare_named_tunnel_inner(
            &options("http://127.0.0.1:8080", "cf-token", temp.path()),
            std::future::pending::<()>(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "tunnel_not_ready");
        assert!(
            error.message.contains("exited before registering"),
            "{:?}",
            error.message
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn named_tunnel_stop_signal_ends_the_runtime_without_waiting_out_startup() {
        let _lock = env_lock();
        let (_bin_dir, _bin, _guard) = fake_cloudflared("#!/bin/sh\nsleep 30\n");
        let temp = tempfile::tempdir().unwrap();
        // Stop is already ready: the readiness loop must return Ok and not
        // wait out the startup deadline.
        let result = run_cloudflare_named_tunnel_inner(
            &options("http://127.0.0.1:8080", "cf-token", temp.path()),
            std::future::ready(()),
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn named_tunnel_exit_clears_service_health_and_cleans_the_session() {
        use std::os::unix::fs::PermissionsExt;
        let _lock = env_lock();
        let (_bin_dir, _bin, _guard) = fake_cloudflared(
            "#!/bin/sh\n\
             echo 'INF Registered tunnel connection connIndex=0'\n\
             sleep 30\n",
        );
        let temp = tempfile::tempdir().unwrap();
        // write_tunnel_health requires a regular owner-only file.
        let readiness = temp.path().join("readiness.json");
        std::fs::write(
            &readiness,
            "{\"tunnel_ready\":true,\"local_mcp_ready\":true}",
        )
        .unwrap();
        std::fs::set_permissions(&readiness, std::fs::Permissions::from_mode(0o600)).unwrap();
        let _profile = EnvGuard::set("WEBCODEX_TUNNEL_PROFILE_ID", "fixture".as_ref());

        // Stop only after the registration marker has been seen and the ready
        // event printed, so the run reaches the supervision select and the
        // health-clear path below it.
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let _ = tx.send(());
        });
        let result = run_cloudflare_named_tunnel_inner(
            &options("http://127.0.0.1:8080", "cf-token", temp.path()),
            async move {
                let _ = rx.await;
            },
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        let health = std::fs::read_to_string(&readiness).unwrap();
        assert!(
            health.contains("false"),
            "service health must be cleared on exit: {health}"
        );
        let root = temp.path().join("cloudflare-tunnel-runtime");
        if root.exists() {
            let empty = std::fs::read_dir(&root)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false);
            assert!(
                empty,
                "the named session directory must be removed when the runtime ends"
            );
        }
    }
}
