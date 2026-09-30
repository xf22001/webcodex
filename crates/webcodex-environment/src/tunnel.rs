//! Persistent Tunnel profiles retain the existing OpenAI connection identity.
//! Runner machines never import or acquire these credentials.
use crate::native::{bootstrap_token, env_value, service_error};
use crate::service::{Component, Ownership, ServiceAccount, ServiceManager, ServiceSpec};
use crate::storage::{atomic_private_write, ensure_private_directory};
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Which managed Tunnel provider a **persistent** profile is bound to.
///
/// This is the Server's long-lived transport, selected by
/// `webcodex server tunnel --provider`. It is deliberately *not* the same
/// dimension as `share`'s transient project tunnel: `share --tunnel cloudflare`
/// is a Cloudflare **quick** tunnel with a random hostname, while
/// `--provider cloudflare` here is a Cloudflare **named** tunnel the operator
/// created in the dashboard. Both are spelled `cloudflare` on the command line,
/// so the variants are named after what they actually are to keep the two
/// lists from being mixed.
///
/// The provider is part of a profile's identity: credentials are never
/// interchangeable between providers, and the persisted record is what lets a
/// later `tunnel-status`/`control-tunnel` rebuild the exact same service spec
/// without the caller having to remember which provider it configured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TunnelProvider {
    /// OpenAI Secure MCP Tunnel, driven by the pinned OpenAI `tunnel-client`.
    #[default]
    #[serde(rename = "openai")]
    OpenAiSecure,
    /// Cloudflare named Tunnel, driven by `cloudflared tunnel run --token`.
    /// The tunnel is managed in the Cloudflare dashboard, so the local side
    /// only needs the tunnel token; ingress and the public hostname never
    /// leave Cloudflare.
    #[serde(rename = "cloudflare")]
    CloudflareNamed,
}

impl TunnelProvider {
    /// The value accepted by `webcodex server tunnel --provider`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiSecure => "openai",
            Self::CloudflareNamed => "cloudflare",
        }
    }

    /// Environment keys holding this provider's identity and secret. Keeping
    /// them provider-specific means a saved profile is self-describing and a
    /// provider mismatch is detected instead of silently reusing a key.
    fn credential_keys(self) -> (&'static str, &'static str) {
        match self {
            Self::OpenAiSecure => ("CONTROL_PLANE_TUNNEL_ID", "CONTROL_PLANE_API_KEY"),
            Self::CloudflareNamed => (
                "WEBCODEX_CLOUDFLARE_TUNNEL_ID",
                "WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN",
            ),
        }
    }
}

impl std::str::FromStr for TunnelProvider {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "openai" => Ok(Self::OpenAiSecure),
            "cloudflare" => Ok(Self::CloudflareNamed),
            other => Err(format!(
                "unknown Tunnel provider {other:?}; expected openai or cloudflare"
            )),
        }
    }
}

#[derive(Debug)]
pub struct TunnelCredentials {
    pub provider: TunnelProvider,
    /// OpenAI Secure MCP Tunnel ID, or a Cloudflare tunnel ID/name. A
    /// remotely-managed Cloudflare tunnel token already identifies the tunnel,
    /// so the Cloudflare provider accepts an empty label.
    pub tunnel_id: Secret,
    /// OpenAI Restricted API key, or the Cloudflare tunnel token.
    pub api_key: Secret,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRecord {
    pub profile_id: String,
    pub installed: bool,
    pub started: bool,
    /// Absent in records written before the provider dimension existed; those
    /// profiles are OpenAI Secure MCP Tunnels.
    #[serde(default)]
    pub provider: TunnelProvider,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelRuntimeObservation {
    pub service_status: service::ServiceStatus,
    pub ready: bool,
    pub tunnel_ready: bool,
    pub local_mcp_ready: bool,
}
fn diagnostic(code: &str, message: &str) -> SetupDiagnostic {
    SetupDiagnostic::new(code, message, "Inspect the saved Tunnel profile and its system service; keep its original Tunnel ID and API credential")
}
fn validate_id(id: &str) -> SetupResultValue<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(diagnostic(
            "tunnel_profile",
            "Tunnel profile identifier is invalid",
        ));
    }
    Ok(())
}
/// Credential shape rules, per provider.
///
/// OpenAI Secure MCP Tunnel IDs are the fixed `tunnel_<32 lowercase hex>` form
/// issued by the control plane. A Cloudflare named tunnel is managed remotely,
/// so its token alone is sufficient and the optional tunnel ID/name is only a
/// human-readable label; both are bounded and rejected if they could break the
/// line-oriented `KEY=value` profile file.
fn valid_tunnel_credentials(provider: TunnelProvider, id: &str, api: &str) -> bool {
    if api.is_empty() || api.len() > 8192 || api.contains(['\n', '\r', '\0', '"', '\'']) {
        return false;
    }
    match provider {
        TunnelProvider::OpenAiSecure => id.strip_prefix("tunnel_").is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }),
        TunnelProvider::CloudflareNamed => {
            id.is_empty()
                || (id.len() <= 64
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
        }
    }
}

/// Render the profile's `KEY=value` environment file.
///
/// This file is the only artifact the Tunnel service reads, which makes its
/// key names a compatibility surface. The OpenAI body is byte-for-byte what
/// earlier releases wrote, and each provider carries only its own credential
/// keys so a saved profile stays self-describing — that is what lets a later
/// status/control call detect a provider mismatch instead of reusing a key
/// that belongs to the other product.
fn tunnel_env_file_content(
    provider: TunnelProvider,
    address: &str,
    bootstrap: &str,
    profile_id: &str,
    id: &str,
    api: &str,
) -> String {
    match provider {
        TunnelProvider::OpenAiSecure => format!(
            "WEBCODEX_ADDR={address}\nWEBCODEX_TOKEN={bootstrap}\nCONTROL_PLANE_TUNNEL_ID={id}\nCONTROL_PLANE_API_KEY={api}\nWEBCODEX_TUNNEL_PROFILE_ID={profile_id}\n"
        ),
        TunnelProvider::CloudflareNamed => {
            // A remotely-managed tunnel token already identifies the tunnel, so
            // the optional tunnel ID/name is omitted rather than written blank.
            let mut content = format!("WEBCODEX_ADDR={address}\nWEBCODEX_TOKEN={bootstrap}\n");
            if !id.is_empty() {
                content.push_str(&format!("WEBCODEX_CLOUDFLARE_TUNNEL_ID={id}\n"));
            }
            content.push_str(&format!(
                "WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN={api}\nWEBCODEX_TUNNEL_PROFILE_ID={profile_id}\n"
            ));
            content
        }
    }
}

/// Rebuild the service spec for an already-recorded profile. The provider is
/// read back from the persisted record so every caller — status, control,
/// removal, upgrade and migration — resolves the same provider the profile was
/// configured with. Records written before the provider dimension existed are
/// OpenAI Secure MCP Tunnels, which is what `TunnelProvider::default` means.
/// The provider a persisted profile is bound to.
///
/// A profile that is missing from the registry — or a record written before the
/// provider dimension existed — is an OpenAI Secure MCP Tunnel, because that
/// was the only provider then. Every caller that rebuilds a spec (status,
/// control, removal, upgrade, migration) resolves through here so they cannot
/// disagree about which transport a profile uses.
fn persisted_tunnel_provider(store: &EnvironmentStore, profile_id: &str) -> TunnelProvider {
    tunnel_profiles(store)
        .ok()
        .and_then(|profiles| {
            profiles
                .into_iter()
                .find(|profile| profile.profile_id == profile_id)
        })
        .map(|profile| profile.provider)
        .unwrap_or_default()
}

pub fn tunnel_service_spec(
    store: &EnvironmentStore,
    record: &EnvironmentRecord,
    profile_id: &str,
) -> SetupResultValue<ServiceSpec> {
    let provider = persisted_tunnel_provider(store, profile_id);
    tunnel_service_spec_for(store, record, profile_id, provider)
}

fn tunnel_service_spec_for(
    store: &EnvironmentStore,
    record: &EnvironmentRecord,
    profile_id: &str,
    provider: TunnelProvider,
) -> SetupResultValue<ServiceSpec> {
    validate_id(profile_id)?;
    if !record.request.local_server() {
        return Err(diagnostic(
            "tunnel_local_server",
            "A Tunnel can only be hosted by the Server machine",
        ));
    }
    let id = if cfg!(windows) {
        format!("WebCodexTunnel-{profile_id}")
    } else {
        format!("webcodex-tunnel-{profile_id}")
    };
    let directory = store.root().join("server/tunnels").join(profile_id);
    let env_file = directory.join("webcodex.env");
    let mut args = vec![
        "server".into(),
        "tunnel".into(),
        "--env-file".into(),
        env_file.to_string_lossy().into_owned(),
        "--provider".into(),
        provider.as_str().into(),
        "--json".into(),
    ];
    if cfg!(windows) && record.request.service_scope.is_system() {
        args.splice(0..0, ["--windows-service".into(), id.clone()]);
    }
    let account = if cfg!(windows) && record.request.service_scope.is_system() {
        ServiceAccount::WindowsVirtual {
            name: format!("NT SERVICE\\{id}"),
        }
    } else {
        ServiceAccount::SystemUser {
            name: record.request.account.name.clone(),
            group: None,
            expected_identity: record.request.account.identity.clone(),
            home: Some(record.request.account.home.clone()),
        }
    };
    let environment = if cfg!(target_os = "macos") {
        BTreeMap::from([(
            "WEBCODEX_SERVICE_LOG_DIR".into(),
            directory.to_string_lossy().into_owned(),
        )])
    } else {
        BTreeMap::new()
    };
    Ok(ServiceSpec {
        scope: record.request.service_scope,
        id,
        component: Component::Tunnel,
        program: record.request.binaries.cli.clone(),
        args,
        working_directory: directory,
        account,
        config_identity: format!("{}-tunnel-{profile_id}", record.environment_id),
        env_file: Some(env_file),
        environment,
        linux_socket: None,
    })
}
pub fn tunnel_profiles(store: &EnvironmentStore) -> SetupResultValue<Vec<TunnelRecord>> {
    store
        .read_json("tunnel.json")
        .map(|value| value.unwrap_or_default())
}
impl NativeEnvironment {
    pub async fn configure_tunnel(
        &self,
        store: &EnvironmentStore,
        profile_id: &str,
        credentials: Option<&TunnelCredentials>,
    ) -> SetupResultValue<service::ServiceStatus> {
        let lock = store.lock()?;
        crate::ensure_upgrade_idle_under_lock(store)?;
        self.configure_tunnel_under_lock(store, &lock, profile_id, credentials, true)
            .await
    }
    pub(crate) async fn configure_tunnel_under_lock(
        &self,
        store: &EnvironmentStore,
        _lock: &crate::storage::EnvironmentLock,
        profile_id: &str,
        credentials: Option<&TunnelCredentials>,
        start: bool,
    ) -> SetupResultValue<service::ServiceStatus> {
        let record = store
            .load_environment()?
            .or_else(|| {
                store
                    .load_journal()
                    .ok()
                    .flatten()
                    .map(|journal| journal.environment)
            })
            .ok_or_else(|| {
                diagnostic("not_configured", "Configure the Server environment first")
            })?;
        // A first configuration takes its provider from the supplied
        // credentials; a re-configuration without credentials keeps whatever
        // the persisted record already binds.
        let provider = match credentials {
            Some(credentials) => credentials.provider,
            None => tunnel_profiles(store)?
                .into_iter()
                .find(|profile| profile.profile_id == profile_id)
                .map(|profile| profile.provider)
                .unwrap_or_default(),
        };
        let spec = tunnel_service_spec_for(store, &record, profile_id, provider)?;
        ServiceManager::preflight(&spec).map_err(service_error)?;
        let path = spec.env_file.as_ref().unwrap();
        if !path.exists() {
            let credentials = credentials.ok_or_else(|| {
                diagnostic(
                    "tunnel_credentials",
                    "The original Tunnel credentials are required for the first configuration",
                )
            })?;
            let id = credentials.tunnel_id.expose();
            let api = credentials.api_key.expose();
            if !valid_tunnel_credentials(provider, id, api) {
                return Err(diagnostic(
                    "tunnel_credentials",
                    "Tunnel credentials are invalid",
                ));
            }
            ensure_private_directory(&spec.working_directory)?;
            let server = read_secret(&store.root().join("server/webcodex.env"))?;
            let address = env_value(server.expose(), "WEBCODEX_ADDR").ok_or_else(|| {
                diagnostic(
                    "server_configuration",
                    "Server listening address is unavailable",
                )
            })?;
            let bootstrap = bootstrap_token(store)?.expose().to_string();
            let content = Secret::new(tunnel_env_file_content(
                provider, &address, &bootstrap, profile_id, id, api,
            ));
            atomic_private_write(path, content.expose().as_bytes())?;
        } else if let Some(credentials) = credentials {
            let saved = read_secret(path)?;
            // The saved profile is self-describing: which credential keys it
            // carries decides its provider, so a provider swap is reported as
            // a conflict instead of being mistaken for a credential mismatch.
            let saved_provider =
                if env_value(saved.expose(), "WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN").is_some() {
                    TunnelProvider::CloudflareNamed
                } else {
                    TunnelProvider::OpenAiSecure
                };
            if saved_provider != provider {
                return Err(diagnostic(
                    "tunnel_binding_conflict",
                    "This profile already contains another Tunnel provider",
                ));
            }
            let (id_key, api_key) = provider.credential_keys();
            if env_value(saved.expose(), id_key).unwrap_or_default()
                != credentials.tunnel_id.expose()
                || env_value(saved.expose(), api_key).unwrap_or_default()
                    != credentials.api_key.expose()
            {
                return Err(diagnostic(
                    "tunnel_binding_conflict",
                    "This profile already contains another Tunnel identity or credential",
                ));
            }
        }
        let health = spec.working_directory.join("readiness.json");
        if !health.exists() {
            atomic_private_write(&health, b"{}")?;
        }
        let mut profiles = tunnel_profiles(store)?;
        if let Some(existing) = profiles
            .iter_mut()
            .find(|profile| profile.profile_id == profile_id)
        {
            // Keep the persisted record aligned with the provider the saved
            // credential file actually carries, so a later status/control call
            // rebuilds the same service spec.
            existing.provider = provider;
        } else {
            profiles.push(TunnelRecord {
                profile_id: profile_id.into(),
                installed: false,
                started: false,
                provider,
            });
        }
        store.write_json("tunnel.json", &profiles)?;
        // A saved inactive profile has no enabled boot service. Installation
        // occurs only when the user explicitly starts this profile.
        if !start {
            return ServiceManager::inspect(&spec).map_err(service_error);
        }
        let current = ServiceManager::inspect(&spec).map_err(service_error)?;
        // Reconfiguring an already running profile must not re-enter Install:
        // on Windows that path grants the virtual account access to private
        // state and is deliberately invalid against a live service.
        if tunnel_install_required(&current)? {
            crate::privilege::service_operation_spec(
                store,
                &record,
                spec.clone(),
                ServiceOperation::Install,
                None,
            )
            .await?;
        }
        profiles
            .iter_mut()
            .find(|profile| profile.profile_id == profile_id)
            .unwrap()
            .installed = true;
        store.write_json("tunnel.json", &profiles)?;
        if ServiceManager::inspect(&spec)
            .map_err(service_error)?
            .running
            != Some(true)
        {
            write_tunnel_health(&health, false, false)?;
        }
        let status = crate::privilege::service_operation_spec(
            store,
            &record,
            spec.clone(),
            ServiceOperation::Start,
            None,
        )
        .await?;
        wait_tunnel_readiness(&spec).await?;
        profiles
            .iter_mut()
            .find(|profile| profile.profile_id == profile_id)
            .unwrap()
            .started = status.running == Some(true);
        store.write_json("tunnel.json", &profiles)?;
        Ok(status)
    }
    pub fn tunnel_status(
        &self,
        store: &EnvironmentStore,
        profile_id: &str,
    ) -> SetupResultValue<TunnelRuntimeObservation> {
        let record = store
            .load_environment()?
            .ok_or_else(|| diagnostic("not_configured", "Configure this environment first"))?;
        let spec = tunnel_service_spec(store, &record, profile_id)?;
        let service_status = ServiceManager::inspect(&spec).map_err(service_error)?;
        let (tunnel_ready, local_mcp_ready) = if service_status.ownership == Ownership::Owned
            && service_status.running == Some(true)
        {
            read_health(&spec.working_directory.join("readiness.json")).unwrap_or((false, false))
        } else {
            (false, false)
        };
        Ok(TunnelRuntimeObservation {
            service_status,
            ready: tunnel_ready && local_mcp_ready,
            tunnel_ready,
            local_mcp_ready,
        })
    }
    pub async fn remove_tunnel(
        &self,
        store: &EnvironmentStore,
        profile_id: &str,
    ) -> SetupResultValue<()> {
        let _lock = store.lock()?;
        crate::ensure_upgrade_idle_under_lock(store)?;
        let record = store
            .load_environment()?
            .ok_or_else(|| diagnostic("not_configured", "Configure this environment first"))?;
        let spec = tunnel_service_spec(store, &record, profile_id)?;
        let status = ServiceManager::inspect(&spec).map_err(service_error)?;
        match status.ownership {
            Ownership::Owned => {
                crate::privilege::service_operation_spec(
                    store,
                    &record,
                    spec.clone(),
                    ServiceOperation::Stop,
                    None,
                )
                .await?;
                let removed = crate::privilege::service_operation_spec(
                    store,
                    &record,
                    spec.clone(),
                    ServiceOperation::Uninstall,
                    None,
                )
                .await?;
                if removed.ownership != Ownership::Absent {
                    return Err(diagnostic(
                        "tunnel_remove_uncertain",
                        "Tunnel service removal has not been confirmed",
                    ));
                }
            }
            Ownership::Absent => {}
            _ => {
                return Err(diagnostic(
                    "tunnel_owner",
                    "The saved Tunnel service owner cannot be verified",
                ))
            }
        }
        // Keep runtime logs for diagnosis. Remove only the exact saved credential
        // after the service is absent, so no live process loses its unique key.
        let env = spec.env_file.as_ref().unwrap();
        if env.exists() {
            std::fs::remove_file(env).map_err(|_| SetupDiagnostic::io())?;
        }
        let health = spec.working_directory.join("readiness.json");
        if health.exists() {
            std::fs::remove_file(health).map_err(|_| SetupDiagnostic::io())?;
        }
        let mut profiles = tunnel_profiles(store)?;
        profiles.retain(|profile| profile.profile_id != profile_id);
        store.write_json("tunnel.json", &profiles)
    }
    pub async fn control_tunnel(
        &self,
        store: &EnvironmentStore,
        profile_id: &str,
        operation: ServiceOperation,
    ) -> SetupResultValue<service::ServiceStatus> {
        let _lock = store.lock()?;
        crate::ensure_upgrade_idle_under_lock(store)?;
        let record = store.load_environment()?.ok_or_else(|| {
            diagnostic("not_configured", "Configure the Server environment first")
        })?;
        let spec = tunnel_service_spec(store, &record, profile_id)?;
        let status = ServiceManager::inspect(&spec).map_err(service_error)?;
        if status.ownership != Ownership::Owned {
            return Err(diagnostic(
                "tunnel_owner",
                "This Tunnel service is not owned by the saved profile",
            ));
        }
        if operation == ServiceOperation::Restart
            || operation == ServiceOperation::Start && status.running != Some(true)
        {
            write_tunnel_health(&spec.working_directory.join("readiness.json"), false, false)?;
        }
        let result =
            crate::privilege::service_operation_spec(store, &record, spec.clone(), operation, None)
                .await?;
        if matches!(
            operation,
            ServiceOperation::Start | ServiceOperation::Restart
        ) {
            wait_tunnel_readiness(&spec).await?;
        }
        Ok(result)
    }
}

fn tunnel_install_required(status: &service::ServiceStatus) -> SetupResultValue<bool> {
    match status.ownership {
        Ownership::Absent => Ok(true),
        Ownership::Owned if status.enabled == Some(true) => Ok(false),
        Ownership::Owned if status.enabled == Some(false) && status.running == Some(false) => Ok(true),
        Ownership::Owned => Err(diagnostic("tunnel_service_state_uncertain", "Tunnel boot state cannot be changed safely while the service is running or its state is unknown")),
        Ownership::Foreign => Err(diagnostic("tunnel_owner", "A different owner already controls this Tunnel service")),
        Ownership::Unknown => Err(diagnostic("tunnel_owner", "Tunnel service ownership cannot be verified")),
    }
}

/// Service heartbeat contains no Tunnel ID, key or authorization header. This
/// precreated file keeps the installer-selected ACL when a virtual account writes.
pub fn write_tunnel_health(
    path: &std::path::Path,
    tunnel_ready: bool,
    local_mcp_ready: bool,
) -> SetupResultValue<()> {
    use std::io::Write;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| SetupDiagnostic::io())?;
    if !metadata.is_file() || metadata.is_symlink() {
        return Err(SetupDiagnostic::io());
    }
    #[cfg(windows)]
    crate::runtime_entry::validate_windows_env_acl(path).map_err(|_| SetupDiagnostic::io())?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::OpenOptionsExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(SetupDiagnostic::io());
        }
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).map_err(|_| SetupDiagnostic::io())?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|_| SetupDiagnostic::io())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SetupDiagnostic::io())?
        .as_millis();
    let value = serde_json::json!({"schema_version":1,"observed_at_ms":now,"service_pid":std::process::id(),"tunnel_ready":tunnel_ready,"local_mcp_ready":local_mcp_ready});
    file.set_len(0)
        .and_then(|_| file.write_all(value.to_string().as_bytes()))
        .and_then(|_| file.sync_all())
        .map_err(|_| SetupDiagnostic::io())
}

pub(crate) async fn wait_tunnel_readiness(spec: &ServiceSpec) -> SetupResultValue<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(65);
    let path = spec.working_directory.join("readiness.json");
    loop {
        let status = ServiceManager::inspect(spec).map_err(service_error)?;
        if status.ownership != Ownership::Owned {
            return Err(diagnostic(
                "tunnel_owner",
                "Tunnel service ownership changed while checking readiness",
            ));
        }
        if status.running == Some(true) {
            let value = read_health(&path);
            if value.is_ok_and(|(tunnel, mcp)| tunnel && mcp) {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(diagnostic("tunnel_not_ready", "The Tunnel service is configured but Tunnel and local MCP readiness have not both been verified"));
        }
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + std::time::Duration::from_millis(250)).min(deadline),
        )
        .await;
    }
}
pub(crate) fn read_health(path: &std::path::Path) -> SetupResultValue<(bool, bool)> {
    use std::io::Read;
    let meta = std::fs::symlink_metadata(path).map_err(|_| SetupDiagnostic::io())?;
    if !meta.is_file() || meta.is_symlink() || meta.len() > 4096 {
        return Err(SetupDiagnostic::io());
    }
    #[cfg(windows)]
    crate::runtime_entry::validate_windows_env_acl(path).map_err(|_| SetupDiagnostic::io())?;
    let file = std::fs::File::open(path).map_err(|_| SetupDiagnostic::io())?;
    fs2::FileExt::try_lock_shared(&file).map_err(|_| SetupDiagnostic::io())?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| SetupDiagnostic::io())?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| SetupDiagnostic::io())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SetupDiagnostic::io())?
        .as_millis();
    let time = value
        .get("observed_at_ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as u128;
    let fresh = time <= now && now.saturating_sub(time) < 7000;
    Ok((
        fresh
            && value
                .get("tunnel_ready")
                .and_then(serde_json::Value::as_bool)
                == Some(true),
        fresh
            && value
                .get("local_mcp_ready")
                .and_then(serde_json::Value::as_bool)
                == Some(true),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_owned_tunnel_skips_reinstall_and_ambiguous_state_fails_closed() {
        let mut status = service::ServiceStatus {
            id: "webcodex-tunnel-main".into(),
            ownership: Ownership::Owned,
            installed: true,
            enabled: Some(true),
            running: Some(true),
            detail: None,
        };
        assert!(!tunnel_install_required(&status).unwrap());
        status.running = Some(false);
        status.enabled = Some(false);
        assert!(tunnel_install_required(&status).unwrap());
        status.running = Some(true);
        assert_eq!(
            tunnel_install_required(&status).unwrap_err().code,
            "tunnel_service_state_uncertain"
        );
        status.ownership = Ownership::Foreign;
        assert_eq!(
            tunnel_install_required(&status).unwrap_err().code,
            "tunnel_owner"
        );
    }

    // -----------------------------------------------------------------------
    // Provider dimension.
    //
    // Renaming the Rust variants (`OpenAiSecure` / `CloudflareNamed`) must not
    // move the persisted or command-line spelling, and each provider must own
    // its own credential keys: that is what keeps a saved profile
    // self-describing and makes a provider mismatch detectable instead of
    // silently reusing the other product's key.
    // -----------------------------------------------------------------------

    #[test]
    fn tunnel_provider_wire_names_are_stable_and_reject_the_rust_variant_names() {
        assert_eq!(
            serde_json::to_string(&TunnelProvider::OpenAiSecure).unwrap(),
            "\"openai\""
        );
        assert_eq!(
            serde_json::to_string(&TunnelProvider::CloudflareNamed).unwrap(),
            "\"cloudflare\""
        );
        assert_eq!(
            serde_json::from_str::<TunnelProvider>("\"openai\"").unwrap(),
            TunnelProvider::OpenAiSecure
        );
        assert_eq!(
            serde_json::from_str::<TunnelProvider>("\"cloudflare\"").unwrap(),
            TunnelProvider::CloudflareNamed
        );
        // The variant names themselves must never become a second, accepted
        // spelling — that is how a wire format silently forks.
        assert!(serde_json::from_str::<TunnelProvider>("\"openaisecure\"").is_err());
        assert!(serde_json::from_str::<TunnelProvider>("\"cloudflarenamed\"").is_err());
    }

    #[test]
    fn a_record_written_before_the_provider_dimension_is_an_openai_secure_tunnel() {
        let record: TunnelRecord =
            serde_json::from_str(r#"{"profile_id":"default","installed":true,"started":false}"#)
                .unwrap();
        assert_eq!(record.provider, TunnelProvider::OpenAiSecure);
        let round_trip = serde_json::to_string(&record).unwrap();
        assert!(
            round_trip.contains("\"provider\":\"openai\""),
            "{round_trip}"
        );
    }

    #[test]
    fn tunnel_provider_parses_the_command_line_spelling_only() {
        assert_eq!(
            "openai".parse::<TunnelProvider>().unwrap(),
            TunnelProvider::OpenAiSecure
        );
        // Case and surrounding whitespace are tolerated, but `share`'s extra
        // `none` value and anything else must be rejected here.
        assert_eq!(
            " CloudFlare ".parse::<TunnelProvider>().unwrap(),
            TunnelProvider::CloudflareNamed
        );
        for other in ["quick", "none", ""] {
            let error = other.parse::<TunnelProvider>().unwrap_err();
            assert!(
                error.contains("expected openai or cloudflare"),
                "{other}: {error}"
            );
        }
    }

    #[test]
    fn each_provider_owns_its_own_credential_keys() {
        assert_eq!(
            TunnelProvider::OpenAiSecure.credential_keys(),
            ("CONTROL_PLANE_TUNNEL_ID", "CONTROL_PLANE_API_KEY")
        );
        assert_eq!(
            TunnelProvider::CloudflareNamed.credential_keys(),
            (
                "WEBCODEX_CLOUDFLARE_TUNNEL_ID",
                "WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN"
            )
        );
    }

    #[test]
    fn openai_credentials_keep_the_control_plane_tunnel_id_shape() {
        let valid_id = format!("tunnel_{}", "0".repeat(32));
        assert!(valid_tunnel_credentials(
            TunnelProvider::OpenAiSecure,
            &valid_id,
            "fake-api-key"
        ));
        for invalid in [
            "",
            "tunnel_",
            "tunnel_short",
            "tunnel_0000000000000000000000000000000",
            "tunnel_000000000000000000000000000000000",
            "tunnel_0000000000000000000000000000000g",
            "not-a-tunnel-id",
        ] {
            assert!(
                !valid_tunnel_credentials(TunnelProvider::OpenAiSecure, invalid, "fake-api-key"),
                "OpenAI Secure MCP Tunnel must reject {invalid:?}"
            );
        }
    }

    #[test]
    fn cloudflare_credentials_allow_an_absent_label_but_not_an_invalid_one() {
        // A remotely-managed tunnel token already identifies the tunnel.
        assert!(valid_tunnel_credentials(
            TunnelProvider::CloudflareNamed,
            "",
            "cf-token"
        ));
        assert!(valid_tunnel_credentials(
            TunnelProvider::CloudflareNamed,
            "my-tunnel_01",
            "cf-token"
        ));
        let oversized = "a".repeat(65);
        for invalid in ["bad label", "bad/slash", oversized.as_str()] {
            assert!(
                !valid_tunnel_credentials(TunnelProvider::CloudflareNamed, invalid, "cf-token"),
                "Cloudflare must reject label {invalid:?}"
            );
        }
    }

    #[test]
    fn credentials_reject_values_that_would_break_the_profile_file() {
        // The profile is a line-oriented KEY=value file: a newline, quote or NUL
        // in a value would rewrite other keys.
        for api in [
            "",
            "line\nbreak",
            "carriage\rreturn",
            "nul\0byte",
            "quote\"mark",
            "single'quote",
        ] {
            assert!(
                !valid_tunnel_credentials(TunnelProvider::CloudflareNamed, "", api),
                "must reject {api:?}"
            );
        }
        let oversized = "a".repeat(8193);
        assert!(!valid_tunnel_credentials(
            TunnelProvider::CloudflareNamed,
            "",
            &oversized
        ));
    }

    #[test]
    fn openai_env_file_keeps_its_historical_key_order() {
        // Byte-for-byte what earlier releases wrote: an existing profile must
        // stay readable by an older binary and by the operator.
        let content = tunnel_env_file_content(
            TunnelProvider::OpenAiSecure,
            "127.0.0.1:8080",
            "wc_boot_fixture",
            "default",
            "tunnel_00000000000000000000000000000000",
            "fake-api-key",
        );
        assert_eq!(
            content,
            "WEBCODEX_ADDR=127.0.0.1:8080\n\
             WEBCODEX_TOKEN=wc_boot_fixture\n\
             CONTROL_PLANE_TUNNEL_ID=tunnel_00000000000000000000000000000000\n\
             CONTROL_PLANE_API_KEY=fake-api-key\n\
             WEBCODEX_TUNNEL_PROFILE_ID=default\n"
        );
    }

    #[test]
    fn cloudflare_env_file_carries_the_token_and_omits_an_absent_label() {
        let labelled = tunnel_env_file_content(
            TunnelProvider::CloudflareNamed,
            "127.0.0.1:8080",
            "wc_boot_fixture",
            "default",
            "my-tunnel",
            "cf-token",
        );
        assert_eq!(
            labelled,
            "WEBCODEX_ADDR=127.0.0.1:8080\n\
             WEBCODEX_TOKEN=wc_boot_fixture\n\
             WEBCODEX_CLOUDFLARE_TUNNEL_ID=my-tunnel\n\
             WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN=cf-token\n\
             WEBCODEX_TUNNEL_PROFILE_ID=default\n"
        );

        let unlabelled = tunnel_env_file_content(
            TunnelProvider::CloudflareNamed,
            "127.0.0.1:8080",
            "wc_boot_fixture",
            "default",
            "",
            "cf-token",
        );
        assert!(
            !unlabelled.contains("WEBCODEX_CLOUDFLARE_TUNNEL_ID"),
            "{unlabelled}"
        );
        assert!(
            unlabelled.contains("WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN=cf-token\n"),
            "{unlabelled}"
        );
    }

    #[test]
    fn an_env_file_never_carries_the_other_providers_credential_keys() {
        // Reading the file back is how the provider is identified, so the two
        // providers must not overlap on a key.
        let openai = tunnel_env_file_content(
            TunnelProvider::OpenAiSecure,
            "a",
            "b",
            "default",
            "id",
            "key",
        );
        assert!(openai.contains("CONTROL_PLANE_API_KEY=key\n"), "{openai}");
        assert!(
            !openai.contains("WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN"),
            "{openai}"
        );

        let cloudflare = tunnel_env_file_content(
            TunnelProvider::CloudflareNamed,
            "a",
            "b",
            "default",
            "id",
            "key",
        );
        assert!(
            cloudflare.contains("WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN=key\n"),
            "{cloudflare}"
        );
        assert!(
            !cloudflare.contains("CONTROL_PLANE_API_KEY"),
            "{cloudflare}"
        );
    }

    fn record_for(profile_id: &str, provider: TunnelProvider) -> TunnelRecord {
        TunnelRecord {
            profile_id: profile_id.into(),
            installed: true,
            started: false,
            provider,
        }
    }

    #[test]
    fn a_persisted_profile_supplies_the_provider_for_every_later_rebuild() {
        let temp = crate::test_tempdir().unwrap();
        let store = EnvironmentStore::open(temp.path().join("environment")).unwrap();

        // No registry at all: legacy behaviour, OpenAI Secure MCP Tunnel.
        assert_eq!(
            persisted_tunnel_provider(&store, "default"),
            TunnelProvider::OpenAiSecure
        );

        store
            .write_json(
                "tunnel.json",
                &vec![record_for("default", TunnelProvider::CloudflareNamed)],
            )
            .unwrap();
        assert_eq!(
            persisted_tunnel_provider(&store, "default"),
            TunnelProvider::CloudflareNamed
        );
        // An unknown profile must not borrow another profile's provider.
        assert_eq!(
            persisted_tunnel_provider(&store, "other"),
            TunnelProvider::OpenAiSecure
        );

        store
            .write_json(
                "tunnel.json",
                &vec![
                    record_for("alpha", TunnelProvider::CloudflareNamed),
                    record_for("beta", TunnelProvider::OpenAiSecure),
                ],
            )
            .unwrap();
        assert_eq!(
            persisted_tunnel_provider(&store, "alpha"),
            TunnelProvider::CloudflareNamed
        );
        assert_eq!(
            persisted_tunnel_provider(&store, "beta"),
            TunnelProvider::OpenAiSecure
        );
    }

    #[test]
    fn a_registry_written_before_the_provider_dimension_reads_back_as_openai() {
        let temp = crate::test_tempdir().unwrap();
        let store = EnvironmentStore::open(temp.path().join("environment")).unwrap();
        std::fs::create_dir_all(store.root()).unwrap();
        std::fs::write(
            store.root().join("tunnel.json"),
            r#"[{"profile_id":"default","installed":true,"started":true}]"#,
        )
        .unwrap();
        assert_eq!(
            persisted_tunnel_provider(&store, "default"),
            TunnelProvider::OpenAiSecure
        );
    }
}
