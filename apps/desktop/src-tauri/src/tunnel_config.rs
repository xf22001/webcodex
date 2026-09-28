//! Persistent desired connection profiles. Secret-bearing types are deliberately
//! neither Debug nor public Serialize; only the dedicated safe projection leaves here.
use crate::connection_id::TunnelProfileId;
use crate::error::{DesktopError, DesktopResult};
use crate::models::{OpenAiTunnelConfigSnapshot, TunnelConfigSource};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;
use webcodex_environment::TunnelProvider;

const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PROFILES: usize = 128;
const SCHEMA_VERSION: u32 = 2;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    /// Absent in files written before the provider dimension existed; those
    /// profiles are OpenAI Secure MCP Tunnels, which is `TunnelProvider`'s
    /// default. The provider is part of the credential's identity: the two
    /// providers' secrets are never interchangeable.
    #[serde(default)]
    provider: TunnelProvider,
    tunnel_id: String,
    api_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelProfile {
    id: TunnelProfileId,
    name: String,
    // None is allowed only for the reserved legacy environment profile.
    credentials: Option<Credentials>,
    enabled: bool,
    autostart: bool,
    revision: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProfiles {
    schema_version: u32,
    profiles: Vec<TunnelProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelProfileConfigSnapshot {
    pub id: TunnelProfileId,
    pub name: String,
    pub provider: TunnelProvider,
    pub tunnel_id: Option<String>,
    pub credential_present: bool,
    pub enabled: bool,
    pub autostart: bool,
    pub revision: u64,
    pub source: TunnelConfigSource,
}

#[derive(Clone)]
pub struct TunnelConfig {
    stored: StoredProfiles,
    invalid: bool,
    original: Option<Vec<u8>>,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            stored: StoredProfiles {
                schema_version: SCHEMA_VERSION,
                profiles: Vec::new(),
            },
            invalid: false,
            original: None,
        }
    }
}

// Write-only IPC input. An omitted API key retains that exact profile's
// credential; an explicitly supplied key must itself be a valid secret.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelProfileRequest {
    pub id: Option<TunnelProfileId>,
    pub name: String,
    /// Defaults to the OpenAI Secure MCP Tunnel so a request from an older
    /// Desktop build keeps its original meaning.
    #[serde(default)]
    pub provider: TunnelProvider,
    pub tunnel_id: String,
    pub api_key: Option<String>,
    pub autostart: bool,
    pub expected_revision: Option<u64>,
}

// First-run/Quick Share legacy default controls; never select an arbitrary profile.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum TunnelConfigRequest {
    Save {
        #[serde(rename = "tunnelId")]
        tunnel_id: String,
        #[serde(rename = "apiKey")]
        api_key: Option<String>,
    },
    UseEnvironment,
}

impl TunnelConfig {
    /// Resolve the exact saved profile for a native service handoff. The
    /// returned secrets are transient and are never included in a snapshot.
    pub(crate) fn credentials_for(
        &self,
        id: TunnelProfileId,
    ) -> DesktopResult<webcodex_environment::TunnelCredentials> {
        if self.invalid {
            return Err(invalid());
        }
        let profile = self
            .stored
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .ok_or_else(missing)?;
        let credentials = match &profile.credentials {
            Some(pair) => pair.clone(),
            None if id == TunnelProfileId::DEFAULT => Credentials {
                // The environment fallback is the legacy OpenAI Secure Tunnel
                // identity: CONTROL_PLANE_* is the only credential pair WebCodex
                // reads from the process environment.
                provider: TunnelProvider::OpenAiSecure,
                tunnel_id: std::env::var("CONTROL_PLANE_TUNNEL_ID")
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
                api_key: std::env::var("CONTROL_PLANE_API_KEY")
                    .unwrap_or_default()
                    .trim()
                    .to_owned(),
            },
            None => return Err(invalid()),
        };
        validate_credentials(
            credentials.provider,
            &credentials.tunnel_id,
            &credentials.api_key,
        )?;
        Ok(webcodex_environment::TunnelCredentials {
            provider: credentials.provider,
            tunnel_id: webcodex_environment::Secret::new(credentials.tunnel_id),
            api_key: webcodex_environment::Secret::new(credentials.api_key),
        })
    }

    /// The provider this profile is bound to. A Desktop-managed launch needs it
    /// before the profile's secrets are read, so the Tunnel command is built
    /// with the same provider the profile was configured with.
    pub(crate) fn provider_for(&self, id: TunnelProfileId) -> DesktopResult<TunnelProvider> {
        if self.invalid {
            return Err(invalid());
        }
        let profile = self
            .stored
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .ok_or_else(missing)?;
        Ok(profile
            .credentials
            .as_ref()
            .map(|pair| pair.provider)
            .unwrap_or_default())
    }

    pub fn load(path: &Path, legacy_autostart: bool) -> Self {
        Self::load_with_writer(path, legacy_autostart, |path, bytes, original| {
            write_guarded(path, bytes, original)
        })
    }

    fn load_with_writer<F>(path: &Path, legacy_autostart: bool, writer: F) -> Self
    where
        F: FnOnce(&Path, &[u8], Option<&[u8]>) -> DesktopResult<()>,
    {
        let original = match read_bytes(path) {
            Ok(value) => value,
            Err(_) => {
                return Self {
                    invalid: true,
                    ..Self::default()
                }
            }
        };
        let mut config = Self {
            original: original.clone(),
            ..Self::default()
        };
        let decoded = (|| -> DesktopResult<(StoredProfiles, bool)> {
            let Some(bytes) = original.as_deref() else {
                return Ok((
                    StoredProfiles {
                        schema_version: SCHEMA_VERSION,
                        profiles: vec![legacy_profile(None, legacy_autostart)],
                    },
                    false,
                ));
            };
            let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            if value.get("schema_version").is_some() {
                let stored: StoredProfiles =
                    serde_json::from_value(value).map_err(|_| invalid())?;
                validate_store(&stored)?;
                return Ok((stored, false));
            }
            let credentials: Option<Credentials> =
                serde_json::from_value(value).map_err(|_| invalid())?;
            if let Some(pair) = &credentials {
                validate_credentials(pair.provider, &pair.tunnel_id, &pair.api_key)?;
            }
            Ok((
                StoredProfiles {
                    schema_version: SCHEMA_VERSION,
                    profiles: vec![legacy_profile(credentials, legacy_autostart)],
                },
                true,
            ))
        })();
        match decoded {
            Ok((stored, migrate)) => {
                if migrate {
                    let encoded = match encode(&stored) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            config.invalid = true;
                            return config;
                        }
                    };
                    if writer(path, &encoded, original.as_deref()).is_err() {
                        // Never fall back to a different environment identity after a failed migration.
                        config.invalid = true;
                        return config;
                    }
                    config.original = Some(encoded);
                }
                config.stored = stored;
            }
            Err(_) => config.invalid = true,
        }
        config
    }

    pub fn profiles(&self) -> Vec<TunnelProfileConfigSnapshot> {
        if self.invalid {
            return Vec::new();
        }
        self.stored
            .profiles
            .iter()
            .filter_map(|profile| {
                let safe = profile_credentials_snapshot(profile);
                if profile.credentials.is_none() && !safe.tunnel_id_present && !safe.api_key_present
                {
                    return None;
                }
                Some(TunnelProfileConfigSnapshot {
                    id: profile.id,
                    name: profile.name.clone(),
                    provider: profile
                        .credentials
                        .as_ref()
                        .map(|pair| pair.provider)
                        .unwrap_or_default(),
                    // A Cloudflare named Tunnel may carry no ID at all, since
                    // its token already identifies the tunnel.
                    tunnel_id: safe.effective_tunnel_id.filter(|value| !value.is_empty()),
                    credential_present: safe.api_key_present,
                    enabled: profile.enabled,
                    autostart: profile.autostart,
                    revision: profile.revision,
                    source: safe.source,
                })
            })
            .collect()
    }

    pub fn snapshot(&self) -> OpenAiTunnelConfigSnapshot {
        if self.invalid {
            return unavailable_snapshot(TunnelConfigSource::Invalid);
        }
        match self
            .stored
            .profiles
            .iter()
            .find(|p| p.id == TunnelProfileId::DEFAULT)
        {
            Some(profile) => profile_credentials_snapshot(profile),
            None => unavailable_snapshot(TunnelConfigSource::File),
        }
    }

    pub fn same_launch_as(&self, other: &Self, id: TunnelProfileId) -> bool {
        match (
            self.stored.profiles.iter().find(|p| p.id == id),
            other.stored.profiles.iter().find(|p| p.id == id),
        ) {
            (Some(a), Some(b)) => a.credentials == b.credentials,
            _ => false,
        }
    }

    pub fn is_invalid(&self) -> bool {
        self.invalid
    }

    pub fn update_profile(
        &mut self,
        path: &Path,
        request: TunnelProfileRequest,
    ) -> DesktopResult<TunnelProfileId> {
        if self.invalid {
            return Err(invalid());
        }
        let id = request.id.unwrap_or_else(TunnelProfileId::new);
        let previous = self.stored.profiles.iter().find(|p| p.id == id);
        if request.id.is_some() && previous.is_none() && id != TunnelProfileId::DEFAULT {
            return Err(missing());
        }
        if let Some(expected) = request.expected_revision {
            if previous.map(|p| p.revision) != Some(expected) {
                return Err(stale());
            }
        }
        let name = request.name.trim().to_string();
        validate_name(&name)?;
        let provider = request.provider;
        // A profile's provider is part of its identity: its saved environment
        // file and managed service are bound to exactly one transport. Changing
        // it in place would strand them, so a switch needs a new connection.
        if let Some(existing) = previous {
            if existing
                .credentials
                .as_ref()
                .map(|pair| pair.provider)
                .unwrap_or_default()
                != provider
            {
                return Err(DesktopError::new(
                    "tunnel_profile_provider_fixed",
                    "This connection is already bound to another Tunnel provider",
                    "Delete this connection and add a new one to use a different provider.",
                ));
            }
        }
        let tunnel_id = request.tunnel_id.trim().to_string();
        // Only an omitted key retains the saved secret. An explicitly supplied
        // key is the operator's new secret and must pass credential validation
        // on its own; whitespace must not silently fall back to the old value.
        let api_key = match request.api_key {
            Some(value) => value.trim().to_string(),
            None => previous
                .and_then(|p| p.credentials.as_ref())
                .map(|p| p.api_key.clone())
                .or_else(|| {
                    // Only the legacy OpenAI default falls back to the environment.
                    previous
                        .filter(|p| {
                            provider == TunnelProvider::OpenAiSecure
                                && p.id == TunnelProfileId::DEFAULT
                                && p.credentials.is_none()
                        })
                        .and_then(|_| std::env::var("CONTROL_PLANE_API_KEY").ok())
                })
                .ok_or_else(invalid)?,
        };
        validate_credentials(provider, &tunnel_id, &api_key)?;
        if !tunnel_id.is_empty()
            && self.profiles().iter().any(|p| {
                p.id != id
                    && p.provider == provider
                    && p.tunnel_id.as_deref() == Some(tunnel_id.as_str())
            })
        {
            return Err(DesktopError::new(
                "tunnel_profile_duplicate",
                "This Tunnel ID is already assigned to a connection",
                "Use the independent Tunnel ID issued for this account.",
            ));
        }
        let next = TunnelProfile {
            id,
            name,
            credentials: Some(Credentials {
                provider,
                tunnel_id,
                api_key,
            }),
            enabled: previous.map(|p| p.enabled).unwrap_or(true),
            autostart: request.autostart,
            revision: next_revision(previous.map(|p| p.revision))?,
        };
        let mut stored = self.stored.clone();
        match stored.profiles.iter().position(|p| p.id == id) {
            Some(index) => stored.profiles[index] = next,
            None => stored.profiles.push(next),
        }
        self.persist(path, stored)?;
        Ok(id)
    }

    /// First-run's explicit Connect action also remembers its startup intent.
    pub fn enable_default_onboarding(&mut self, path: &Path) -> DesktopResult<()> {
        if self.invalid {
            return Err(invalid());
        }
        let mut next = self.stored.clone();
        let profile = next
            .profiles
            .iter_mut()
            .find(|p| p.id == TunnelProfileId::DEFAULT)
            .ok_or_else(missing)?;
        if profile.enabled && profile.autostart {
            return Ok(());
        }
        profile.enabled = true;
        profile.autostart = true;
        profile.revision = next_revision(Some(profile.revision))?;
        self.persist(path, next)
    }

    pub fn set_enabled(
        &mut self,
        path: &Path,
        id: TunnelProfileId,
        enabled: bool,
    ) -> DesktopResult<()> {
        if self.invalid {
            return Err(invalid());
        }
        let mut next = self.stored.clone();
        let profile = next
            .profiles
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(missing)?;
        if profile.enabled == enabled {
            return Ok(());
        }
        profile.enabled = enabled;
        profile.revision = next_revision(Some(profile.revision))?;
        self.persist(path, next)
    }

    pub fn remove(&mut self, path: &Path, id: TunnelProfileId) -> DesktopResult<()> {
        if self.invalid {
            return Err(invalid());
        }
        let mut next = self.stored.clone();
        let index = next
            .profiles
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(missing)?;
        next.profiles.remove(index);
        // An explicit empty collection is authoritative: deleting default cannot revive env fallback.
        self.persist(path, next)
    }

    pub fn update(&mut self, path: &Path, request: TunnelConfigRequest) -> DesktopResult<()> {
        match request {
            TunnelConfigRequest::Save { tunnel_id, api_key } => {
                let existing = self
                    .stored
                    .profiles
                    .iter()
                    .find(|p| p.id == TunnelProfileId::DEFAULT);
                let name = existing
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "ChatGPT".into());
                let autostart = existing.map(|p| p.autostart).unwrap_or(true);
                self.update_profile(
                    path,
                    TunnelProfileRequest {
                        id: Some(TunnelProfileId::DEFAULT),
                        name,
                        // First-run/legacy onboarding is the OpenAI Secure MCP
                        // Tunnel. A Cloudflare named Tunnel is added as its own
                        // connection instead.
                        provider: TunnelProvider::OpenAiSecure,
                        tunnel_id,
                        api_key,
                        autostart,
                        expected_revision: None,
                    },
                )?;
                Ok(())
            }
            TunnelConfigRequest::UseEnvironment => {
                if self.invalid {
                    return Err(invalid());
                }
                let mut next = self.stored.clone();
                let index = next
                    .profiles
                    .iter()
                    .position(|p| p.id == TunnelProfileId::DEFAULT);
                let mut profile = legacy_profile(None, true);
                if let Some(index) = index {
                    profile.name = next.profiles[index].name.clone();
                    profile.enabled = next.profiles[index].enabled;
                    profile.autostart = next.profiles[index].autostart;
                    profile.revision = next_revision(Some(next.profiles[index].revision))?;
                    next.profiles[index] = profile;
                } else {
                    next.profiles.push(profile);
                }
                self.persist(path, next)
            }
        }
    }

    pub fn apply_to_command(&self, command: &mut Command) -> DesktopResult<()> {
        self.apply_profile_to_command(TunnelProfileId::DEFAULT, command)
    }

    pub fn apply_profile_to_command(
        &self,
        id: TunnelProfileId,
        command: &mut Command,
    ) -> DesktopResult<()> {
        if self.invalid {
            return Err(invalid());
        }
        let profile = self
            .stored
            .profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(missing)?;
        let credentials = match &profile.credentials {
            Some(pair) => pair.clone(),
            None if id == TunnelProfileId::DEFAULT => Credentials {
                // The environment fallback is the legacy OpenAI Secure Tunnel
                // identity: CONTROL_PLANE_* is the only credential pair WebCodex
                // reads from the process environment.
                provider: TunnelProvider::OpenAiSecure,
                tunnel_id: std::env::var("CONTROL_PLANE_TUNNEL_ID")
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                api_key: std::env::var("CONTROL_PLANE_API_KEY")
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            },
            None => return Err(invalid()),
        };
        validate_credentials(
            credentials.provider,
            &credentials.tunnel_id,
            &credentials.api_key,
        )?;
        if !credentials.tunnel_id.is_empty()
            && self.profiles().iter().any(|p| {
                p.id != id
                    && p.provider == credentials.provider
                    && p.tunnel_id.as_deref() == Some(credentials.tunnel_id.as_str())
            })
        {
            return Err(invalid());
        }
        // Each provider's transport reads its own credential keys, so a saved
        // profile never has to be reinterpreted as another provider's shape.
        match credentials.provider {
            TunnelProvider::OpenAiSecure => {
                command
                    .env("CONTROL_PLANE_TUNNEL_ID", &credentials.tunnel_id)
                    .env("CONTROL_PLANE_API_KEY", &credentials.api_key);
            }
            TunnelProvider::CloudflareNamed => {
                if !credentials.tunnel_id.is_empty() {
                    command.env("WEBCODEX_CLOUDFLARE_TUNNEL_ID", &credentials.tunnel_id);
                }
                command.env("WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN", &credentials.api_key);
            }
        }
        command.env("WEBCODEX_TUNNEL_PROFILE_ID", id.to_string());
        Ok(())
    }

    fn persist(&mut self, path: &Path, stored: StoredProfiles) -> DesktopResult<()> {
        validate_store(&stored)?;
        let bytes = encode(&stored)?;
        write_guarded(path, &bytes, self.original.as_deref())?;
        self.stored = stored;
        self.original = Some(bytes);
        self.invalid = false;
        Ok(())
    }
}

fn legacy_profile(credentials: Option<Credentials>, autostart: bool) -> TunnelProfile {
    TunnelProfile {
        id: TunnelProfileId::DEFAULT,
        name: "ChatGPT".into(),
        credentials,
        enabled: autostart,
        autostart,
        revision: 1,
    }
}

fn profile_credentials_snapshot(profile: &TunnelProfile) -> OpenAiTunnelConfigSnapshot {
    match &profile.credentials {
        Some(pair) => OpenAiTunnelConfigSnapshot {
            tunnel_id_present: true,
            api_key_present: true,
            source: TunnelConfigSource::File,
            saved_tunnel_id: Some(pair.tunnel_id.clone()),
            effective_tunnel_id: Some(pair.tunnel_id.clone()),
        },
        None => environment_snapshot(),
    }
}

pub fn environment_snapshot() -> OpenAiTunnelConfigSnapshot {
    let id = std::env::var("CONTROL_PLANE_TUNNEL_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| valid_id(s));
    let key_present = std::env::var("CONTROL_PLANE_API_KEY")
        .ok()
        .is_some_and(|s| valid_key(s.trim()));
    OpenAiTunnelConfigSnapshot {
        tunnel_id_present: id.is_some(),
        api_key_present: key_present,
        source: TunnelConfigSource::Environment,
        saved_tunnel_id: None,
        effective_tunnel_id: id,
    }
}

fn unavailable_snapshot(source: TunnelConfigSource) -> OpenAiTunnelConfigSnapshot {
    OpenAiTunnelConfigSnapshot {
        tunnel_id_present: false,
        api_key_present: false,
        source,
        saved_tunnel_id: None,
        effective_tunnel_id: None,
    }
}

fn validate_store(stored: &StoredProfiles) -> DesktopResult<()> {
    if stored.schema_version != SCHEMA_VERSION || stored.profiles.len() > MAX_PROFILES {
        return Err(invalid());
    }
    let mut ids = HashSet::new();
    let mut tunnels = HashSet::new();
    for profile in &stored.profiles {
        if !ids.insert(profile.id) || profile.revision == 0 {
            return Err(invalid());
        }
        validate_name(&profile.name)?;
        if let Some(pair) = &profile.credentials {
            validate_credentials(pair.provider, &pair.tunnel_id, &pair.api_key)?;
            // An empty label is the normal Cloudflare case, and two empty
            // labels are not a conflict. The same ID under two different
            // providers is also not a conflict, so the key includes the provider.
            if !pair.tunnel_id.is_empty()
                && !tunnels.insert((pair.provider, pair.tunnel_id.clone()))
            {
                return Err(invalid());
            }
        } else if profile.id != TunnelProfileId::DEFAULT {
            return Err(invalid());
        }
    }
    Ok(())
}
fn validate_name(name: &str) -> DesktopResult<()> {
    if name.is_empty() || name.len() > 160 || name.chars().any(char::is_control) {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 8192 && key.bytes().all(|b| b.is_ascii_graphic())
}
/// A Cloudflare named Tunnel token. Stricter than `valid_key` because this
/// secret is later written into the line-oriented profile file, where a quote,
/// backslash or newline would corrupt the record.
fn valid_tunnel_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 8192
        && token.bytes().all(|b| b.is_ascii_graphic())
        && !token.contains(['"', '\''])
}
/// Credential shape rules, per provider. An OpenAI Secure MCP Tunnel needs the
/// issued `tunnel_<hex>` ID plus its restricted key; a Cloudflare named Tunnel
/// is managed remotely, so its token alone is the credential and the optional
/// ID is only a human-readable label.
fn validate_credentials(provider: TunnelProvider, id: &str, key: &str) -> DesktopResult<()> {
    let valid = match provider {
        TunnelProvider::OpenAiSecure => valid_id(id) && valid_key(key),
        TunnelProvider::CloudflareNamed => {
            (id.is_empty() || valid_id(id)) && valid_tunnel_token(key)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn next_revision(previous: Option<u64>) -> DesktopResult<u64> {
    previous.unwrap_or(0).checked_add(1).ok_or_else(invalid)
}
fn encode(stored: &StoredProfiles) -> DesktopResult<Vec<u8>> {
    let bytes = serde_json::to_vec(stored).map_err(|_| invalid())?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}
fn read_bytes(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(bytes))
}
fn write_guarded(path: &Path, bytes: &[u8], expected: Option<&[u8]>) -> DesktopResult<()> {
    crate::state::write_atomic_file_with_hook(path, bytes, |_| {
        if read_bytes(path)?.as_deref() != expected {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(())
    })
    .map_err(|_| {
        DesktopError::new(
            "tunnel_config_unavailable",
            "Connection settings could not be saved",
            "Refresh Desktop and retry after checking private configuration access.",
        )
    })
}
fn invalid() -> DesktopError {
    DesktopError::new("tunnel_config_invalid", "Connection settings are invalid or unavailable", "Check the connection name, Tunnel ID and credential. Invalid saved files are never replaced implicitly.")
}
fn missing() -> DesktopError {
    DesktopError::new(
        "tunnel_profile_missing",
        "This connection no longer exists",
        "Refresh the connection list.",
    )
}
fn stale() -> DesktopError {
    DesktopError::new(
        "tunnel_profile_changed",
        "This connection changed while being edited",
        "Refresh the connection before saving again.",
    )
}

#[cfg(test)]
mod tests;
