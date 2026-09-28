use super::*;

fn input(args: &[&str]) -> Result<Input, String> {
    parse(
        &args
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>(),
    )
}

#[test]
fn business_choices_and_resume_are_unambiguous() {
    let create = input(&["configure", "--create", "--no-project"]).unwrap();
    assert!(create.create && create.no_project);
    let viewer = input(&[
        "configure",
        "--join",
        "https://server.example",
        "--no-project",
        "--token-file",
        "credential",
    ])
    .unwrap();
    assert!(viewer.no_project && viewer.token_file.is_some() && !viewer.code_stdin);
    let runner = input(&[
        "configure",
        "--join",
        "https://server.example",
        "--project",
        "project",
        "--code-stdin",
    ])
    .unwrap();
    assert!(runner.project.is_some() && runner.code_stdin && runner.token_file.is_none());
    let resumed = input(&["resume", "--code-stdin", "--new-pairing-code"]).unwrap();
    assert!(resumed.new_code && resumed.code_stdin);
    for args in [
        vec!["configure", "--create", "--join", "https://server.example"],
        vec!["configure", "--project", "a", "--no-project"],
        vec!["configure", "--join", "a", "--join", "b"],
        vec!["configure", "--token-file", "secret", "--code-stdin"],
        vec!["configure", "--development-build"],
    ] {
        assert!(input(&args).is_err());
    }
}

#[test]
fn projectless_runner_is_explicit_and_does_not_change_legacy_viewer_defaults() {
    let local = input(&["configure", "--create", "--runner"]).unwrap();
    assert!(local.runner && local.project.is_none());
    let remote = input(&[
        "configure",
        "--join",
        "https://server.example",
        "--runner",
        "--code-stdin",
    ])
    .unwrap();
    assert!(remote.runner && remote.project.is_none() && remote.code_stdin);
    assert!(
        !input(&["configure", "--create", "--no-project"])
            .unwrap()
            .runner
    );
    for command in ["status", "resume", "doctor", "start"] {
        assert!(input(&[command, "--runner"]).is_err());
    }
}

#[tokio::test]
async fn json_argument_errors_are_structured_and_do_not_echo_inputs() {
    let args = vec!["configure", "--api-key=private-fixture-value", "--json"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let error = run(&args).await.unwrap_err();
    let value: serde_json::Value = serde_json::from_str(&error).unwrap();
    assert_eq!(value["ok"], false);
    assert!(!error.contains("private-fixture-value"));
}

#[test]
fn tunnel_and_upgrade_inputs_never_take_literal_credentials() {
    let tunnel = input(&[
        "configure-tunnel",
        "work",
        "--credentials-file",
        "private.json",
    ])
    .unwrap();
    assert_eq!(tunnel.operand.as_deref(), Some("work"));
    assert!(input(&["configure-tunnel", "--api-key", "secret"]).is_err());
    assert!(input(&["status", "--credentials-file", "private.json"]).is_err());
    let upgrade = input(&[
        "upgrade-preflight",
        "--candidate-dir",
        "candidate",
        "--development-build",
    ])
    .unwrap();
    assert!(upgrade.development_build);
}

#[test]
fn explicit_runtime_directory_never_persists_the_temporary_invoking_cli() {
    let root = std::env::temp_dir().canonicalize().unwrap();
    let binaries = discover_binaries(Some(&root)).unwrap();
    for (path, name) in [
        (&binaries.cli, "webcodex"),
        (&binaries.server, "webcodex-server"),
        (&binaries.runner, "webcodex-runner"),
    ] {
        assert_eq!(
            *path,
            root.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
        );
    }
}

#[cfg(unix)]
#[test]
fn tunnel_credentials_require_owner_private_file_and_redact_parse_failure() {
    use std::os::unix::fs::PermissionsExt;
    let root =
        std::env::temp_dir().join(format!("webcodex-cli-credentials-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("credential.json");
    std::fs::write(
        &path,
        r#"{"tunnel_id":"fixture","api_key":"private-fixture-value"}"#,
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let credential = read_tunnel_credentials(&path).unwrap();
    assert_eq!(credential.api_key.expose(), "private-fixture-value");
    assert!(!format!("{credential:?}").contains("private-fixture-value"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_tunnel_credentials(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(
        &path,
        r#"{"tunnel_id":"fixture","api_key":"private-fixture-value","unknown":0}"#,
    )
    .unwrap();
    assert!(!read_tunnel_credentials(&path)
        .unwrap_err()
        .contains("private-fixture-value"));
    std::fs::remove_dir_all(root).unwrap();
}

/// Write a protected Tunnel credential file the way an operator would: both the
/// directory and the file have to be owner-only or `read_tunnel_credentials`
/// refuses to read them at all.
#[cfg(unix)]
fn private_credential_file(body: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let root =
        std::env::temp_dir().join(format!("webcodex-cli-provider-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("credential.json");
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (root, path)
}

#[cfg(unix)]
#[test]
fn a_credential_file_without_a_provider_stays_an_openai_secure_tunnel() {
    // Every credential file written before the provider dimension existed must
    // keep working unchanged, and must not be mistaken for a Cloudflare token.
    let (root, path) = private_credential_file(r#"{"tunnel_id":"legacy","api_key":"legacy-key"}"#);
    let credential = read_tunnel_credentials(&path).unwrap();
    assert_eq!(credential.provider, TunnelProvider::OpenAiSecure);
    assert_eq!(credential.tunnel_id.expose(), "legacy");
    assert_eq!(credential.api_key.expose(), "legacy-key");
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn a_cloudflare_credential_file_carries_the_token_and_an_optional_label() {
    // The token already identifies a dashboard-managed tunnel, so the label is
    // optional and is only used for human-readable status output.
    let (root, path) = private_credential_file(r#"{"provider":"cloudflare","token":"cf-token"}"#);
    let credential = read_tunnel_credentials(&path).unwrap();
    assert_eq!(credential.provider, TunnelProvider::CloudflareNamed);
    assert_eq!(credential.api_key.expose(), "cf-token");
    assert_eq!(credential.tunnel_id.expose(), "");
    std::fs::remove_dir_all(root).unwrap();

    let (root, path) = private_credential_file(
        r#"{"provider":"cloudflare","tunnel_id":"dashboard-label","token":"cf-token"}"#,
    );
    let credential = read_tunnel_credentials(&path).unwrap();
    assert_eq!(credential.provider, TunnelProvider::CloudflareNamed);
    assert_eq!(credential.tunnel_id.expose(), "dashboard-label");
    assert_eq!(credential.api_key.expose(), "cf-token");
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn a_credential_file_must_declare_exactly_one_secret_and_never_echoes_it() {
    for body in [
        // `token` and `api_key` are the two providers' secrets; accepting both
        // would silently pick one and leave the other profile's credential in a
        // file the operator believes belongs to the other provider.
        r#"{"provider":"cloudflare","tunnel_id":"label","token":"cf-token","api_key":"openai-key"}"#,
        r#"{"provider":"cloudflare","tunnel_id":"label"}"#,
        r#"{"tunnel_id":"label"}"#,
    ] {
        let (root, path) = private_credential_file(body);
        let error = read_tunnel_credentials(&path).unwrap_err();
        assert!(
            !error.contains("cf-token") && !error.contains("openai-key"),
            "{error}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn a_credential_file_rejects_a_provider_that_is_not_a_tunnel_transport() {
    // `quick` is a valid spelling for a transient share, but not for a saved
    // Tunnel profile; the error has to name the two that are accepted.
    let (root, path) = private_credential_file(r#"{"provider":"quick","token":"cf-token"}"#);
    let error = read_tunnel_credentials(&path).unwrap_err();
    assert!(error.contains("openai") && error.contains("cloudflare"), "{error}");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_provider_flag_is_scoped_to_configure_tunnel() {
    let named = input(&[
        "configure-tunnel",
        "work",
        "--provider",
        "cloudflare",
        "--credentials-file",
        "private.json",
    ])
    .unwrap();
    assert_eq!(named.operand.as_deref(), Some("work"));
    assert_eq!(named.provider.as_deref(), Some("cloudflare"));
    assert!(named.credentials_file.is_some());
    // Naming no provider keeps the historical behaviour: the value is only
    // interpreted by the command that owns it.
    assert!(input(&["configure-tunnel", "work"]).unwrap().provider.is_none());
    for command in ["tunnel-status", "remove-tunnel", "status"] {
        assert!(input(&[command, "--provider", "openai"]).is_err());
    }
}

#[test]
fn a_saved_profile_keeps_its_provider_until_it_is_removed() {
    // Nothing stored and nothing requested: the historical default.
    assert_eq!(
        resolve_tunnel_provider("work", None, None).unwrap(),
        TunnelProvider::OpenAiSecure
    );
    assert_eq!(
        resolve_tunnel_provider("work", None, Some(TunnelProvider::CloudflareNamed)).unwrap(),
        TunnelProvider::CloudflareNamed
    );
    // A stored profile supplies its own provider when the caller is silent.
    assert_eq!(
        resolve_tunnel_provider("work", Some(TunnelProvider::CloudflareNamed), None).unwrap(),
        TunnelProvider::CloudflareNamed
    );
    // Restating the stored provider is not a switch.
    assert_eq!(
        resolve_tunnel_provider(
            "work",
            Some(TunnelProvider::CloudflareNamed),
            Some(TunnelProvider::CloudflareNamed)
        )
        .unwrap(),
        TunnelProvider::CloudflareNamed
    );
    // Switching is refused: the saved credential would be stranded under a
    // service spec that can no longer start it.
    let error = resolve_tunnel_provider(
        "work",
        Some(TunnelProvider::OpenAiSecure),
        Some(TunnelProvider::CloudflareNamed),
    )
    .unwrap_err();
    assert!(error.contains("work"), "{error}");
    assert!(error.contains("openai"), "{error}");
    assert!(error.contains("remove-tunnel"), "{error}");
}

#[test]
fn an_explicit_provider_must_agree_with_the_credential_file() {
    let openai = TunnelCredentials {
        provider: TunnelProvider::OpenAiSecure,
        tunnel_id: Secret::new("tunnel".to_string()),
        api_key: Secret::new("private-fixture-value".to_string()),
    };
    // Naming no provider defers to the file, and restating it is not a conflict.
    assert!(check_credentials_provider(&openai, None).is_ok());
    assert!(check_credentials_provider(&openai, Some(TunnelProvider::OpenAiSecure)).is_ok());
    let error =
        check_credentials_provider(&openai, Some(TunnelProvider::CloudflareNamed)).unwrap_err();
    assert!(error.contains("cloudflare"), "{error}");
    assert!(error.contains("--credentials-file"), "{error}");
    assert!(!error.contains("private-fixture-value"), "{error}");
}

#[cfg(unix)]
#[tokio::test]
async fn installer_finalization_cannot_override_authorized_store() {
    let arguments = [
        "installer-finish",
        "--environment-dir",
        "/different-user/environment",
        "--json",
    ]
    .map(str::to_owned);
    let error = run(&arguments).await.unwrap_err();
    assert!(error.contains("fixed by the owner authorization"));
    assert!(!error.contains("/different-user"));
    let child = [
        "__installer-child",
        "4",
        "finish",
        "/different-user/environment",
    ]
    .map(str::to_owned);
    assert_eq!(
        run(&child).await.unwrap_err(),
        "Invalid internal installer request"
    );
}

#[test]
fn legacy_server_network_inputs_are_explicit_and_scoped() {
    let legacy = input(&[
        "migrate-legacy-server",
        "--user",
        "alice",
        "--listen",
        "0.0.0.0:8080",
        "--server-url",
        "http://127.0.0.1:8080",
        "--token-file",
        "private-token",
    ])
    .unwrap();
    assert_eq!(legacy.listen.as_deref(), Some("0.0.0.0:8080"));
    assert_eq!(legacy.username.as_deref(), Some("alice"));
    assert!(input(&["configure", "--create", "--listen", "0.0.0.0:8080"]).is_err());
}
