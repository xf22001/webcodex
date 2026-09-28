use super::super::support::*;

#[test]
fn server_tunnel_parser_is_machine_owned_and_accepts_both_providers() {
    let parsed = parse_server_tunnel(&args(&[
        "--provider",
        "openai",
        "--env-file",
        "local.env",
        "--json",
        "--stop-on-stdin-eof",
    ]))
    .unwrap();
    assert_eq!(parsed.env_file, PathBuf::from("local.env"));
    assert_eq!(parsed.provider, ServerTunnelProvider::OpenAiSecure);
    assert!(parsed.stop_on_stdin_eof);

    let persistent = parse_server_tunnel(&args(&[
        "--provider",
        "openai",
        "--env-file",
        "local.env",
        "--json",
    ]))
    .unwrap();
    assert!(!persistent.stop_on_stdin_eof);

    let named = parse_server_tunnel(&args(&[
        "--provider",
        "cloudflare",
        "--env-file",
        "local.env",
        "--json",
    ]))
    .unwrap();
    assert_eq!(named.provider, ServerTunnelProvider::CloudflareNamed);
    assert!(!named.stop_on_stdin_eof);

    assert!(parse_server_tunnel(&args(&[
        "--provider",
        "quick",
        "--env-file",
        "local.env",
        "--json",
    ]))
    .unwrap_err()
    .contains("expected openai or cloudflare"));
    assert!(
        parse_server_tunnel(&args(&["--provider", "openai", "--env-file", "local.env",])).is_err()
    );
}

#[test]
fn regular_tunnel_bootstrap_token_follows_server_env_precedence() {
    let _guard = env_test_guard();
    let tmp = tempfile::tempdir().unwrap();
    let env_file = tmp.path().join("webcodex.env");
    std::fs::write(&env_file, "WEBCODEX_TOKEN=file-bootstrap\n").unwrap();

    let _env = EnvGuard::new().remove("WEBCODEX_TOKEN");
    assert_eq!(
        crate::webcodex_cli::server::derive_regular_tunnel_bootstrap_token(&env_file).unwrap(),
        "file-bootstrap"
    );
    drop(_env);

    let _env = EnvGuard::new().set("WEBCODEX_TOKEN", "process-bootstrap");
    assert_eq!(
        crate::webcodex_cli::server::derive_regular_tunnel_bootstrap_token(&env_file).unwrap(),
        "process-bootstrap"
    );
}

#[test]
fn cloudflare_tunnel_token_follows_process_env_over_the_profile_file() {
    let _guard = env_test_guard();
    let tmp = tempfile::tempdir().unwrap();
    let env_file = tmp.path().join("webcodex.env");
    std::fs::write(&env_file, "WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN=file-token\n").unwrap();

    let _env = EnvGuard::new().remove("WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN");
    assert_eq!(
        crate::webcodex_cli::server::derive_cloudflare_tunnel_token(&env_file).unwrap(),
        "file-token"
    );
    drop(_env);

    // The process environment wins so an operator can override a saved profile
    // for one run without rewriting it.
    let _env = EnvGuard::new().set("WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN", "process-token");
    assert_eq!(
        crate::webcodex_cli::server::derive_cloudflare_tunnel_token(&env_file).unwrap(),
        "process-token"
    );
}

#[test]
fn cloudflare_tunnel_token_requires_a_non_blank_value_in_either_source() {
    let _guard = env_test_guard();
    let tmp = tempfile::tempdir().unwrap();
    let env_file = tmp.path().join("webcodex.env");
    let _env = EnvGuard::new().remove("WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN");

    // A profile that never mentions the key cannot supply a named Tunnel token.
    std::fs::write(&env_file, "WEBCODEX_TOKEN=server-bootstrap\n").unwrap();
    let error = crate::webcodex_cli::server::derive_cloudflare_tunnel_token(&env_file).unwrap_err();
    assert!(error.contains("WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN"), "{error}");

    // Present but blank counts as absent, not as an empty token.
    std::fs::write(&env_file, "WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN=   \n").unwrap();
    assert!(crate::webcodex_cli::server::derive_cloudflare_tunnel_token(&env_file).is_err());

    // Surrounding whitespace is never part of the token.
    std::fs::write(&env_file, "WEBCODEX_CLOUDFLARE_TUNNEL_TOKEN=  spaced-token  \n").unwrap();
    assert_eq!(
        crate::webcodex_cli::server::derive_cloudflare_tunnel_token(&env_file).unwrap(),
        "spaced-token"
    );
}

#[test]
fn regular_tunnel_server_url_is_derived_from_loopback_env_only() {
    let tmp = tempfile::tempdir().unwrap();
    let env_file = tmp.path().join("webcodex.env");
    std::fs::write(&env_file, "WEBCODEX_ADDR=0.0.0.0:18080\n").unwrap();
    assert_eq!(
        crate::webcodex_cli::server::derive_regular_tunnel_server_url(&env_file).unwrap(),
        "http://127.0.0.1:18080"
    );

    std::fs::write(&env_file, "WEBCODEX_ADDR=192.0.2.10:18080\n").unwrap();
    assert!(crate::webcodex_cli::server::derive_regular_tunnel_server_url(&env_file).is_err());
}
