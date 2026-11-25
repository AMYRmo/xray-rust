//! `tlsSettings.echConfigList` / `echSockopt` parsing: the pinned form, the
//! DNS-URL form, and the rejections.
use serde_json::{json, Value};
use xray_config::{parse_xray_json, DiagnosticSeverity};

/// Cloudflare's published ECHConfigList for cloudflare-ech.com, fetched
/// 2026-11-25. The keys rotate; the parser only checks structure, so
/// rotation cannot break this test.
const CLOUDFLARE_ECH: &str = "AEX+DQBBlAAgACAeUKbX0efnz7S4ardHYPaRON3+4GB2UJ6iBY4xKZo6fAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";

fn outbound(tls_settings: Value) -> Value {
    json!({"tag": "proxy", "protocol": "vless",
        "settings": {"vnext": [{"address": "server.example", "port": 443,
            "users": [{"id": "27848739-7e62-4138-9fd3-098a63964b6b", "encryption": "none"}]}]},
        "streamSettings": {"network": "raw", "security": "tls",
            "tlsSettings": tls_settings}})
}

fn errors_of(
    parsed: Result<xray_config::ParsedConfig, xray_config::ConfigParseError>,
) -> Vec<(String, String)> {
    parsed
        .err()
        .map(|error| {
            error
                .diagnostics
                .into_iter()
                .filter(|d| d.severity == DiagnosticSeverity::Error)
                .map(|d| (d.path.unwrap_or_default(), d.message))
                .collect()
        })
        .unwrap_or_default()
}

fn tls_errors(tls_settings: Value) -> Vec<(String, String)> {
    let config = json!({"outbounds": [outbound(tls_settings)]}).to_string();
    errors_of(parse_xray_json(&config))
}

#[test]
fn pinned_ech_config_list_parses() {
    let errors = tls_errors(json!({"serverName": "server.example", "echConfigList": CLOUDFLARE_ECH}));
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn dns_url_ech_config_list_parses() {
    let errors = tls_errors(json!({"serverName": "server.example",
        "echConfigList": "cloudflare-ech.com+https://1.1.1.1/dns-query"}));
    assert!(errors.is_empty(), "{errors:?}");
    let errors_bare = tls_errors(json!({"serverName": "server.example",
        "echConfigList": "https://1.1.1.1/dns-query"}));
    assert!(errors_bare.is_empty(), "{errors_bare:?}");
}

#[test]
fn ech_sockopt_object_parses() {
    let errors = tls_errors(json!({"serverName": "server.example",
        "echConfigList": CLOUDFLARE_ECH,
        "echSockopt": {"dialerProxy": "proxy-out"}}));
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn malformed_ech_config_list_is_rejected() {
    let errors = tls_errors(json!({"serverName": "server.example",
        "echConfigList": "!!!not-base64!!!"}));
    assert!(
        errors.iter().any(|(path, _)| path.ends_with("echConfigList")),
        "{errors:?}"
    );
    let errors_empty = tls_errors(json!({"serverName": "server.example", "echConfigList": ""}));
    assert!(
        errors_empty.iter().any(|(path, _)| path.ends_with("echConfigList")),
        "{errors_empty:?}"
    );
    // Valid base64, but not an ECHConfigList: wrong version, not 0xfe0d.
    let errors_version = tls_errors(json!({"serverName": "server.example", "echConfigList": "AAIAAA=="}));
    assert!(
        errors_version.iter().any(|(path, _)| path.ends_with("echConfigList")),
        "{errors_version:?}"
    );
}

#[test]
fn ech_config_url_with_unsupported_scheme_is_rejected() {
    let errors = tls_errors(json!({"serverName": "server.example",
        "echConfigList": "ftp://1.1.1.1/dns-query"}));
    assert!(
        errors.iter().any(|(path, _)| path.ends_with("echConfigList")),
        "{errors:?}"
    );
}

#[test]
fn non_string_ech_config_list_is_rejected() {
    let errors = tls_errors(json!({"serverName": "server.example", "echConfigList": 42}));
    assert!(
        errors.iter().any(|(path, _)| path.ends_with("echConfigList")),
        "{errors:?}"
    );
}
