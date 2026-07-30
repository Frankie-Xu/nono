//! Audit-only platform enrollment and protected local identity state.

use crate::cli::{
    PlatformArgs, PlatformCommands, PlatformEnrollArgs, PlatformStatusArgs, PlatformUnenrollArgs,
};
use crate::trust_keystore::{self, TrustKeyRef};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

pub(crate) const REQUEST_PROTOCOL_V1: &str = "1";
pub(crate) const ENROLLMENT_PROTOCOL_V1: &str = "1";
pub(crate) const KEY_ALGORITHM: &str = "ecdsa_p256_sha256_fixed";
const PLATFORM_KEY_SERVICE: &str = "nono-platform";
const PLATFORM_STATE_FILENAME: &str = "platform.json";
const RESPONSE_LIMIT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PlatformState {
    pub protocol_version: String,
    pub platform_url: String,
    pub tenant_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub management_mode: String,
    pub key_algorithm: String,
    pub key_ref: String,
    pub enrolled_at: String,
}

#[derive(Debug, Serialize)]
struct EnrollmentExchangeRequest {
    protocol_version: String,
    token: String,
    subject_kind: String,
    display_name: Option<String>,
    key_algorithm: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct EnrollmentExchangeResponse {
    protocol_version: String,
    tenant_id: String,
    subject_id: String,
    subject_kind: String,
    management_mode: String,
    enrolled_at: String,
}

pub(crate) fn run_platform(args: PlatformArgs) -> Result<()> {
    match args.command {
        PlatformCommands::Enroll(args) => enroll(args),
        PlatformCommands::Status(args) => status(args),
        PlatformCommands::Unenroll(args) => unenroll(args),
    }
}

fn enroll(args: PlatformEnrollArgs) -> Result<()> {
    let platform_url = validate_platform_url(&args.url)?;
    let state_path = state_path()?;
    if state_path.exists() {
        return Err(NonoError::ConfigParse(format!(
            "platform enrollment already exists at {}; re-enrollment and key rotation are not implemented",
            state_path.display()
        )));
    }

    let key_ref = TrustKeyRef::parse(&args.keyref)?;
    let key_label = key_ref.key_id()?;
    let key_pair =
        if trust_keystore::contains_secret_for_ref(&key_ref, PLATFORM_KEY_SERVICE, &key_label)? {
            load_signing_key_for_ref(&key_ref)?
        } else {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|_| {
                    NonoError::KeystoreAccess("failed to generate platform key".to_string())
                })?;
            let key_pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
                    .map_err(|_| {
                        NonoError::KeystoreAccess(
                            "failed to load generated platform key".to_string(),
                        )
                    })?;
            let private_key = Zeroizing::new(STANDARD.encode(pkcs8.as_ref()));
            trust_keystore::store_secret_for_ref(
                &key_ref,
                PLATFORM_KEY_SERVICE,
                &key_label,
                private_key.as_str(),
            )?;
            key_pair
        };

    let request = EnrollmentExchangeRequest {
        protocol_version: ENROLLMENT_PROTOCOL_V1.to_string(),
        token: args.token,
        subject_kind: if args.workload { "workload" } else { "device" }.to_string(),
        display_name: args.name,
        key_algorithm: KEY_ALGORITHM.to_string(),
        public_key: URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref()),
    };
    let response = post_enrollment(&platform_url, &request)?;
    if response.protocol_version != ENROLLMENT_PROTOCOL_V1
        || response.management_mode != "audit_only"
    {
        return Err(NonoError::ConfigParse(
            "platform returned an unsupported enrollment contract".to_string(),
        ));
    }

    let state = PlatformState {
        protocol_version: response.protocol_version,
        platform_url,
        tenant_id: response.tenant_id,
        subject_id: response.subject_id,
        subject_kind: response.subject_kind,
        management_mode: response.management_mode,
        key_algorithm: KEY_ALGORITHM.to_string(),
        key_ref: args.keyref,
        enrolled_at: response.enrolled_at,
    };
    write_json_secure(&state_path, &state)?;
    println!("Enrolled for audit-only delivery.");
    println!("  Tenant:  {}", state.tenant_id);
    println!("  Subject: {}", state.subject_id);
    println!("  Platform: {}", state.platform_url);
    Ok(())
}

fn status(args: PlatformStatusArgs) -> Result<()> {
    let Some(state) = load_state()? else {
        if args.json {
            println!(r#"{{"enrolled":false}}"#);
        } else {
            println!("Not enrolled with a platform.");
        }
        return Ok(());
    };
    if args.json {
        let output = serde_json::json!({
            "enrolled": true,
            "platform_url": state.platform_url,
            "tenant_id": state.tenant_id,
            "subject_id": state.subject_id,
            "subject_kind": state.subject_kind,
            "management_mode": state.management_mode,
            "enrolled_at": state.enrolled_at,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .map_err(|error| NonoError::ConfigParse(error.to_string()))?
        );
    } else {
        println!("Platform enrollment");
        println!("  Platform: {}", state.platform_url);
        println!("  Tenant:   {}", state.tenant_id);
        println!("  Subject:  {} ({})", state.subject_id, state.subject_kind);
        println!("  Mode:     {}", state.management_mode);
    }
    Ok(())
}

/// Remove the local enrollment. Local-only by design: the platform-side
/// subject stays active until a human revokes it in the console, because the
/// device key must not be able to erase its own registration.
fn unenroll(args: PlatformUnenrollArgs) -> Result<()> {
    let state_path = state_path()?;
    let Some(state) = load_state()? else {
        println!("Not enrolled with a platform.");
        return Ok(());
    };
    let queued = crate::audit_client::queued_count()?;

    fs::remove_file(&state_path).map_err(|source| NonoError::ConfigWrite {
        path: state_path.clone(),
        source,
    })?;
    println!("Unenrolled from {}.", state.platform_url);
    println!(
        "  Subject {} stays registered with tenant {} until an operator revokes it.",
        state.subject_id, state.tenant_id
    );
    if args.delete_key {
        let key_ref = TrustKeyRef::parse(&state.key_ref)?;
        let key_label = key_ref.key_id()?;
        trust_keystore::remove_secret_for_ref(&key_ref, PLATFORM_KEY_SERVICE, &key_label)?;
        println!("  Local signing key deleted; the next enrollment mints a new one.");
    } else {
        println!("  Local signing key kept; pass --delete-key to remove it.");
    }
    if queued > 0 {
        println!(
            "  {queued} audit session(s) remain queued and will be delivered after the next \
             enrollment."
        );
    }
    Ok(())
}

fn post_enrollment(
    platform_url: &str,
    request: &EnrollmentExchangeRequest,
) -> Result<EnrollmentExchangeResponse> {
    let endpoint = endpoint_url(platform_url, "/api/v1/enrollment/exchange")?;
    let agent = http_agent(Duration::from_secs(15));
    let body = serde_json::to_string(request)
        .map_err(|error| NonoError::ConfigParse(format!("failed to encode enrollment: {error}")))?;
    let mut response = agent
        .post(&endpoint)
        .config()
        .http_status_as_error(false)
        .build()
        .header("Content-Type", "application/json")
        .send(&body)
        .map_err(|error| NonoError::ConfigParse(format!("enrollment request failed: {error}")))?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let message = response
            .body_mut()
            .with_config()
            .limit(RESPONSE_LIMIT_BYTES)
            .read_to_string()
            .unwrap_or_default();
        return Err(NonoError::ConfigParse(format!(
            "platform enrollment returned HTTP {status}: {message}"
        )));
    }
    let response_body = response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT_BYTES)
        .read_to_string()
        .map_err(|error| NonoError::ConfigParse(format!("invalid enrollment response: {error}")))?;
    serde_json::from_str(&response_body)
        .map_err(|error| NonoError::ConfigParse(format!("invalid enrollment response: {error}")))
}

pub(crate) fn load_state() -> Result<Option<PlatformState>> {
    let path = state_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path).map_err(|source| NonoError::ConfigRead {
        path: path.clone(),
        source,
    })?;
    let state = serde_json::from_str::<PlatformState>(&contents)
        .map_err(|error| NonoError::ConfigParse(format!("invalid {}: {error}", path.display())))?;
    if state.protocol_version != ENROLLMENT_PROTOCOL_V1
        || state.key_algorithm != KEY_ALGORITHM
        || state.management_mode != "audit_only"
    {
        return Err(NonoError::ConfigParse(
            "unsupported local platform enrollment state".to_string(),
        ));
    }
    Ok(Some(state))
}

pub(crate) fn load_signing_key(state: &PlatformState) -> Result<EcdsaKeyPair> {
    let key_ref = TrustKeyRef::parse(&state.key_ref)?;
    load_signing_key_for_ref(&key_ref)
}

fn load_signing_key_for_ref(key_ref: &TrustKeyRef) -> Result<EcdsaKeyPair> {
    let key_label = key_ref.key_id()?;
    let encoded = match key_ref {
        TrustKeyRef::Keystore(_) => trust_keystore::load_secret(PLATFORM_KEY_SERVICE, &key_label)?,
        TrustKeyRef::File(path) => nono::load_secret_file(path)?,
    };
    let bytes =
        Zeroizing::new(STANDARD.decode(encoded.as_bytes()).map_err(|error| {
            NonoError::KeystoreAccess(format!("invalid platform key: {error}"))
        })?);
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &bytes)
        .map_err(|_| NonoError::KeystoreAccess("invalid platform signing key".to_string()))
}

pub(crate) fn canonical_request_v1(
    method: &str,
    path: &str,
    subject_id: &str,
    timestamp_ms: &str,
    request_id: &str,
    body_digest: &str,
) -> String {
    format!(
        "nono-request-v1\n{method}\n{path}\n{subject_id}\n{timestamp_ms}\n{request_id}\n{body_digest}"
    )
}

pub(crate) fn endpoint_url(platform_url: &str, path: &str) -> Result<String> {
    let base = url::Url::parse(platform_url)
        .map_err(|error| NonoError::ConfigParse(format!("invalid platform URL: {error}")))?;
    base.join(path)
        .map(|url| url.to_string())
        .map_err(|error| NonoError::ConfigParse(format!("invalid platform endpoint: {error}")))
}

pub(crate) fn http_agent(global_timeout: Duration) -> ureq::Agent {
    let tls_config = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    ureq::Agent::config_builder()
        .timeout_global(Some(global_timeout))
        .timeout_resolve(Some(Duration::from_secs(2)))
        .timeout_connect(Some(Duration::from_secs(2)))
        .timeout_recv_response(Some(Duration::from_secs(5)))
        .tls_config(tls_config)
        .build()
        .new_agent()
}

fn validate_platform_url(value: &str) -> Result<String> {
    let mut url = url::Url::parse(value)
        .map_err(|error| NonoError::ConfigParse(format!("invalid platform URL: {error}")))?;
    let loopback_http =
        url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if url.scheme() != "https" && !loopback_http {
        return Err(NonoError::ConfigParse(
            "platform URL must use HTTPS; HTTP is allowed only for loopback dogfooding".to_string(),
        ));
    }
    url.set_query(None);
    url.set_fragment(None);
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(if path.is_empty() { "/" } else { &path });
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn state_path() -> Result<PathBuf> {
    crate::config::user_config_dir()
        .map(|dir| dir.join(PLATFORM_STATE_FILENAME))
        .ok_or_else(|| {
            NonoError::ConfigParse("could not resolve nono config directory".to_string())
        })
}

pub(crate) fn write_json_secure<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| NonoError::ConfigParse(format!("path has no parent: {}", path.display())))?;
    fs::create_dir_all(parent).map_err(|source| NonoError::ConfigWrite {
        path: parent.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
        NonoError::ConfigWrite {
            path: parent.to_path_buf(),
            source,
        }
    })?;

    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|source| NonoError::ConfigWrite {
            path: tmp.clone(),
            source,
        })?;
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(|source| NonoError::ConfigWrite {
            path: tmp.clone(),
            source,
        })?;
    let encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| NonoError::ConfigParse(format!("failed to encode JSON: {error}")))?;
    file.write_all(&encoded)
        .and_then(|_| file.sync_all())
        .map_err(|source| NonoError::ConfigWrite {
            path: tmp.clone(),
            source,
        })?;
    fs::rename(&tmp, path).map_err(|source| NonoError::ConfigWrite {
        path: path.to_path_buf(),
        source,
    })?;
    if let Ok(parent_file) = File::open(parent) {
        let _ = parent_file.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct CanonicalFixture {
        method: String,
        path: String,
        subject_id: String,
        timestamp_ms: String,
        request_id: String,
        body_digest: String,
        canonical: String,
    }

    #[test]
    fn canonical_request_matches_protocol_fixture() {
        let fixture: CanonicalFixture = serde_json::from_str(include_str!(
            "../../../tests/fixtures/audit-request-v1.json"
        ))
        .expect("valid canonical request fixture");
        assert_eq!(
            canonical_request_v1(
                &fixture.method,
                &fixture.path,
                &fixture.subject_id,
                &fixture.timestamp_ms,
                &fixture.request_id,
                &fixture.body_digest,
            ),
            fixture.canonical
        );
    }

    #[test]
    fn http_is_limited_to_loopback() {
        assert!(validate_platform_url("http://127.0.0.1:8090").is_ok());
        assert!(validate_platform_url("http://localhost:8090").is_ok());
        assert!(validate_platform_url("http://example.com").is_err());
        assert!(validate_platform_url("https://example.com").is_ok());
    }
}
