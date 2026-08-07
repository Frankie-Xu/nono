//! Invocation-scoped filesystem requests for Tool Sandbox commands.
//!
//! macOS cannot widen a live Seatbelt sandbox. The caller therefore describes
//! the exact access it wants at the shim boundary. The supervisor validates the
//! request against an explicit profile ceiling, asks the approval backend, and
//! only then adds the normalized grants to the fresh child sandbox.

use crate::command_policy::{CommandApprovalFilesystemConfig, CommandSandboxConfig};
use crate::tool_sandbox::env::split_env_entry;
use nono::{AccessMode, CommandFilesystemGrant, CommandFilesystemGrantKind, NonoError, Result};
use serde::Deserialize;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

pub(crate) const TOOL_SANDBOX_FS_REQUEST_ENV: &str = "NONO_TOOL_SANDBOX_FS_REQUEST";
const MAX_REQUESTED_GRANTS: usize = 32;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemRequestEnvelope {
    filesystem: Vec<RequestedFilesystemGrant>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestedFilesystemGrant {
    path: String,
    access: RequestedAccess,
    kind: CommandFilesystemGrantKind,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RequestedAccess {
    Read,
    Write,
    ReadWrite,
}

impl From<RequestedAccess> for AccessMode {
    fn from(value: RequestedAccess) -> Self {
        match value {
            RequestedAccess::Read => Self::Read,
            // Tool Sandbox `fs_write*` grants are read-write on both platform
            // backends. Normalize before approval so the backend sees the
            // capability that will actually be installed.
            RequestedAccess::Write => Self::ReadWrite,
            RequestedAccess::ReadWrite => Self::ReadWrite,
        }
    }
}

pub(crate) fn resolve_requested_filesystem(
    request_env: &[Vec<u8>],
    request_cwd: &[u8],
    policy: &CommandSandboxConfig,
    policy_root: &Path,
    deny_paths: &[PathBuf],
) -> Result<Vec<CommandFilesystemGrant>> {
    let mut encoded: Option<&[u8]> = None;
    for entry in request_env {
        let Some((name, value)) = split_env_entry(entry) else {
            continue;
        };
        if name == TOOL_SANDBOX_FS_REQUEST_ENV.as_bytes() && encoded.replace(value).is_some() {
            return Err(NonoError::ConfigParse(format!(
                "tool-sandbox request contains duplicate {TOOL_SANDBOX_FS_REQUEST_ENV} entries"
            )));
        }
    }
    let Some(encoded) = encoded else {
        return Ok(Vec::new());
    };
    let ceiling = policy.approval_fs.as_ref().ok_or_else(|| {
        NonoError::BlockedCommand {
            command: "filesystem approval".to_string(),
            reason: format!(
                "{TOOL_SANDBOX_FS_REQUEST_ENV} was supplied but the selected command sandbox has no approval_fs ceiling"
            ),
        }
    })?;
    let envelope: FilesystemRequestEnvelope = serde_json::from_slice(encoded).map_err(|err| {
        NonoError::ConfigParse(format!("invalid {TOOL_SANDBOX_FS_REQUEST_ENV} JSON: {err}"))
    })?;
    if envelope.filesystem.is_empty() {
        return Err(NonoError::ConfigParse(format!(
            "{TOOL_SANDBOX_FS_REQUEST_ENV}.filesystem must not be empty"
        )));
    }
    if envelope.filesystem.len() > MAX_REQUESTED_GRANTS {
        return Err(NonoError::ConfigParse(format!(
            "{TOOL_SANDBOX_FS_REQUEST_ENV} exceeds the {MAX_REQUESTED_GRANTS}-grant limit"
        )));
    }

    let cwd = PathBuf::from(OsString::from_vec(request_cwd.to_vec()))
        .canonicalize()
        .map_err(|source| NonoError::PathCanonicalization {
            path: PathBuf::from(OsString::from_vec(request_cwd.to_vec())),
            source,
        })?;
    let read_roots = resolve_ceiling_roots(&ceiling.read_roots, policy_root, &cwd)?;
    let write_roots = resolve_ceiling_roots(&ceiling.write_roots, policy_root, &cwd)?;

    let mut grants: Vec<CommandFilesystemGrant> = Vec::new();
    for requested in envelope.filesystem {
        if requested.path.is_empty() || requested.path.as_bytes().contains(&0) {
            return Err(NonoError::ConfigParse(
                "tool-sandbox filesystem request contains an empty path or NUL byte".to_string(),
            ));
        }
        let unresolved = PathBuf::from(&requested.path);
        let unresolved = if unresolved.is_absolute() {
            unresolved
        } else {
            cwd.join(unresolved)
        };
        let path = unresolved
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: unresolved.clone(),
                source,
            })?;
        if path == Path::new("/") {
            return Err(NonoError::BlockedCommand {
                command: "filesystem approval".to_string(),
                reason: "cannot grant the filesystem root".to_string(),
            });
        }
        let metadata = std::fs::metadata(&path).map_err(|source| NonoError::ConfigRead {
            path: path.clone(),
            source,
        })?;
        match requested.kind {
            CommandFilesystemGrantKind::File if !metadata.is_file() => {
                return Err(NonoError::ExpectedFile(path));
            }
            CommandFilesystemGrantKind::Directory if !metadata.is_dir() => {
                return Err(NonoError::ExpectedDirectory(path));
            }
            CommandFilesystemGrantKind::File | CommandFilesystemGrantKind::Directory => {}
        }
        if overlaps_deny(&path, requested.kind, deny_paths) {
            return Err(NonoError::BlockedCommand {
                command: "filesystem approval".to_string(),
                reason: format!("requested path overlaps a deny: {}", path.display()),
            });
        }
        let access = AccessMode::from(requested.access);
        let allowed = match access {
            AccessMode::Read => read_roots
                .iter()
                .chain(write_roots.iter())
                .any(|root| path.starts_with(root)),
            AccessMode::Write | AccessMode::ReadWrite => {
                write_roots.iter().any(|root| path.starts_with(root))
            }
        };
        if !allowed {
            return Err(NonoError::BlockedCommand {
                command: "filesystem approval".to_string(),
                reason: format!(
                    "requested path exceeds its approval_fs ceiling: {} ({access})",
                    path.display()
                ),
            });
        }

        if let Some(existing) = grants
            .iter_mut()
            .find(|grant| grant.path == path && grant.kind == requested.kind)
        {
            existing.access = merge_access(existing.access, access);
        } else {
            grants.push(CommandFilesystemGrant {
                path,
                access,
                kind: requested.kind,
            });
        }
    }
    Ok(grants)
}

fn resolve_ceiling_roots(
    entries: &[String],
    policy_root: &Path,
    cwd: &Path,
) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::with_capacity(entries.len());
    for entry in entries {
        let expanded = crate::profile::expand_vars(entry, policy_root)?;
        let path = if expanded.is_absolute() {
            expanded
        } else {
            cwd.join(expanded)
        };
        let canonical = path
            .canonicalize()
            .map_err(|source| NonoError::PathCanonicalization {
                path: path.clone(),
                source,
            })?;
        if canonical == Path::new("/") || !canonical.is_dir() {
            return Err(NonoError::BlockedCommand {
                command: "filesystem approval".to_string(),
                reason: format!(
                    "approval_fs root must be an existing directory below '/': {}",
                    canonical.display()
                ),
            });
        }
        roots.push(canonical);
    }
    Ok(roots)
}

fn overlaps_deny(path: &Path, kind: CommandFilesystemGrantKind, deny_paths: &[PathBuf]) -> bool {
    deny_paths.iter().any(|deny| {
        let canonical_deny = deny.canonicalize().unwrap_or_else(|_| deny.clone());
        path.starts_with(&canonical_deny)
            || (kind == CommandFilesystemGrantKind::Directory && canonical_deny.starts_with(path))
    })
}

fn merge_access(left: AccessMode, right: AccessMode) -> AccessMode {
    if left == right {
        left
    } else {
        AccessMode::ReadWrite
    }
}

pub(crate) fn add_approved_filesystem_to_policy(
    policy: &mut CommandSandboxConfig,
    grants: &[CommandFilesystemGrant],
) -> Result<()> {
    for grant in grants {
        let path = grant.path.to_str().ok_or_else(|| {
            NonoError::ConfigParse(format!(
                "approved filesystem path is not UTF-8: {}",
                grant.path.display()
            ))
        })?;
        let destination = match (grant.kind, grant.access) {
            (CommandFilesystemGrantKind::File, AccessMode::Read) => &mut policy.fs_read_file,
            (CommandFilesystemGrantKind::Directory, AccessMode::Read) => &mut policy.fs_read,
            (CommandFilesystemGrantKind::File, AccessMode::Write | AccessMode::ReadWrite) => {
                &mut policy.fs_write_file
            }
            (CommandFilesystemGrantKind::Directory, AccessMode::Write | AccessMode::ReadWrite) => {
                &mut policy.fs_write
            }
        };
        if !destination.iter().any(|entry| entry == path) {
            destination.push(path.to_string());
        }
    }
    Ok(())
}

pub(crate) fn approval_route(
    ceiling: &CommandApprovalFilesystemConfig,
) -> (Option<&str>, Option<u64>) {
    (ceiling.backend.as_deref(), ceiling.timeout_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: &Path, access: &str, kind: &str) -> Vec<Vec<u8>> {
        vec![format!(
            "{TOOL_SANDBOX_FS_REQUEST_ENV}={{\"filesystem\":[{{\"path\":{},\"access\":\"{access}\",\"kind\":\"{kind}\"}}]}}",
            serde_json::to_string(&path.display().to_string()).expect("serialize path")
        )
        .into_bytes()]
    }

    #[test]
    fn request_is_bounded_by_configured_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("input");
        std::fs::write(&file, b"data").expect("write fixture");
        let policy = CommandSandboxConfig {
            approval_fs: Some(CommandApprovalFilesystemConfig {
                read_roots: vec![dir.path().display().to_string()],
                ..CommandApprovalFilesystemConfig::default()
            }),
            ..CommandSandboxConfig::default()
        };
        let grants = resolve_requested_filesystem(
            &request(&file, "read", "file"),
            dir.path().as_os_str().as_encoded_bytes(),
            &policy,
            dir.path(),
            &[],
        )
        .expect("resolve request");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].path, file.canonicalize().expect("canonical file"));
    }

    #[test]
    fn write_request_fails_under_read_only_ceiling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("input");
        std::fs::write(&file, b"data").expect("write fixture");
        let policy = CommandSandboxConfig {
            approval_fs: Some(CommandApprovalFilesystemConfig {
                read_roots: vec![dir.path().display().to_string()],
                ..CommandApprovalFilesystemConfig::default()
            }),
            ..CommandSandboxConfig::default()
        };
        let result = resolve_requested_filesystem(
            &request(&file, "write", "file"),
            dir.path().as_os_str().as_encoded_bytes(),
            &policy,
            dir.path(),
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn write_request_is_normalized_to_actual_read_write_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("output");
        std::fs::write(&file, b"data").expect("write fixture");
        let policy = CommandSandboxConfig {
            approval_fs: Some(CommandApprovalFilesystemConfig {
                write_roots: vec![dir.path().display().to_string()],
                ..CommandApprovalFilesystemConfig::default()
            }),
            ..CommandSandboxConfig::default()
        };
        let grants = resolve_requested_filesystem(
            &request(&file, "write", "file"),
            dir.path().as_os_str().as_encoded_bytes(),
            &policy,
            dir.path(),
            &[],
        )
        .expect("resolve request");
        assert_eq!(grants[0].access, AccessMode::ReadWrite);
    }

    #[test]
    fn directory_request_cannot_enclose_a_denied_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let denied = dir.path().join("secret");
        std::fs::create_dir(&denied).expect("denied dir");
        let policy = CommandSandboxConfig {
            approval_fs: Some(CommandApprovalFilesystemConfig {
                read_roots: vec![dir.path().display().to_string()],
                ..CommandApprovalFilesystemConfig::default()
            }),
            ..CommandSandboxConfig::default()
        };
        let result = resolve_requested_filesystem(
            &request(dir.path(), "read", "directory"),
            dir.path().as_os_str().as_encoded_bytes(),
            &policy,
            dir.path(),
            &[denied],
        );
        assert!(result.is_err());
    }
}
