# Audit delivery protocol v1

This document specifies the open client contract used by `nono` to enroll an
audit-only device or workload and deliver a completed session to a compatible
control plane. Enrollment does not imply mandatory fleet policy or session
conformance.

## Enrollment

An operator provisions a short-lived, single-use token bound server-side to a
tenant. The client generates an ECDSA P-256 keypair and sends:

```http
POST /api/v1/enrollment/exchange
Content-Type: application/json
```

```json
{
  "protocol_version": "1",
  "token": "<one-time token>",
  "subject_kind": "device",
  "display_name": "developer laptop",
  "key_algorithm": "ecdsa_p256_sha256_fixed",
  "public_key": "<base64url uncompressed P-256 point>"
}
```

The response binds a stable `subject_id` to the server-derived `tenant_id` and
returns `management_mode: "audit_only"`. The private key and enrollment state
must be stored outside project-controlled configuration.

## Signed final ingest

The final envelope is posted to `/api/v1/audit/ingest`. The client sends:

```text
X-Nono-Protocol-Version: 1
X-Nono-Subject-Id: <enrolled subject>
X-Nono-Timestamp: <Unix milliseconds>
X-Nono-Request-Id: <ingest UUID>
X-Nono-Content-SHA256: sha256:<lowercase hex digest of exact body bytes>
X-Nono-Signature: p256-sha256:<base64url fixed-width ECDSA signature>
```

The bytes signed are UTF-8:

```text
nono-request-v1
POST
/api/v1/audit/ingest
<subject_id>
<timestamp_ms>
<request_id>
<body_digest>
```

The server must reject unsupported versions, stale timestamps, modified
bodies, unknown or revoked subjects, tenant mismatches, and reuse of a request
ID with different content. Repeating the same authenticated request ID and
body is idempotent and returns the original receipt.

An accepted v1 receipt is `pending` until the platform independently
recomputes the event chain and Merkle root. Enrollment and transport
authentication alone do not make evidence verified.
