# Cross-Boundary Trust Decisions — Scenario-Based Threat Model

**Issue:** #231 | **Version:** 1.0.0 | **Status:** Active

---

## 1. Scope & Purpose

This threat model documents the trust boundaries in Inqutum where a decision must be made about whether to trust data or an actor crossing from one security domain to another. Each boundary is analyzed with:

- **Abuse cases** — realistic attack scenarios
- **Trust boundaries** — where the boundary lies
- **Mitigations** — implemented controls
- **Verification** — automated tests/checks for highest-risk paths
- **Operational edge cases** — failure modes, rollback/recovery

The model is scenario-based: every entry starts from a concrete attacker goal and traces through the system to show where trust is placed and how it is validated.

---

## 2. Trust Boundaries Inventory

| ID | Boundary | Crosses From → To | Decision Point |
|----|----------|-------------------|----------------|
| TB-01 | **Payment Verification** | Client (payer) → Server (Horizon) | Does this tx hash prove payment for this invoice? |
| TB-02 | **Invoice State Transition** | Server (internal) → Database | Can this invoice move PENDING → PAID? |
| TB-03 | **Impersonation** | Maintainer → Seller context | Is this action allowed for this support session? |
| TB-04 | **Capability Tokens** | Maintainer → Sensitive action | Is this short-lived grant valid for this action+target? |
| TB-05 | **Export Authorization** | Maintainer → Historical data | Can this actor see this dimension/bucket? |
| TB-06 | **External Reference** | External source → Verification record | Does this source confirm the reference? |
| TB-07 | **Email/Notification Delivery** | Server → SMTP/API provider | Was this email actually delivered? |
| TB-08 | **Admin Bearer Token** | Request → Admin route | Is this request from an authorized maintainer? |
| TB-09 | **Job Queue Processing** | Worker → Job store | Should this job be retried/dead-lettered? |
| TB-10 | **Stellar Network** | Transaction → Invoice | Is this tx on the expected network (testnet/pubnet)? |
| TB-11 | **Audit Trail Integrity** | Server → Audit store | Is this event authentic and unmodified? |
| TB-12 | **Recovery Checkpoints** | Side-effect → Checkpoint store | Did this external action (email send) complete? |

---

## 3. Scenario-Based Analysis

### 3.1 TB-01: Payment Verification — "Fake Payment Proof"

**Attacker Goal:** Convince the server an invoice is paid without actually paying on Stellar.

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | Submit a valid tx hash from an unrelated payment (different destination/amount/asset) |
| A2 | Submit a tx hash from a testnet payment to settle a pubnet invoice (or vice versa) |
| A3 | Submit a path payment or fee-bump transaction that wraps a matching inner payment |
| A4 | Replay a previously used tx hash for a different invoice |
| A5 | Forge Horizon response (MITM on Horizon connection) |
| A6 | Use a muxed destination to confuse exact-match logic |

**Trust Boundary:** Server receives `txHash` from client → fetches transaction/operations from Horizon → verifies against invoice expectations.

**Mitigations Implemented:**
- `verifyHorizonPayment()` in `payment-verification.ts` runs fixed-order checks:
  1. **Tx hash format** — 64 hex chars (rejects malformed early)
  2. **Network match** — caller's observed network must match invoice's configured network (`NETWORK_MISMATCH`)
  3. **Payment operation exists** — filters for `type === 'payment'` only (rejects path payments, manageData, etc.)
  4. **Memo exact match** — normalized comparison (case-sensitive, whitespace-preserved)
  5. **Destination exact match** — muxed-aware normalization (`M` addresses vs `G`+`muxedId`)
  6. **Amount match** — stroop-level comparison, optional ±1 tolerance via feature flag
  7. **Asset identity match** — `(code, issuer)` pair comparison; code-only `XLM` fails against native XLM
- Fee-bump envelopes: inner transaction used for memo/ops, outer hash persisted
- All rejections use stable `VerificationCode` enum, no stack traces in user messages

**Verification (Automated):**
- `tests/payment-verification.test.ts` — 50+ cases covering all codes, edge cases (fee-bump, muxed, tolerance)
- `tests/verify-amount-tolerance.test.ts` — stroop precision, tolerance flag
- `tests/invoice-payment-loop.test.ts` — end-to-end verify → settle flow
- Contract test: `/api/invoices/:id/verify` returns documented statuses (200, 400, 404, 500)

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| Horizon unavailable | `/api/ready` returns 503, `/api/health/dependencies` shows `stellar_horizon: down` | Retry verify when Horizon recovers; invoice stays PENDING |
| Network misconfig (testnet/pubnet) | `NETWORK_MISMATCH` rejection; audit event `PAYMENT_VERIFY_FAILED` | Fix `STELLAR_NETWORK` env, restart; no state corruption |
| Amount tolerance flag flip | Feature flag `paymentAmountTolerance` changes acceptance window | Flag is audited on change; existing paid invoices immutable |
| Reused tx hash | `INVOICE_ALREADY_PAID` if same invoice; different invoice accepted (valid per Stellar) | Business logic: one payment can settle multiple invoices if memo matches |

---

### 3.2 TB-02: Invoice State Transition — "Unauthorized State Change"

**Attacker Goal:** Move an invoice to PAID/CANCELLED/EXPIRED without proper authorization.

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | Direct DB write bypassing verification |
| A2 | Race condition: verify + cancel simultaneously |
| A3 | Expired invoice marked paid via simulate-payment (sandbox only) |
| A4 | Version mismatch on optimistic lock bypass |

**Trust Boundary:** Internal server logic → Database (PostgreSQL or in-memory).

**Mitigations Implemented:**
- All state transitions go through `InvoiceService` methods (`verifyPayment`, `cancelInvoice`, `markExpiredInvoices`)
- Optimistic locking via `version` field on `StoredInvoice` — concurrent updates fail with 409
- `checkInvoiceIsPayable()` enforces: only PENDING → PAID; EXPIRED/CANCELLED/REJECTED are terminal
- `simulate-payment` only available when `ALLOW_SIMULATE=true` (never in production)
- Payment monitor service only transitions PENDING → PAID after `verifyHorizonPayment` succeeds

**Verification (Automated):**
- `tests/invoice-lifecycle-transitions.test.ts` — all valid/invalid transitions
- `tests/concurrency.test.ts` — optimistic lock under concurrent verify/cancel
- `tests/invoice-service.test.ts` — service-level invariants

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| DB write fails mid-transition | Transaction rolls back; invoice unchanged | Retry from client; idempotent verify uses tx hash |
| Payment monitor crashes after verify | Job requeued; expiry sweep marks overdue | `jobs.requeueDead()` + `invoiceService.markExpiredInvoices()` |
| Version drift (manual DB edit) | Optimistic lock fails on next update | Admin: read current version, retry with correct version |

---

### 3.3 TB-03: Impersonation — "Support Session Abuse"

**Attacker Goal:** Use a support impersonation session to perform unauthorized actions on a seller's account.

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | Maintainer opens session with elevated permissions without justification |
| A2 | Session not expired after 30 min; used hours later |
| A3 | Maintainer impersonates themselves (no reduced scope) |
| A4 | Session used for irreversible action without elevated confirmation |
| A5 | Session hijacked (session ID leaked) |

**Trust Boundary:** Maintainer identity + session state → Authorization decision for each action.

**Mitigations Implemented (impersonation.ts):**
- **Scoped permissions** — default `['read']`; `elevated` required for irreversible actions (`ELEVATED_ONLY_ACTIONS`)
- **Time-limited** — default 30 min, hard cap 60 min; lazy expiry on read
- **Self-impersonation blocked** — `maintainerId === targetId` rejected
- **Audited decisions** — every `authorize()` call writes `IMPERSONATION_ACTION_ALLOWED` or `IMPERSONATION_ACTION_BLOCKED`
- **Banner indicator** — persistent UI shows active session target + expiry
- **Purge on restart** — in-memory sessions lost; maintainer must re-authenticate

**Verification (Automated):**
- `tests/impersonation.test.ts` — session lifecycle, permission matrix, elevated confirmation, audit events
- `tests/api-contract.test.ts` — `/api/ops/impersonation*` endpoints require admin bearer

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| Server restart loses sessions | No active sessions on restart | Maintainer re-opens session; audit trail has history |
| Clock skew | Session expires early/late | Uses service clock (`now()`); testable via injection |
| Maintainer ID reuse | Velocity counting in risk scorer | Distinct maintainer IDs recommended; documented in RISK_SCORING.md |

---

### 3.4 TB-04: Capability Tokens — "Privilege Escalation via Token"

**Attacker Goal:** Perform a sensitive admin action (feature flag change) without proper authorization.

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | Steal/guess long-lived `JOBS_ADMIN_TOKEN` and use directly |
| A2 | Replay a used capability token |
| A3 | Modify token claims (action/target/subject) |
| A4 | Use algorithm confusion (JWT `none` / RS256→HS256) |
| A5 | Issue token with excessive TTL |
| A6 | Concurrent use of same token (race) |

**Trust Boundary:** Request with `X-Capability-Token` header → `CapabilityTokenService.use()` → action execution.

**Mitigations Implemented (capability-tokens.ts):**
- **Fixed format** — `qcap.v1.<claims>.<HMAC-SHA256>`; no `alg` header (prevents alg confusion)
- **Explicit typing** — `typ: 'qcap'` + dedicated `CAPABILITY_TOKEN_SECRET` (not shared with JWT)
- **Constant-time signature verify** — `timingSafeEqual` before parsing claims
- **Scope binding** — action + target in claims; verified against requested scope
- **Single-use with reservation** — `use()` reserves ID, commits on success, releases on failure
- **TTL bounds** — min 1s, max per-action (default 5 min, max 15 min for feature flags)
- **Ledger capacity** — bounded memory; fails closed when full (no eviction of used IDs)

**Verification (Automated):**
- `tests/capability-tokens.test.ts` — issuance, verification, reuse, expiry, scope mismatch, malformed, concurrent use
- `tests/ops-health.test.ts` — capability routes require admin + capability

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| Secret rotation | Old tokens fail `CAPABILITY_INVALID` | Issue new tokens with new secret; old expire naturally |
| Clock skew across instances | `CAPABILITY_EXPIRED` or `CAPABILITY_INVALID` | `CLOCK_SKEW_MS = 30s` tolerance; run instances with NTP |
| Ledger full | `CAPABILITY_LEDGER_FULL` (503) | Capacity default 10k; increase `ledgerCapacity` option |
| Process restart | Ledger lost (in-memory) | Used IDs not persisted; capability could be replayed if not expired — mitigate with short TTL |

---

### 3.5 TB-05: Export Authorization — "Data Exfiltration via Export"

**Attacker Goal:** Extract sensitive PII or financial data via export endpoint.

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | Request export with sensitive dimensions (`customerEmail`, `payerName`, `rawMemo`) |
| A2 | Request export for all sellers (no seller scoping) |
| A3 | Exhaust memory with unbounded `maxSourceRecords`/`maxBuckets` |
| A4 | Export by non-maintainer (missing auth) |

**Trust Boundary:** Maintainer request → `TrendExportService.exportTrends()` → data aggregation → download.

**Mitigations Implemented (trend-export.ts):**
- **Admin bearer required** — `JOBS_ADMIN_TOKEN` on `/api/ops/trends/export`
- **Actor validation** — `actor.role` must be `maintainer` or `admin`
- **Dimension allow-list** — only `ALLOWED_TREND_DIMENSIONS` accepted; `SENSITIVE_TREND_DIMENSIONS` explicitly blocked
- **Seller cohort anonymization** — `sellerCohort` uses SHA-256 one-way hash
- **Bounds enforcement** — `maxSourceRecords` (default 50k, max configurable), `maxBuckets` (default 500)
- **Truncation metadata** — `truncated: true` in export if caps hit
- **Schema versioning** — every export carries `schema`, `schemaVersion`, `exportId`, `generatedAt`, `generatedBy`

**Verification (Automated):**
- `tests/trend-export.test.ts` — dimension filtering, sensitive block, bounds, anonymization, schema
- `tests/api-contract.test.ts` — `/api/ops/trends/export` requires admin

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| Export times out | `503` or worker killed | Reduce `maxSourceRecords`/`maxBuckets`; retry |
| Memory OOM during aggregation | Process crash | Bounded by caps; monitor `/api/ops/health` for `staleJobs` |
| Sensitive dimension requested | `400 SENSITIVE_DIMENSION_BLOCKED` | Client must use allowed dimensions only |

---

### 3.6 TB-06: External Reference Verification — "False Verification"

**Attacker Goal:** Get a reference marked `VERIFIED` when the external source did not confirm it.

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | Probe returns malformed response; parsed as success |
| A2 | Source returns stale data (old ledger sequence) |
| A3 | Network partition: probe times out but retry succeeds with stale data |
| A4 | Source compromised; returns `verified` for invalid reference |
| A5 | Retry exhaustion marks terminal failure incorrectly |

**Trust Boundary:** External source response → `ExternalReferenceVerificationService` → persisted record status.

**Mitigations Implemented (external-reference-verification.ts):**
- **Per-attempt timeout** — 3s default; `AbortSignal` cancels hung connections
- **Strict response parsing** — `ExternalSourceRawResponse` schema; unknown fields ignored
- **Staleness check** — `maxStalenessMs` (default 24h) rejects old `observedTimestamp`
- **Clock skew tolerance** — `allowedClockSkewMs` (default 60s) for future timestamps
- **Retry policy** — only transient codes (`SOURCE_TIMEOUT`, `SOURCE_UNREACHABLE`, `REFERENCE_PENDING_UPSTREAM`) retry; deterministic failures fail fast
- **Per-attempt history** — `attemptHistory` array with latency, outcome, error code
- **Single-attempt mode** — `verifySingleAttempt` for synchronous checks

**Verification (Automated):**
- `tests/external-reference-verification.test.ts` — retry logic, staleness, clock skew, timeout, terminal failures
- Contract: `/api/ops/external-references/verify` statuses (200, 202, 422)

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| Source permanently down | `FAILED_TERMINAL` after maxAttempts | Manual review; `POST /api/ops/external-references/verify` with `singleAttempt: true` |
| Stale data accepted | `STALE_SOURCE_DATA` in attempt history | Increase `maxStalenessMs` if source is slow |
| Probe throws unexpected error | Caught as `SOURCE_UNREACHABLE` (retryable) | Probe should normalize errors; test with malformed responses |

---

### 3.7 TB-07: Email/Notification Delivery — "False Delivery Report"

**Attacker Goal:** System reports email sent when it was not, or sends to wrong recipient.

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | SMTP accepts but silently drops (no bounce) |
| A2 | Email sent to wrong address (typo in `to`) |
| A3 | Idempotency key reused for different email content |
| A4 | Checkpoint in-doubt: crash mid-send, unknown outcome |
| A5 | Provider throttles; retry logic sends duplicates |

**Trust Boundary:** Server → Email provider (SMTP/API) → Delivery status recorded in checkpoint store.

**Mitigations Implemented (email-delivery.ts, side-effect-checkpoint.ts):**
- **Idempotency keys** — every send keyed by `idempotencyKey`; duplicate content check
- **Checkpoint store** — `MemoryCheckpointStore` / `PostgresCheckpointStore` records `in_progress`, `sent`, `failed`, `in_doubt`
- **In-doubt handling** — crash mid-send → `in_doubt`; operator must confirm outcome before retry
- **Provider failure classification** — `auth`, `quota`, `transient`, `permanent`, `invalid_recipient`, `config`, `in_progress`, `in_doubt`, `key_reused`
- **Retry policy** — exponential backoff for transient; no retry for permanent/auth
- **Webhook ingestion** — bounce/complaint/delivered callbacks update checkpoint status

**Verification (Automated):**
- `tests/email-queue-and-anti-spam.test.ts` — queue, dedupe, retry, checkpoint
- `tests/side-effect-checkpoints.test.ts` — in-doubt, in-progress, key reuse, recovery
- `tests/webhook-verification.test.ts` — provider callbacks

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| Email in-doubt after crash | Checkpoint status `in_doubt` | `GET /api/email/problems`; operator confirms sent/failed; `POST /api/email/deliveries` retry |
| Provider credentials rotated | `EMAIL_AUTH` failures | Update `SMTP_*` env; restart; queued emails retry |
| Idempotency key collision | `KEY_REUSED` error | Generate unique keys per send (invoice ID + timestamp) |

---

### 3.8 TB-08: Admin Bearer Token — "Long-Lived Token Abuse"

**Attacker Goal:** Use `JOBS_ADMIN_TOKEN` to perform admin actions without capability token.

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | Token leaked in logs/CI/config |
| A2 | Token used for sensitive action without capability (bypass) |
| A3 | Token shared across team; no individual accountability |

**Trust Boundary:** `Authorization: Bearer <token>` header → `requireAdmin()` middleware → route handler.

**Mitigations Implemented:**
- **Bearer token only for admin surface** — not used on public invoice API
- **Capability token required for sensitive actions** — `POST /api/ops/config/feature-flags/:flag` needs both admin bearer + `X-Capability-Token`
- **Timing-safe compare** — `timingSafeEqual` for token comparison
- **Disabled when unset** — routes return 403 `CAPABILITIES_DISABLED` if `CAPABILITY_TOKEN_SECRET` unset
- **Audit on capability use** — `CAPABILITY_ISSUED` + action audit before execution

**Verification (Automated):**
- `tests/api-contract.test.ts` — admin surface refuses unauthenticated (401/403)
- `tests/capability-tokens.test.ts` — capability required for sensitive action

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| Token leaked | Audit shows unexpected maintainer actions | Rotate `JOBS_ADMIN_TOKEN`; restart instances |
| Capability secret unset | Sensitive routes return 403 | Set `CAPABILITY_TOKEN_SECRET` (32+ chars); restart |

---

### 3.9 TB-09: Job Queue Processing — "Silent Job Loss"

**Attacker Goal:** Background job fails silently or is processed incorrectly.

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | Job fails, retries exhausted, dead-lettered but not alerted |
| A2 | Job stuck in `running` (worker died); never requeued |
| A3 | Job payload corrupted; handler throws |
| A4 | Idempotency key collision on retry |

**Trust Boundary:** `JobWorker` → `JobStore` (PostgreSQL) → handler execution → status update.

**Mitigations Implemented:**
- **Stale detection** — `OPS_THRESHOLDS.queuedStaleMs = 5min`; `/api/ops/health` reports stale running/queued jobs
- **Dead-letter retry** — `POST /api/jobs/:id/retry` with idempotency key
- **Partial failure dashboard** — `/api/ops/partial-failures` filters by type/status
- **Idempotent retry** — `PartialFailureRetryCoordinator` reserves idempotency key
- **Expiry sweep job** — marks overdue PENDING invoices EXPIRED
- **Synthetic journey monitor** — `/api/ops/synthetic-journey/run` exercises critical path

**Verification (Automated):**
- `tests/jobs.test.ts` — job lifecycle, retry, dead-letter, idempotency
- `tests/partial-failures.test.ts` — dashboard, retry coordinator
- `tests/synthetic-journey-monitor.test.ts` — end-to-end journey

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| Worker crash mid-job | Job stays `running`; lease expires | Stale detection → manual retry or `POST /api/ops/partial-failures/:id/retry` |
| Job handler bug | Repeated failures, same error code | Fix code; `POST /api/jobs/:id/retry` with new deployment |
| Queue backlog | `/api/ops/health` shows `staleJobs.count > 0` | Scale workers; check `JOBS_EMBEDDED_WORKER` |

---

### 3.10 TB-10: Stellar Network — "Cross-Network Payment Confusion"

**Attacker Goal:** Settle a testnet invoice with a pubnet payment (or vice versa).

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | Invoice created on testnet; payer submits pubnet tx hash |
| A2 | `STELLAR_NETWORK` env changes between invoice creation and verify |
| A3 | Horizon URL points to wrong network |

**Trust Boundary:** Invoice `network` field + caller's `network` param → `verifyHorizonPayment` network match check.

**Mitigations Implemented:**
- Invoice stores expected network implicitly via server config at creation time
- `verifyHorizonPayment` compares `expected.network` (server config) with caller's `network` param
- `STELLAR_NETWORK` validated at startup (`TESTNET` or `PUBLIC` only)
- Horizon URL derived from network unless overridden

**Verification (Automated):**
- `tests/payment-verification.test.ts` — `NETWORK_MISMATCH` cases
- `tests/deploy-smoke.test.ts` — production config requires `ALLOW_SIMULATE=false`, valid network

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| Network config drift | `NETWORK_MISMATCH` rejections spike | Audit `PAYMENT_VERIFY_FAILED` events; align config |
| Horizon URL mismatch | `HORIZON_UNREACHABLE` or wrong network data | Verify `STELLAR_HORIZON_URL` matches `STELLAR_NETWORK` |

---

### 3.11 TB-11: Audit Trail Integrity — "Audit Event Tampering"

**Attacker Goal:** Modify or delete audit events to hide malicious activity.

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | Direct DB write to alter/delete audit events |
| A2 | Replay old audit event to confuse timeline |
| A3 | Impersonation session not audited |

**Trust Boundary:** Server code → `MemoryAuditStore` / PostgreSQL audit table.

**Mitigations Implemented (audit-service.ts):**
- **Append-only** — `recordEvent()` only inserts; no update/delete methods exposed
- **Structured events** — typed `action`, `actor`, `scope`, `reason`, `metadata`
- **Impersonation audited** — `IMPERSONATION_STARTED`, `ENDED`, `EXPIRED`, `ACTION_ALLOWED`, `ACTION_BLOCKED`
- **Capability audited** — `CAPABILITY_ISSUED` before token returned
- **Intent receipts** — signed HMAC chain; tampering detected on verify
- **Search index replay** — projection rebuilt from audit events

**Verification (Automated):**
- `tests/audit-trail.test.ts` — event recording, querying, export
- `tests/projection-replay.test.ts` — replay from audit events rebuilds index
- `tests/maintainer-approval.test.ts` — receipt chain verification

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| Audit DB unavailable | `recordEvent` throws; action may still proceed | Audit is best-effort; critical actions also in DB transactions |
| Search index drift | `/api/ops/stale-projections/detect` reports mismatch | `POST /api/ops/projections/search-index/replay` (dry-run first) |
| Intent receipt chain broken | `verifyReceiptChain()` returns broken index | Investigate; receipts are append-only; chain break = tampering |

---

### 3.12 TB-12: Recovery Checkpoints — "Side-Effect Double Execution"

**Attacker Goal:** Email sent twice (or not at all) due to crash/retry ambiguity.

**Abuse Cases:**
| Scenario | Description |
|----------|-------------|
| A1 | Crash after provider accepts, before checkpoint recorded |
| A2 | Retry sends duplicate because first was in-doubt |
| A3 | Provider returns success but checkpoint write fails |

**Trust Boundary:** Email send → `PostgresCheckpointStore` → outcome recorded.

**Mitigations Implemented (side-effect-checkpoint.ts):**
- **Fingerprint-based** — `fingerprintOf(message)` binds checkpoint to exact content
- **Three states** — `in_progress`, `done`, `in_doubt`
- **Reservation** — `runWithCheckpoint` reserves fingerprint, runs action, commits/releases
- **In-doubt resolution** — operator must confirm via `GET /api/email/problems` before retry

**Verification (Automated):**
- `tests/side-effect-checkpoints.test.ts` — reservation, in-doubt, key reuse, fingerprint collision
- `tests/email-queue-and-anti-spam.test.ts` — end-to-end with checkpoint

**Operational Edge Cases & Recovery:**
| Failure Mode | Detection | Recovery |
|--------------|-----------|----------|
| Checkpoint DB unavailable | `CHECKPOINT_UNAVAILABLE` error | Queue email; retry when DB up |
| In-doubt unresolved | `GET /api/email/problems` shows in-doubt | Operator contacts provider; confirms sent/failed; manual checkpoint update |

---

## 4. Cross-Boundary Trust Decision Matrix

| Boundary | Decision Maker | Inputs | Output | Fail-Open/Closed |
|----------|----------------|--------|--------|------------------|
| TB-01 Payment Verify | `verifyHorizonPayment()` | txHash, Horizon tx/ops, invoice expectations | `VerificationResult` | **Closed** — any mismatch = reject |
| TB-02 Invoice State | `InvoiceService` methods | Current status, version, action | Updated invoice or error | **Closed** — invalid transition = 409 |
| TB-03 Impersonation | `ImpersonationService.authorize()` | Session, action, elevated flag | `AuthorizationDecision` | **Closed** — no session = deny |
| TB-04 Capability | `CapabilityTokenService.use()` | Token, scope, action callback | Action result or error | **Closed** — invalid/used/expired = deny |
| TB-05 Export | `TrendExportService.exportTrends()` | Actor, dimensions, bounds | Export artifact or error | **Closed** — sensitive dim = 400 |
| TB-06 Ext Reference | `ExternalReferenceVerifier` | Source response, retry policy | `VERIFIED` / `FAILED_TERMINAL` | **Closed** — unverified = retry/fail |
| TB-07 Email | `EmailDeliveryService.send()` | Message, idempotency key, checkpoint | `EmailTransportResult` | **Closed** — in-doubt = operator decision |
| TB-08 Admin | `requireAdmin()` middleware | Bearer token | Pass/401/403 | **Closed** — missing/invalid = deny |
| TB-09 Jobs | `JobWorker` + `PartialFailureRetryCoordinator` | Job, idempotency key | Retry result | **Closed** — not dead = 409 |
| TB-10 Network | `verifyHorizonPayment` network check | Expected vs caller network | Pass/`NETWORK_MISMATCH` | **Closed** — mismatch = reject |
| TB-11 Audit | `auditStore.recordEvent()` | Event struct | Appended event | **Best-effort** — failure logged, action continues |
| TB-12 Checkpoint | `runWithCheckpoint()` | Fingerprint, action callback | Action result | **Closed** — in-doubt = operator |

---

## 5. Highest-Risk Paths & Verification Coverage

| Rank | Path | Risk | Test Coverage |
|------|------|------|---------------|
| 1 | Payment Verification (TB-01) | Financial loss | `payment-verification.test.ts` (50+ cases), `invoice-payment-loop.test.ts` |
| 2 | Invoice State Transition (TB-02) | State corruption | `invoice-lifecycle-transitions.test.ts`, `concurrency.test.ts` |
| 3 | Capability Tokens (TB-04) | Privilege escalation | `capability-tokens.test.ts` (malformed, replay, scope, concurrent) |
| 4 | Impersonation (TB-03) | Data access abuse | `impersonation.test.ts` (permissions, expiry, elevated, audit) |
| 5 | External Reference (TB-06) | False verification | `external-reference-verification.test.ts` (retry, staleness, timeout) |
| 6 | Export (TB-05) | PII exfiltration | `trend-export.test.ts` (sensitive dim block, anonymization, bounds) |
| 7 | Email Checkpoint (TB-12) | Duplicate/missed delivery | `side-effect-checkpoints.test.ts`, `email-queue-and-anti-spam.test.ts` |
| 8 | Job Queue (TB-09) | Silent failure | `jobs.test.ts`, `partial-failures.test.ts`, `synthetic-journey-monitor.test.ts` |

---

## 6. Operational Runbooks

### 6.1 Payment Verification Failure Spike
1. Check `/api/health/dependencies` → `stellar_horizon` state
2. If `down`: Horizon outage; wait for recovery
3. If `degraded`: Increase verify timeout; monitor `PAYMENT_VERIFY_FAILED` audit events
4. If `healthy` but rejections high: Check for network mismatch (config drift)

### 6.2 Impersonation Session Anomaly
1. `GET /api/ops/impersonation` — list active sessions
2. Look for `ELEVATION_REQUIRED` / `NEVER_ALLOWED` denials in audit
3. `POST /api/ops/impersonation/end` to force-close suspicious session
4. Review `IMPERSONATION_ACTION_BLOCKED` events for pattern

### 6.3 Capability Token Issues
1. `GET /api/ops/capabilities` — not directly exposed; check audit for `CAPABILITY_ISSUED`
2. If `CAPABILITY_LEDGER_FULL`: Increase `ledgerCapacity` or wait for expiry
3. If `CAPABILITY_SCOPE_MISMATCH`: Verify action/target match issued capability

### 6.4 Export Stuck / OOM
1. Reduce `maxSourceRecords` and `maxBuckets` in request
2. Check `/api/ops/health` for memory pressure
3. Use `format=json` instead of `csv` for large exports

### 6.5 Email In-Doubt Resolution
1. `GET /api/email/problems` — filter `status=in_doubt`
2. Check provider logs (SendGrid, SES, etc.) for message ID
3. If confirmed sent: `POST /api/email/deliveries` with `status=sent`
4. If confirmed failed: `POST /api/email/deliveries` with `status=failed` → retry

### 6.6 Search Index Drift
1. `GET /api/ops/stale-projections/detect` — check `healthy: false`
2. `POST /api/ops/projections/search-index/replay` with `dryRun: true` — review diff
3. `POST /api/ops/projections/search-index/replay` with `dryRun: false` — apply
4. If worse: `POST /api/ops/projections/search-index/rollback`

---

## 7. Rollback & Compatibility

| Component | Rollback Strategy | Compatibility |
|-----------|-------------------|---------------|
| Payment Verification | Revert `payment-verification.ts`; contract version unchanged | `VERIFICATION_CONTRACT_VERSION` tracks breaking changes |
| Impersonation | Set `MAINTAINER_INTENT_SECRET` unset → routes return 403 | No schema change; sessions in-memory |
| Capability Tokens | Unset `CAPABILITY_TOKEN_SECRET` → 403 on sensitive routes | `construct with capability: null` for pre-#285 behavior |
| Export | Remove `/api/ops/trends/export` route | New endpoint only; no existing API affected |
| External Reference | Disable by not calling verifier | New service; opt-in via routes |
| Email Checkpoint | Use `MemoryCheckpointStore` instead of Postgres | Same interface; swap implementation |
| Job Queue | `JOBS_EMBEDDED_WORKER=false` → external worker | Same `JobStore` interface |
| Audit Trail | No rollback (append-only) | New fields only; old events unchanged |

---

## 8. Automated Verification Inventory

| Test File | Boundaries Covered | CI Gate |
|-----------|-------------------|---------|
| `payment-verification.test.ts` | TB-01, TB-10 | Required |
| `invoice-lifecycle-transitions.test.ts` | TB-02 | Required |
| `impersonation.test.ts` | TB-03 | Required |
| `capability-tokens.test.ts` | TB-04 | Required |
| `trend-export.test.ts` | TB-05 | Required |
| `external-reference-verification.test.ts` | TB-06 | Required |
| `side-effect-checkpoints.test.ts` | TB-12 | Required |
| `jobs.test.ts` + `partial-failures.test.ts` | TB-09 | Required |
| `api-contract.test.ts` | All (route table, envelopes, auth) | Required |
| `deploy-smoke.test.ts` | TB-01, TB-08, TB-10 (prod config) | Required |
| `invoice-payment-loop.test.ts` | TB-01, TB-02 (E2E) | Required |
| `concurrency.test.ts` | TB-02 (optimistic lock) | Required |
| `projection-replay.test.ts` | TB-11 | Required |
| `maintainer-approval.test.ts` | TB-11 (receipt chain) | Required |

---

## 9. Future Hardening (Not in Scope)

- **Distributed capability ledger** — shared Redis for multi-instance replay protection
- **Signed audit events** — HMAC chain per event (not just intent receipts)
- **Hardware-backed secret storage** — HSM/KMS for `CAPABILITY_TOKEN_SECRET`, `JOBS_ADMIN_TOKEN`
- **Zero-trust network** — mTLS between services, Horizon client cert auth
- **Formal verification** — TLA+ model for payment verification state machine

---

## 10. References

- `backend/src/services/payment-verification.ts` — canonical verification logic
- `backend/src/audit/impersonation.ts` — support session model
- `backend/src/security/capability-tokens.ts` — capability token service
- `backend/src/exports/trend-export.ts` — historical export with privacy
- `backend/src/services/external-reference-verification.ts` — resilient external verification
- `backend/src/notifications/email-delivery.ts` — email with checkpoints
- `backend/src/recovery/side-effect-checkpoint.ts` — side-effect checkpointing
- `backend/src/ops/dependency-degradation.ts` — dependency health matrix
- `backend/src/ops/ops-health.ts` — operational health report
- `backend/src/ops/maintainer-approval.ts` — signed intent receipts
- `backend/src/ops/risk-scoring.ts` — behavioral risk scoring
- `docs/CAPABILITY_TOKENS.md` — capability token design
- `docs/RISK_SCORING.md` — risk assessment for maintainer actions
- `docs/DEPENDENCY-DEGRADATION.md` — operator runbook for external deps