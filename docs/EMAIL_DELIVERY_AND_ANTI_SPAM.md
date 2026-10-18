# Email Delivery Queue, Retry Policy, and Anti-Spam Relay Protection (Phase E)

This document specifies the architecture and operational policy for asynchronous transactional email delivery, retry handling, failure visibility, and anti-spam relay protection in Quittance (issues #37 and #38).

---

## 1. Overview & Threat Model

Quittance supports invoice creation and payment verification without mandatory email accounts. When sending invoice links or payment receipts to a recipient's email, the server acts as the sender of record.

### Risks:
1. **Spam Relay Abuse**: Malicious actors could generate spurious invoices or receipts to bombard arbitrary third-party inboxes using the project's sending domain.
2. **Silent Delivery Failure**: Transient SMTP errors (network timeouts, upstream 429 rate limits, temporary outages) causing emails to be dropped silently with no freelancer visibility or retry.
3. **Domain Reputation Damage**: High bounce rates (>5%) or spam complaints (>0.1%) leading to mailbox providers (Gmail, Outlook) blacklisting transactional emails.

---

## 2. Queue & Retry Architecture (Issue #37)

### Persistence & Storage Parity
Every outbound email attempt is persisted to the `email_deliveries` table (Postgres) or memory delivery store (in-memory MVP) before transmission:

```sql
CREATE TABLE IF NOT EXISTS email_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  invoice_id UUID REFERENCES invoices(id) ON DELETE CASCADE,
  recipient_email VARCHAR(255) NOT NULL,
  sender_wallet VARCHAR(56) NOT NULL,
  email_type VARCHAR(50) NOT NULL,
  subject VARCHAR(255) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SENDING', 'SENT', 'FAILED', 'PERMANENTLY_FAILED', 'PAUSED')),
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 5,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_attempt_at TIMESTAMPTZ,
  last_error TEXT,
  is_retryable BOOLEAN NOT NULL DEFAULT TRUE,
  payload JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  sent_at TIMESTAMPTZ
);
```

### Retry Policy & Backoff
- **Exponential Backoff**:
  $$\text{Delay}(n) = \min(\text{maxBackoff}, \text{initialBackoff} \times 2^{n - 1})$$
  Default initial backoff is 1s, maximum backoff is 1 hour.
- **Classification**:
  - **Retryable Errors** (e.g. `429 Too Many Requests`, `503 Service Unavailable`, `ECONNRESET`, network timeouts): Increments `attempts`, updates `last_error`, sets `next_attempt_at` for next retry.
  - **Permanent Errors** (e.g. `550 User not found`, `554 Mailbox unavailable`, invalid recipient DNS/syntax, spam rejection): Immediately marks status `PERMANENTLY_FAILED` with `is_retryable = false` without useless retries.
  - **Exhaustion**: Reaching `max_attempts` transitions status to `PERMANENTLY_FAILED`.

### Freelancer Visibility
- Outbound delivery status for an invoice is exposed via `GET /api/invoices/:id/deliveries` to the authorized seller wallet.
- Surfaces `status`, `attempts`, `lastError`, `nextAttemptAt`, and whether retries are ongoing or exhausted.

---

## 2a. Duplicate suppression (Issue #294)

Callers may pass an optional `dedupeKey` to `EmailQueueService.enqueue`. It must be a stable event/request ID (8-255 URL-safe characters); the service scopes it to the sender wallet. Repeating a key returns the original delivery and does not queue another message or consume another rate-limit/quota slot. Invalid keys fail with `NOTIFICATION_DEDUPE_KEY_INVALID`. Requests without a key preserve legacy behavior.

Postgres enforces uniqueness with a partial unique index; apply the normal `npm run db:migrate` schema deployment before enabling keys. The memory store offers the same contract within one process only. A duplicate racing the first insert resolves to the winner. Keep keys stable across retries and do not reuse them for distinct notification events. Existing rows have `NULL` keys and are unaffected. Rollback: deploy code that no longer supplies keys first; retain the nullable column/index until all new code is rolled back. Do not drop the index while key-sending instances are running.

This suppresses duplicate queue creation, not provider-level exactly-once delivery: if an SMTP provider accepts a message and the process crashes before marking it `SENT`, a retry can still send again. Provider-supported idempotency or delivery reconciliation is needed to close that external side-effect window. Inbound webhook endpoints are not currently part of the public API; webhook consumers should authenticate signatures before recording an event and use a durable event-ID ledger before processing.

## 3. Anti-Spam Relay Protections & Circuit Breaker (Issue #38)

### Per-Wallet Outbound Rate Limiting
- Outbound emails are rate-limited per Stellar wallet public key (default: 10 emails per rolling 60-minute window), completely distinct from general IP API rate limits.
- Excess attempts return `HTTP 429` with `Retry-After` header and error code `EMAIL_RATE_LIMIT_EXCEEDED`.

### Address Validation & Anti-Injection
- Strict RFC 5322 validation.
- Rejection of control characters (`\r`, `\n`) to prevent SMTP header injection attacks.

### Bounce & Complaint Rate Monitoring & Automatic Circuit Breaker
- Tracks rolling deliverability metrics: `totalSent`, `totalDelivered`, `totalBounces`, `totalComplaints`.
- **Automatic Trip Thresholds**:
  - Bounce Rate $> 5.0\%$ (with minimum sample size of 10 sends).
  - Complaint Rate $> 0.1\%$.
- **Behavior When Tripped**:
  - Circuit breaker enters `TRIPPED` state (`isTripped = true`).
  - Outbound transmissions are paused immediately.
  - New enqueued emails are saved with status `PAUSED` so legitimate customer requests are **never dropped or lost**.
- **Recovery & Resumption**:
  - When operational issues are resolved, the maintainer resets the breaker via `POST /api/email/circuit-breaker/reset`.
  - Calling reset automatically drains and transitions all `PAUSED` items back to `PENDING` with `next_attempt_at = NOW()`.
