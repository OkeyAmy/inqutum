# Notification and webhook duplicate suppression

The delivery ledger is an opt-in primitive for outbound workers; it does not change existing HTTP response contracts or automatically wrap every notification path.

## Worker contract

1. Authenticate the caller and authorize access to the tenant/event/destination before calling `claimDelivery`. Use a trusted owner ID for `scope`, not a request-body value.
2. Use a stable source event ID (for example `invoice-paid:<invoice-id>`) and a stable destination identifier on every retry. The identity is scoped by owner, channel, event and destination.
3. If `claimed: false`, do not send. `already_delivered` is terminal; `in_progress` means another worker owns the lease.
4. Send only after a durable claim succeeds. Call `completeDelivery` after provider success and `failDelivery` after a retryable/terminal failure. A false result means the lease was superseded; do not overwrite the newer worker's state.
5. Treat database errors as failure to claim. Do not fall back to sending without deduplication when the guarantee is required.

## Failure and recovery

- Concurrent workers are serialized by the database primary key and conditional upsert.
- A worker crash leaves an `in_progress` row. After its lease expires, a retry can take ownership; choose a lease longer than normal provider latency and keep it bounded.
- Failed sends may be retried. Successful sends remain suppressed. Provider timeouts can be ambiguous: the provider may have accepted the request before the worker timed out. Pass the same stable idempotency key to the provider when supported; otherwise exactly-once delivery cannot be guaranteed across that ambiguity.
- The ledger records a hashed destination, not the URL/token itself. `last_error` is truncated to 1000 characters; callers should avoid putting secrets in thrown error messages.
- Rows are durable across restarts and workers. Define a retention policy only after the maximum queue retry/redelivery window is known; deleting rows too early permits old events to be sent again.
- To recover a stuck row, inspect its status, attempt count, lease and timestamps. Prefer letting the lease expire. Manual status changes can cause duplicate delivery and should be audited.

## Rollout and rollback

1. Apply `db/migrations/002-delivery-deduplication.sql` through the existing migration runner.
2. Integrate one notification/webhook worker at a time, keeping existing payloads, headers and response contracts unchanged.
3. Monitor claim conflicts, retry counts, expired leases and delivery failures before expanding rollout.
4. Roll back by disabling the worker integration, not by dropping the table. Keep the ledger during rollback so re-enabling suppression does not resend already delivered events. The migration is additive and safe to re-run; dropping the table is destructive and not the recommended rollback.

## Verification

Run `cd backend && npm test -- --test-name-pattern="notification and webhook duplicate suppression"` or run the focused file directly with `node --import tsx --test tests/notification-webhook-deduplication.test.ts`.
