import { createHash } from 'node:crypto';
import type { IdempotencyStore } from '../idempotency/store';

export type WebhookResult =
  | { accepted: true; duplicate: boolean; result?: unknown }
  | { accepted: false; status: 400 | 401 | 409 | 410 | 422 | 503; code: string };

export interface WebhookInput {
  provider: string;
  eventId: string;
  rawBody: string | Buffer;
  /** Must validate the provider signature over the original raw body. */
  verifySignature: () => boolean | Promise<boolean>;
  /** Called once for each successfully accepted event ID. */
  handle: () => unknown | Promise<unknown>;
  now?: () => Date;
}

/**
 * Signature-first webhook deduplication backed by the existing idempotency store.
 * The store must be shared/durable in production; the memory store is for tests/MVP.
 */
export async function processWebhook(store: IdempotencyStore, input: WebhookInput): Promise<WebhookResult> {
  if (!input.provider?.trim() || !input.eventId?.trim() || input.eventId.length > 255) {
    return { accepted: false, status: 400, code: 'WEBHOOK_EVENT_ID_INVALID' };
  }
  let authorized = false;
  try { authorized = await input.verifySignature(); } catch { authorized = false; }
  if (!authorized) return { accepted: false, status: 401, code: 'WEBHOOK_SIGNATURE_INVALID' };

  const key = input.eventId.trim();
  const scope = 'webhook:' + input.provider.trim().toLowerCase();
  const body = Buffer.isBuffer(input.rawBody) ? input.rawBody : Buffer.from(input.rawBody);
  const fingerprint = createHash('sha256').update(body).digest('hex');
  const now = (input.now ?? (() => new Date()))();
  let decision;
  try {
    decision = await store.begin({ scope, key, fingerprint, now, ttlMs: 7 * 24 * 60 * 60 * 1000, lockMs: 60 * 1000 });
  } catch {
    return { accepted: false, status: 503, code: 'WEBHOOK_DEDUPE_STORE_UNAVAILABLE' };
  }
  if (decision.kind === 'replay') return { accepted: true, duplicate: true, result: decision.response.body };
  if (decision.kind === 'in_progress') return { accepted: false, status: 409, code: 'WEBHOOK_EVENT_IN_PROGRESS' };
  if (decision.kind === 'conflict') return { accepted: false, status: 422, code: 'WEBHOOK_EVENT_ID_CONFLICT' };
  if (decision.kind === 'expired') return { accepted: false, status: 410, code: 'WEBHOOK_EVENT_ID_EXPIRED' };

  try {
    const result = await input.handle();
    await store.complete(scope, key, { status: 200, body: result ?? null }, now);
    return { accepted: true, duplicate: false, result };
  } catch (error) {
    try { await store.release(scope, key); } catch { /* preserve handler error */ }
    throw error;
  }
}
