import { createHash, randomUUID } from 'node:crypto';

export interface DeliveryDb {
  query(sql: string, params?: unknown[]): Promise<{ rows: Array<Record<string, unknown>>; rowCount?: number | null }>;
}

export type DeliveryChannel = 'notification' | 'webhook';

export interface DeliveryClaim {
  /** Stable source event ID, not a freshly generated ID for each retry. */
  eventId: string;
  /** Authenticated tenant/owner scope; never use an untrusted request field. */
  scope: string;
  /** Stable recipient or endpoint identifier. Do not pass secrets or full URLs. */
  destination: string;
  channel: DeliveryChannel;
  /** Lease duration for workers that crash before completing. */
  leaseMs?: number;
}

export type ClaimResult =
  | { claimed: true; token: string }
  | { claimed: false; reason: 'already_delivered' | 'in_progress' };

/**
 * Durable, cross-worker duplicate suppression for outbound notification and
 * webhook delivery. Call only after authenticating/authorizing the owner and
 * validating the destination. A stable eventId + scope + destination + channel
 * identifies one logical delivery across queue retries and worker restarts.
 */
export async function claimDelivery(db: DeliveryDb, input: DeliveryClaim, now = new Date()): Promise<ClaimResult> {
  if (!input.eventId.trim() || !input.scope.trim() || !input.destination.trim()) {
    throw new Error('eventId, scope, and destination are required');
  }
  if (input.channel !== 'notification' && input.channel !== 'webhook') {
    throw new Error('Unsupported delivery channel');
  }
  const leaseMs = input.leaseMs ?? 60_000;
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 1_000 || leaseMs > 15 * 60_000) {
    throw new Error('leaseMs must be between 1000 and 900000');
  }

  const token = randomUUID();
  const result = await db.query(
    `INSERT INTO delivery_deduplication
       (delivery_key, scope, channel, event_id, destination_hash, status, claim_token, lease_until, attempts, updated_at)
     VALUES ($1, $2, $3, $4, $5, 'in_progress', $6, $7, 1, $8)
     ON CONFLICT (delivery_key) DO UPDATE
       SET status = 'in_progress',
           claim_token = EXCLUDED.claim_token,
           lease_until = EXCLUDED.lease_until,
           attempts = delivery_deduplication.attempts + 1,
           updated_at = EXCLUDED.updated_at,
           last_error = NULL
       WHERE delivery_deduplication.status = 'failed'
          OR (delivery_deduplication.status = 'in_progress' AND delivery_deduplication.lease_until <= $8)
     RETURNING claim_token`,
    [
      createHash('sha256').update([input.scope, input.channel, input.eventId, input.destination].join('\u0000')).digest('hex'),
      input.scope,
      input.channel,
      input.eventId,
      createHash('sha256').update(input.destination).digest('hex'),
      token,
      new Date(now.getTime() + leaseMs),
      now,
    ]
  );

  if (result.rowCount) return { claimed: true, token };

  const existing = await db.query(
    'SELECT status FROM delivery_deduplication WHERE delivery_key = $1',
    [createHash('sha256').update([input.scope, input.channel, input.eventId, input.destination].join('\u0000')).digest('hex')]
  );
  if (existing.rows[0]?.status === 'delivered') return { claimed: false, reason: 'already_delivered' };
  return { claimed: false, reason: 'in_progress' };
}

/** Mark success only for the worker holding the current lease token. */
export async function completeDelivery(db: DeliveryDb, deliveryKey: string, token: string, now = new Date()): Promise<boolean> {
  const result = await db.query(
    `UPDATE delivery_deduplication
        SET status = 'delivered', delivered_at = $3, updated_at = $3, lease_until = NULL, last_error = NULL
      WHERE delivery_key = $1 AND claim_token = $2 AND status = 'in_progress'`,
    [deliveryKey, token, now]
  );
  return result.rowCount === 1;
}

/** Release a failed attempt for retry; old workers cannot mutate a newer lease. */
export async function failDelivery(db: DeliveryDb, deliveryKey: string, token: string, error: unknown, now = new Date()): Promise<boolean> {
  const message = String(error instanceof Error ? error.message : error).slice(0, 1000);
  const result = await db.query(
    `UPDATE delivery_deduplication
        SET status = 'failed', last_error = $3, updated_at = $4, lease_until = NULL
      WHERE delivery_key = $1 AND claim_token = $2 AND status = 'in_progress'`,
    [deliveryKey, token, message, now]
  );
  return result.rowCount === 1;
}

/** Derive the same opaque key used by claimDelivery for completion/failure calls. */
export function deliveryKey(input: Pick<DeliveryClaim, 'eventId' | 'scope' | 'destination' | 'channel'>): string {
  return createHash('sha256')
    .update([input.scope, input.channel, input.eventId, input.destination].join('\u0000'))
    .digest('hex');
}
