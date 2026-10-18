import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  claimDelivery,
  completeDelivery,
  deliveryKey,
  failDelivery,
  type DeliveryDb,
} from '../src/notifications/delivery-deduplication.ts';

class FakeDeliveryDb implements DeliveryDb {
  rows = new Map<string, Record<string, any>>();
  fail = false;

  async query(sql: string, params: unknown[] = []) {
    if (this.fail) throw new Error('database unavailable');
    const q = sql.replace(/\s+/g, ' ').trim();
    if (q.startsWith('INSERT INTO delivery_deduplication')) {
      const [key, scope, channel, eventId, destinationHash, status, token, lease, , now] = params as any[];
      const old = this.rows.get(key);
      if (!old) {
        this.rows.set(key, { delivery_key: key, scope, channel, event_id: eventId, destination_hash: destinationHash, status, claim_token: token, lease_until: lease, attempts: 1, updated_at: now });
        return { rows: [{ claim_token: token }], rowCount: 1 };
      }
      if (old.status === 'failed' || (old.status === 'in_progress' && new Date(old.lease_until) <= new Date(now))) {
        Object.assign(old, { status, claim_token: token, lease_until: lease, attempts: old.attempts + 1, updated_at: now, last_error: null });
        return { rows: [{ claim_token: token }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    }
    if (q.startsWith('SELECT status FROM delivery_deduplication')) {
      const row = this.rows.get(params[0] as string);
      return { rows: row ? [{ status: row.status }] : [], rowCount: row ? 1 : 0 };
    }
    if (q.startsWith('UPDATE delivery_deduplication')) {
      const [key, token, third, fourth] = params as any[];
      const row = this.rows.get(key);
      if (!row || row.claim_token !== token || row.status !== 'in_progress') return { rows: [], rowCount: 0 };
      if (q.includes("status = 'delivered'")) Object.assign(row, { status: 'delivered', delivered_at: third, updated_at: third, lease_until: null, last_error: null });
      else Object.assign(row, { status: 'failed', last_error: third, updated_at: fourth, lease_until: null });
      return { rows: [], rowCount: 1 };
    }
    throw new Error('Unsupported SQL: ' + q);
  }
}

const base = { eventId: 'invoice-paid:inv-123', scope: 'seller-123', destination: 'https://example.test/hook', channel: 'webhook' as const };
const now = new Date('2026-10-18T10:00:00Z');

describe('notification and webhook duplicate suppression', () => {
  it('claims a new delivery and suppresses a duplicate while in progress', async () => {
    const db = new FakeDeliveryDb();
    const first = await claimDelivery(db, base, now);
    const second = await claimDelivery(db, base, now);
    assert.equal(first.claimed, true);
    assert.deepEqual(second, { claimed: false, reason: 'in_progress' });
  });

  it('suppresses completed duplicates across retries', async () => {
    const db = new FakeDeliveryDb();
    const claim = await claimDelivery(db, base, now);
    assert.equal(claim.claimed, true);
    const key = deliveryKey(base);
    assert.equal(await completeDelivery(db, key, claim.token, now), true);
    assert.deepEqual(await claimDelivery(db, base, new Date(now.getTime() + 1000)), { claimed: false, reason: 'already_delivered' });
  });

  it('allows retry after a failed delivery and fences stale workers', async () => {
    const db = new FakeDeliveryDb();
    const first = await claimDelivery(db, base, now);
    assert.equal(first.claimed, true);
    const key = deliveryKey(base);
    assert.equal(await failDelivery(db, key, first.token, new Error('temporary 502'), now), true);
    const retry = await claimDelivery(db, base, new Date(now.getTime() + 1000));
    assert.equal(retry.claimed, true);
    assert.equal(await completeDelivery(db, key, first.token, now), false, 'stale worker cannot complete a newer claim');
    assert.equal(await completeDelivery(db, key, retry.token, now), true);
    assert.equal(db.rows.get(key)?.attempts, 2);
  });

  it('recovers a crashed worker after its lease expires', async () => {
    const db = new FakeDeliveryDb();
    const first = await claimDelivery(db, { ...base, leaseMs: 1000 }, now);
    assert.equal(first.claimed, true);
    const second = await claimDelivery(db, { ...base, leaseMs: 1000 }, new Date(now.getTime() + 1001));
    assert.equal(second.claimed, true);
    assert.equal(await completeDelivery(db, deliveryKey(base), first.token, now), false);
  });

  it('keeps destinations and event keys scoped by authenticated owner and channel', async () => {
    const db = new FakeDeliveryDb();
    const first = await claimDelivery(db, base, now);
    assert.equal(first.claimed, true);
    assert.equal((await claimDelivery(db, { ...base, scope: 'seller-other' }, now)).claimed, true);
    assert.equal((await claimDelivery(db, { ...base, channel: 'notification' }, now)).claimed, true);
    assert.notEqual(deliveryKey(base), deliveryKey({ ...base, scope: 'seller-other' }));
  });

  it('rejects missing identity fields and invalid lease configuration', async () => {
    const db = new FakeDeliveryDb();
    await assert.rejects(() => claimDelivery(db, { ...base, eventId: ' ' }, now), /required/);
    await assert.rejects(() => claimDelivery(db, { ...base, leaseMs: 10 }, now), /leaseMs/);
  });

  it('surfaces database failures so callers can avoid sending without a durable claim', async () => {
    const db = new FakeDeliveryDb();
    db.fail = true;
    await assert.rejects(() => claimDelivery(db, base, now), /database unavailable/);
  });
});
