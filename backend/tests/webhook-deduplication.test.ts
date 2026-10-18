import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { MemoryIdempotencyStore } from '../src/idempotency/memory-store';
import { processWebhook } from '../src/webhooks/process-webhook';

describe('webhook duplicate suppression (#294)', () => {
  it('processes a valid event once and acknowledges a duplicate without rerunning it', async () => {
    const store = new MemoryIdempotencyStore();
    let handled = 0;
    const input = { provider: 'ExamplePay', eventId: 'evt_12345678', rawBody: '{"id":"evt_12345678"}', verifySignature: () => true, handle: () => ++handled };
    assert.deepEqual(await processWebhook(store, input), { accepted: true, duplicate: false, result: 1 });
    assert.deepEqual(await processWebhook(store, input), { accepted: true, duplicate: true, result: 1 });
    assert.equal(handled, 1);
  });

  it('checks signature before reserving an event ID', async () => {
    const store = new MemoryIdempotencyStore();
    let handled = 0;
    const input = { provider: 'ExamplePay', eventId: 'evt_12345678', rawBody: '{}', verifySignature: () => false, handle: () => ++handled };
    assert.deepEqual(await processWebhook(store, input), { accepted: false, status: 401, code: 'WEBHOOK_SIGNATURE_INVALID' });
    assert.deepEqual(await processWebhook(store, { ...input, verifySignature: () => true }), { accepted: true, duplicate: false, result: 1 });
    assert.equal(handled, 1);
  });

  it('releases failed attempts so a provider retry can succeed', async () => {
    const store = new MemoryIdempotencyStore();
    let attempts = 0;
    const input = { provider: 'ExamplePay', eventId: 'evt_retry_123', rawBody: '{"x":1}', verifySignature: () => true, handle: () => { attempts++; if (attempts === 1) throw new Error('temporary'); return 'ok'; } };
    await assert.rejects(() => processWebhook(store, input), /temporary/);
    assert.deepEqual(await processWebhook(store, input), { accepted: true, duplicate: false, result: 'ok' });
    assert.equal(attempts, 2);
  });

  it('rejects reuse of an event ID with a different payload', async () => {
    const store = new MemoryIdempotencyStore();
    const base = { provider: 'ExamplePay', eventId: 'evt_12345678', verifySignature: () => true, handle: () => 'ok' };
    await processWebhook(store, { ...base, rawBody: '{"x":1}' });
    assert.deepEqual(await processWebhook(store, { ...base, rawBody: '{"x":2}' }), { accepted: false, status: 422, code: 'WEBHOOK_EVENT_ID_CONFLICT' });
  });
});
