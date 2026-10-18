import assert from 'node:assert/strict';
import { describe, it, beforeEach } from 'node:test';
import { EmailAntiSpamService } from '../src/services/email-anti-spam.service';
import { MemoryEmailDeliveryStorage } from '../src/storage/memory-email-delivery-storage';
import { EmailQueueService, MockTransporter } from '../src/services/email-queue.service';
import type { EnqueueEmailInput } from '../src/types/email';

describe('Phase E: Email Queue, Retry Policy, and Anti-Spam Protection', () => {
  let antiSpam: EmailAntiSpamService;
  let storage: MemoryEmailDeliveryStorage;
  let transporter: MockTransporter;
  let queue: EmailQueueService;

  const WALLET_A = 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN';
  const WALLET_B = 'GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H';
  const INVOICE_ID = '00000000-0000-0000-0000-000000000001';

  beforeEach(async () => {
    antiSpam = new EmailAntiSpamService({
      maxEmailsPerHourPerWallet: 3,
      bounceRateThreshold: 0.1, // 10%
      complaintRateThreshold: 0.01,
      minSampleSizeForBreaker: 5,
    });
    storage = new MemoryEmailDeliveryStorage();
    transporter = new MockTransporter();
    queue = new EmailQueueService({
      storage,
      antiSpam,
      transporter,
      retryConfig: {
        initialBackoffMs: 100,
        backoffMultiplier: 2,
        maxBackoffMs: 1000,
        defaultMaxAttempts: 3,
      },
    });
  });

  describe('Issue #38: Anti-Spam & Rate Limiting Controls', () => {
    it('validates recipient format and prevents CRLF header injection', () => {
      const valid = antiSpam.validateRecipient('client@example.com');
      assert.equal(valid.valid, true);
      assert.equal(valid.normalized, 'client@example.com');

      const invalidEmail = antiSpam.validateRecipient('not-an-email');
      assert.equal(invalidEmail.valid, false);

      const headerInjection = antiSpam.validateRecipient('victim@example.com\r\nBcc: spam@bad.com');
      assert.equal(headerInjection.valid, false);
      assert.match(headerInjection.error!, /invalid control characters/i);
    });

    it('enforces per-wallet outbound rate limits distinct from IP rate limits', async () => {
      const input: EnqueueEmailInput = {
        invoiceId: INVOICE_ID,
        recipientEmail: 'client1@example.com',
        senderWallet: WALLET_A,
        emailType: 'INVOICE_SENT',
        subject: 'Invoice 1',
      };

      // 1st, 2nd, 3rd sends succeed
      const res1 = await queue.enqueue(input);
      assert.equal(res1.success, true);

      const res2 = await queue.enqueue({ ...input, recipientEmail: 'client2@example.com' });
      assert.equal(res2.success, true);

      const res3 = await queue.enqueue({ ...input, recipientEmail: 'client3@example.com' });
      assert.equal(res3.success, true);

      // 4th send for WALLET_A should be blocked by rate limiter
      const res4 = await queue.enqueue({ ...input, recipientEmail: 'client4@example.com' });
      assert.equal(res4.success, false);
      assert.equal(res4.code, 'EMAIL_RATE_LIMIT_EXCEEDED');
      assert.ok(res4.retryAfterSeconds! > 0);

      // Distinct wallet WALLET_B is unaffected
      const resB = await queue.enqueue({ ...input, senderWallet: WALLET_B });
      assert.equal(resB.success, true);
    });

    it('automatically trips circuit breaker on excessive bounce rates and pauses queued sends without dropping them', async () => {
      const WALLET_C = 'G' + 'C'.repeat(55);
      // Simulate 5 sends with 2 bounces (40% bounce rate > 10% threshold)
      for (let i = 0; i < 3; i++) {
        antiSpam.recordDelivery();
      }
      for (let i = 0; i < 2; i++) {
        antiSpam.recordBounce();
      }

      assert.equal(antiSpam.isCircuitBreakerTripped(), true);
      const metrics = antiSpam.getCircuitBreakerMetrics();
      assert.equal(metrics.isTripped, true);
      assert.ok(metrics.bounceRate > 0.1);

      // When breaker is tripped, new enqueued emails are set to PAUSED status
      const input: EnqueueEmailInput = {
        invoiceId: INVOICE_ID,
        recipientEmail: 'paused@example.com',
        senderWallet: WALLET_C,
        emailType: 'INVOICE_SENT',
        subject: 'Paused Invoice',
      };
      const enqueued = await queue.enqueue(input);
      assert.equal(enqueued.success, true);
      assert.equal(enqueued.delivery?.status, 'PAUSED');

      // Resetting circuit breaker allows resuming paused emails
      antiSpam.resetCircuitBreaker();
      assert.equal(antiSpam.isCircuitBreakerTripped(), false);

      const resumedCount = await queue.resumePausedEmails();
      assert.equal(resumedCount >= 1, true);

      const reloaded = await storage.getDeliveryById(enqueued.delivery!.id);
      assert.equal(reloaded?.status, 'PENDING');
    });
  });

  describe('Issue #37: Email Delivery Queue, Retry Policy, and Visibility', () => {
    it('suppresses duplicate enqueue keys and rejects malformed keys', async () => {
      const input: EnqueueEmailInput = {
        invoiceId: INVOICE_ID, dedupeKey: 'event_12345678', recipientEmail: 'dedupe@example.com',
        senderWallet: WALLET_A, emailType: 'INVOICE_SENT', subject: 'One notification',
      };
      const first = await queue.enqueue(input);
      const duplicate = await queue.enqueue({ ...input });
      assert.equal(first.success, true);
      assert.equal(duplicate.success, true);
      assert.equal(duplicate.delivery?.id, first.delivery?.id);
      assert.equal((await storage.listDeliveries({ invoiceId: INVOICE_ID })).length, 1);
      const conflict = await queue.enqueue({ ...input, subject: 'Different notification' });
      assert.equal(conflict.success, false);
      assert.equal(conflict.code, 'NOTIFICATION_DEDUPE_KEY_CONFLICT');
      const invalid = await queue.enqueue({ ...input, dedupeKey: 'bad' });
      assert.equal(invalid.success, false);
      assert.equal(invalid.code, 'NOTIFICATION_DEDUPE_KEY_INVALID');
    });

    it('successfully delivers email and records persistent audit fields', async () => {
      const input: EnqueueEmailInput = {
        invoiceId: INVOICE_ID,
        recipientEmail: 'happy@example.com',
        senderWallet: WALLET_A,
        emailType: 'INVOICE_SENT',
        subject: 'Happy Path Invoice',
      };

      const enqueued = await queue.enqueue(input);
      assert.equal(enqueued.success, true);
      const deliveryId = enqueued.delivery!.id;

      const processed = await queue.processDelivery(deliveryId);
      assert.equal(processed?.status, 'SENT');
      assert.equal(processed?.attempts, 1);
      assert.ok(processed?.sentAt instanceof Date);
      assert.equal(transporter.sentEmails.length, 1);
      assert.equal(transporter.sentEmails[0].to, 'happy@example.com');
    });

    it('retries with exponential backoff on transient errors and marks PERMANENTLY_FAILED after max attempts', async () => {
      const input: EnqueueEmailInput = {
        invoiceId: INVOICE_ID,
        recipientEmail: 'retry@example.com',
        senderWallet: WALLET_A,
        emailType: 'PAYMENT_PROOF',
        subject: 'Payment Proof Retry',
        maxAttempts: 3,
      };

      const enqueued = await queue.enqueue(input);
      const deliveryId = enqueued.delivery!.id;

      // Attempt 1: Transient failure
      transporter.shouldFailNext = true;
      transporter.failError = 'Connection timed out';
      transporter.failRetryable = true;

      const step1 = await queue.processDelivery(deliveryId);
      assert.equal(step1?.status, 'PENDING');
      assert.equal(step1?.attempts, 1);
      assert.equal(step1?.isRetryable, true);
      assert.match(step1?.lastError!, /timed out/i);
      assert.ok(step1!.nextAttemptAt.getTime() > Date.now());

      // Attempt 2: Transient failure
      transporter.shouldFailNext = true;
      transporter.failError = '429 Rate limited by upstream SMTP';
      transporter.failRetryable = true;

      const step2 = await queue.processDelivery(deliveryId);
      assert.equal(step2?.status, 'PENDING');
      assert.equal(step2?.attempts, 2);

      // Attempt 3: Final failure reaching maxAttempts -> PERMANENTLY_FAILED
      transporter.shouldFailNext = true;
      transporter.failError = '503 Service unavailable';
      transporter.failRetryable = true;

      const step3 = await queue.processDelivery(deliveryId);
      assert.equal(step3?.status, 'PERMANENTLY_FAILED');
      assert.equal(step3?.attempts, 3);
      assert.equal(step3?.isRetryable, false);
      assert.match(step3?.lastError!, /Max attempts \(3\) reached/i);
    });

    it('immediately fails permanently on non-retryable errors (e.g. 550 User unknown)', async () => {
      const input: EnqueueEmailInput = {
        invoiceId: INVOICE_ID,
        recipientEmail: 'bad-inbox@example.com',
        senderWallet: WALLET_A,
        emailType: 'INVOICE_SENT',
        subject: 'Permanent Failure Invoice',
        maxAttempts: 5,
      };

      const enqueued = await queue.enqueue(input);
      const deliveryId = enqueued.delivery!.id;

      transporter.shouldFailNext = true;
      transporter.failError = '550 User not found / mailbox unavailable';
      transporter.failRetryable = false;

      const result = await queue.processDelivery(deliveryId);
      assert.equal(result?.status, 'PERMANENTLY_FAILED');
      assert.equal(result?.attempts, 1);
      assert.equal(result?.isRetryable, false);
    });

    it('surfaces delivery records to freelancer for an invoice', async () => {
      const input: EnqueueEmailInput = {
        invoiceId: INVOICE_ID,
        recipientEmail: 'client@example.com',
        senderWallet: WALLET_A,
        emailType: 'INVOICE_SENT',
        subject: 'Visible Delivery',
      };

      await queue.enqueue(input);
      const deliveries = await queue.getInvoiceDeliveries(INVOICE_ID);
      assert.equal(deliveries.length, 1);
      assert.equal(deliveries[0].invoiceId, INVOICE_ID);
      assert.equal(deliveries[0].recipientEmail, 'client@example.com');
      assert.equal(deliveries[0].status, 'PENDING');
    });

    it('preserves queued sends across storage re-initialization (server restart simulation)', async () => {
      const input: EnqueueEmailInput = {
        invoiceId: INVOICE_ID,
        recipientEmail: 'durable@example.com',
        senderWallet: WALLET_A,
        emailType: 'INVOICE_SENT',
        subject: 'Durable Send',
      };

      const enqueued = await queue.enqueue(input);
      assert.equal(enqueued.success, true);

      // Simulate new server instance reusing the storage
      const newQueue = new EmailQueueService({
        storage,
        antiSpam,
        transporter,
      });

      const pending = await storage.getPendingDeliveries(10, new Date(Date.now() + 1000));
      assert.equal(pending.some((d) => d.id === enqueued.delivery!.id), true);

      const processedCount = await newQueue.processPendingBatch(10);
      assert.equal(processedCount >= 1, true);

      const reloaded = await storage.getDeliveryById(enqueued.delivery!.id);
      assert.equal(reloaded?.status, 'SENT');
    });
  });
});
