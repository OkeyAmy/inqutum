import type {
  EmailDelivery,
  EmailDeliveryStatus,
  EmailSendResult,
  EmailTransporter,
  EnqueueEmailInput,
} from '../types/email';
import type { EmailDeliveryStorage } from '../storage/email-delivery-storage';
import { memoryEmailDeliveryStorage } from '../storage/memory-email-delivery-storage';
import { EmailAntiSpamService, emailAntiSpamService } from './email-anti-spam.service';
import { quotaManager } from '../domain/quota-management';

export interface EmailRetryConfig {
  initialBackoffMs: number;
  backoffMultiplier: number;
  maxBackoffMs: number;
  defaultMaxAttempts: number;
}

const DEFAULT_RETRY_CONFIG: EmailRetryConfig = {
  initialBackoffMs: 1000, // 1 second
  backoffMultiplier: 2,
  maxBackoffMs: 3600 * 1000, // 1 hour max backoff
  defaultMaxAttempts: 5,
};

export class MockTransporter implements EmailTransporter {
  public sentEmails: Array<{
    to: string;
    from: string;
    subject: string;
    text?: string;
    html?: string;
    attachments?: any[];
  }> = [];

  public shouldFailNext = false;
  public failError = 'Temporary SMTP failure';
  public failRetryable = true;

  public async sendMail(options: {
    to: string;
    from: string;
    subject: string;
    text?: string;
    html?: string;
    attachments?: any[];
  }): Promise<EmailSendResult> {
    if (this.shouldFailNext) {
      this.shouldFailNext = false;
      return {
        success: false,
        error: this.failError,
        isRetryable: this.failRetryable,
      };
    }

    this.sentEmails.push(options);
    return {
      success: true,
      messageId: `mock-msg-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
    };
  }

  public clear(): void {
    this.sentEmails = [];
    this.shouldFailNext = false;
  }
}

export class EmailQueueService {
  private storage: EmailDeliveryStorage;
  private antiSpam: EmailAntiSpamService;
  private transporter: EmailTransporter;
  private retryConfig: EmailRetryConfig;
  private maxEmailsPerInvoice: number;
  private timer: NodeJS.Timeout | null = null;
  private isProcessing = false;

  constructor(options: {
    storage?: EmailDeliveryStorage;
    antiSpam?: EmailAntiSpamService;
    transporter?: EmailTransporter;
    retryConfig?: Partial<EmailRetryConfig>;
    maxEmailsPerInvoice?: number;
  } = {}) {
    this.storage = options.storage || memoryEmailDeliveryStorage;
    this.antiSpam = options.antiSpam || emailAntiSpamService;
    this.transporter = options.transporter || new MockTransporter();
    this.retryConfig = { ...DEFAULT_RETRY_CONFIG, ...options.retryConfig };
    this.maxEmailsPerInvoice =
      options.maxEmailsPerInvoice ??
      parseInt(process.env.MAX_EMAILS_PER_INVOICE || '5', 10);
  }

  public setStorage(storage: EmailDeliveryStorage): void {
    this.storage = storage;
  }

  public setTransporter(transporter: EmailTransporter): void {
    this.transporter = transporter;
  }

  /**
   * Enqueue an outbound email.
   * Runs anti-spam checks:
   * 1. Recipient address validation.
   * 2. Per-wallet rate limiting.
   * 3. Circuit breaker state check (if tripped, marks as PAUSED).
   */
  public async enqueue(input: EnqueueEmailInput): Promise<{
    success: boolean;
    delivery?: EmailDelivery;
    error?: string;
    code?: string;
    retryAfterSeconds?: number;
  }> {
    const val = this.antiSpam.validateRecipient(input.recipientEmail);
    if (!val.valid) {
      return { success: false, code: 'INVALID_RECIPIENT_EMAIL', error: val.error };
    }

    const contentCheck = this.antiSpam.validateContent(
      `${input.subject || ''} ${input.payload?.text || ''}`
    );
    if (!contentCheck.valid) {
      return { success: false, code: 'SPAM_CONTENT_REJECTED', error: contentCheck.error };
    }

    // A caller-supplied key is scoped to this sender. Do this before rate/quota consumption
    // so a duplicate retry returns the original delivery without consuming another slot.
    if (input.dedupeKey !== undefined) {
      const key = input.dedupeKey.trim();
      if (key.length < 8 || key.length > 255 || !/^[A-Za-z0-9_.:-]+$/.test(key)) {
        return { success: false, code: 'NOTIFICATION_DEDUPE_KEY_INVALID', error: 'dedupeKey must be 8-255 URL-safe characters' };
      }
      const existing = await this.storage.getDeliveryByDedupeKey(input.senderWallet + ':' + key);
      if (existing) {
        const samePayload = JSON.stringify(existing.payload ?? {}) === JSON.stringify(input.payload ?? {});
        if (existing.invoiceId !== input.invoiceId || existing.recipientEmail.toLowerCase() !== val.normalized?.toLowerCase() || existing.emailType !== input.emailType || existing.subject !== input.subject || !samePayload) {
          return { success: false, code: 'NOTIFICATION_DEDUPE_KEY_CONFLICT', error: 'dedupeKey was already used for a different notification' };
        }
        return { success: true, delivery: existing };
      }
      input = { ...input, dedupeKey: input.senderWallet + ':' + key };
    }

    const rateCheck = this.antiSpam.checkWalletRateLimit(input.senderWallet);
    if (!rateCheck.allowed) {
      return {
        success: false,
        code: 'EMAIL_RATE_LIMIT_EXCEEDED',
        error: `Outbound email rate limit exceeded for wallet (${rateCheck.currentCount}/${rateCheck.maxAllowed} per hour)`,
        retryAfterSeconds: rateCheck.retryAfterSeconds,
      };
    }

    // Per-invoice email cap (Issue #31): Enforce max outbound emails per invoice to prevent spam relays
    const existingDeliveries = await this.storage.listDeliveries({ invoiceId: input.invoiceId });
    if (existingDeliveries.length >= this.maxEmailsPerInvoice) {
      return {
        success: false,
        code: 'EXCEEDED_INVOICE_EMAIL_LIMIT',
        error: `Maximum email notification limit reached for this invoice (${this.maxEmailsPerInvoice} per invoice)`,
      };
    }

    // Reserve only after validation and the existing per-invoice cap: this is
    // the point at which the request can actually consume queue capacity.
    const quota = quotaManager.reserve('email_enqueue', {
      actor: input.senderWallet,
      resource: input.invoiceId,
    });
    if (!quota.allowed) {
      return {
        success: false,
        code: quota.code,
        error: quota.message,
        retryAfterSeconds: quota.retryAfterSeconds,
      };
    }

    const isBreakerTripped = this.antiSpam.isCircuitBreakerTripped();
    const initialStatus: EmailDeliveryStatus = isBreakerTripped ? 'PAUSED' : 'PENDING';

    let delivery: EmailDelivery;
    try {
      delivery = await this.storage.createDelivery(
      {
        ...input,
        recipientEmail: val.normalized || input.recipientEmail,
        maxAttempts: input.maxAttempts || this.retryConfig.defaultMaxAttempts,
      },
      initialStatus
      );
      if (input.dedupeKey) {
        const samePayload = JSON.stringify(delivery.payload ?? {}) === JSON.stringify(input.payload ?? {});
        if (delivery.invoiceId !== input.invoiceId || delivery.recipientEmail.toLowerCase() !== (val.normalized || input.recipientEmail).toLowerCase() || delivery.emailType !== input.emailType || delivery.subject !== input.subject || !samePayload) {
          return { success: false, code: 'NOTIFICATION_DEDUPE_KEY_CONFLICT', error: 'dedupeKey was already used for a different notification' };
        }
      }
    } catch (error) {
      // Concurrent duplicate enqueue can race the preflight lookup. Recover by
      // reading the unique-key winner; propagate unrelated storage failures.
      if (input.dedupeKey) {
        const existing = await this.storage.getDeliveryByDedupeKey(input.dedupeKey);
        if (existing) {
          const samePayload = JSON.stringify(existing.payload ?? {}) === JSON.stringify(input.payload ?? {});
          if (existing.invoiceId !== input.invoiceId || existing.recipientEmail.toLowerCase() !== (val.normalized || input.recipientEmail).toLowerCase() || existing.emailType !== input.emailType || existing.subject !== input.subject || !samePayload) {
            return { success: false, code: 'NOTIFICATION_DEDUPE_KEY_CONFLICT', error: 'dedupeKey was already used for a different notification' };
          }
          return { success: true, delivery: existing };
        }
      }
      throw error;
    }

    this.antiSpam.recordWalletSend(input.senderWallet);

    return { success: true, delivery };
  }

  /**
   * Calculate next retry timestamp using exponential backoff.
   */
  public calculateNextAttempt(attemptNumber: number): Date {
    const { initialBackoffMs, backoffMultiplier, maxBackoffMs } = this.retryConfig;
    const exponent = Math.max(0, attemptNumber - 1);
    const delayMs = Math.min(maxBackoffMs, initialBackoffMs * Math.pow(backoffMultiplier, exponent));
    return new Date(Date.now() + delayMs);
  }

  /**
   * Classify whether an error message / code represents a permanent failure that should not be retried.
   */
  public isPermanentError(error: string): boolean {
    const lower = (error || '').toLowerCase();
    return (
      lower.includes('invalid recipient') ||
      lower.includes('user not found') ||
      lower.includes('550') ||
      lower.includes('554') ||
      lower.includes('mailbox unavailable') ||
      lower.includes('spam rejected') ||
      lower.includes('domain does not exist') ||
      lower.includes('address rejected')
    );
  }

  /**
   * Process a single email delivery.
   */
  public async processDelivery(deliveryId: string): Promise<EmailDelivery | null> {
    const delivery = await this.storage.getDeliveryById(deliveryId);
    if (!delivery) return null;

    if (delivery.status === 'SENT' || delivery.status === 'PERMANENTLY_FAILED') {
      return delivery;
    }

    if (this.antiSpam.isCircuitBreakerTripped()) {
      return this.storage.updateDeliveryStatus(delivery.id, {
        status: 'PAUSED',
        attempts: delivery.attempts,
        lastError: 'Circuit breaker is active due to elevated bounce/complaint rate',
      });
    }

    const currentAttempt = delivery.attempts + 1;
    const now = new Date();

    try {
      const result = await this.transporter.sendMail({
        to: delivery.recipientEmail,
        from: 'no-reply@quittance.network',
        subject: delivery.subject,
        text: delivery.payload?.text || `Invoice notification for ${delivery.invoiceId}`,
        html: delivery.payload?.html,
      });

      if (result.success) {
        this.antiSpam.recordDelivery();
        return await this.storage.updateDeliveryStatus(delivery.id, {
          status: 'SENT',
          attempts: currentAttempt,
          lastAttemptAt: now,
          sentAt: now,
        });
      }

      const errorMsg = result.error || 'Unknown send failure';
      const isRetryable = result.isRetryable !== undefined ? result.isRetryable : !this.isPermanentError(errorMsg);

      if (!isRetryable) {
        this.antiSpam.recordBounce();
        return await this.storage.updateDeliveryStatus(delivery.id, {
          status: 'PERMANENTLY_FAILED',
          attempts: currentAttempt,
          lastError: errorMsg,
          isRetryable: false,
          lastAttemptAt: now,
        });
      }

      if (currentAttempt >= delivery.maxAttempts) {
        this.antiSpam.recordBounce();
        return await this.storage.updateDeliveryStatus(delivery.id, {
          status: 'PERMANENTLY_FAILED',
          attempts: currentAttempt,
          lastError: `Max attempts (${delivery.maxAttempts}) reached. Last error: ${errorMsg}`,
          isRetryable: false,
          lastAttemptAt: now,
        });
      }

      // Schedule retry with exponential backoff
      const nextAttemptAt = this.calculateNextAttempt(currentAttempt);
      return await this.storage.updateDeliveryStatus(delivery.id, {
        status: 'PENDING',
        attempts: currentAttempt,
        lastError: errorMsg,
        isRetryable: true,
        lastAttemptAt: now,
        nextAttemptAt,
      });
    } catch (error: any) {
      const errorMsg = error?.message || String(error);
      const isRetryable = !this.isPermanentError(errorMsg);

      if (!isRetryable || currentAttempt >= delivery.maxAttempts) {
        this.antiSpam.recordBounce();
        return await this.storage.updateDeliveryStatus(delivery.id, {
          status: 'PERMANENTLY_FAILED',
          attempts: currentAttempt,
          lastError: errorMsg,
          isRetryable: false,
          lastAttemptAt: now,
        });
      }

      const nextAttemptAt = this.calculateNextAttempt(currentAttempt);
      return await this.storage.updateDeliveryStatus(delivery.id, {
        status: 'PENDING',
        attempts: currentAttempt,
        lastError: errorMsg,
        isRetryable: true,
        lastAttemptAt: now,
        nextAttemptAt,
      });
    }
  }

  /**
   * Process a batch of pending emails ready for sending.
   */
  public async processPendingBatch(maxCount = 20): Promise<number> {
    if (this.isProcessing) return 0;
    this.isProcessing = true;

    try {
      if (this.antiSpam.isCircuitBreakerTripped()) {
        return 0;
      }

      const pending = await this.storage.getPendingDeliveries(maxCount, new Date());
      let processed = 0;

      for (const item of pending) {
        await this.processDelivery(item.id);
        processed++;
      }

      return processed;
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Resume paused emails after the circuit breaker is reset.
   */
  public async resumePausedEmails(): Promise<number> {
    if (this.antiSpam.isCircuitBreakerTripped()) {
      return 0;
    }
    return this.storage.resumePausedDeliveries();
  }

  /**
   * Get deliveries for a specific invoice.
   */
  public async getInvoiceDeliveries(invoiceId: string): Promise<EmailDelivery[]> {
    return this.storage.listDeliveries({ invoiceId });
  }

  /**
   * Start background queue worker.
   */
  public startWorker(intervalMs = 5000): void {
    if (this.timer) return;
    this.timer = setInterval(async () => {
      try {
        await this.processPendingBatch();
      } catch (err) {
        console.error('Email queue worker error:', err);
      }
    }, intervalMs);
  }

  /**
   * Stop background queue worker.
   */
  public stopWorker(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}

export const emailQueueService = new EmailQueueService();
export default emailQueueService;
