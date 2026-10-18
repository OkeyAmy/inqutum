import type { Pool } from 'pg';
import type { Queryable } from '../services/invoice.service';
import type {
  EmailDelivery,
  EmailDeliveryFilter,
  EmailDeliveryStatus,
  EnqueueEmailInput,
} from '../types/email';
import type { EmailDeliveryStorage } from './email-delivery-storage';

function mapRowToDelivery(row: any): EmailDelivery {
  return {
    id: row.id,
    invoiceId: row.invoice_id,
    dedupeKey: row.dedupe_key || undefined,
    recipientEmail: row.recipient_email,
    senderWallet: row.sender_wallet,
    emailType: row.email_type,
    subject: row.subject,
    status: row.status,
    attempts: parseInt(row.attempts, 10) || 0,
    maxAttempts: parseInt(row.max_attempts, 10) || 5,
    nextAttemptAt: new Date(row.next_attempt_at),
    lastAttemptAt: row.last_attempt_at ? new Date(row.last_attempt_at) : undefined,
    lastError: row.last_error || undefined,
    isRetryable: row.is_retryable !== false,
    payload: typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload || undefined,
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
    sentAt: row.sent_at ? new Date(row.sent_at) : undefined,
  };
}

export class PostgresEmailDeliveryStorage implements EmailDeliveryStorage {
  public readonly mode = 'postgres';
  private db: Queryable;

  constructor(db: Queryable) {
    this.db = db;
  }

  public async createDelivery(
    input: EnqueueEmailInput,
    initialStatus: EmailDeliveryStatus = 'PENDING'
  ): Promise<EmailDelivery> {
    const text = `
      INSERT INTO email_deliveries (
        invoice_id, dedupe_key, recipient_email, sender_wallet, email_type, subject,
        status, attempts, max_attempts, next_attempt_at, is_retryable, payload
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, NOW(), TRUE, $9)
      ON CONFLICT (dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING
      RETURNING *;
    `;
    const params = [
      input.invoiceId,
      input.dedupeKey ?? null,
      input.recipientEmail,
      input.senderWallet,
      input.emailType,
      input.subject,
      initialStatus,
      input.maxAttempts ?? 5,
      JSON.stringify(input.payload || {}),
    ];

    const res = await this.db.query(text, params);
    if (res.rows[0]) return mapRowToDelivery(res.rows[0]);
    if (input.dedupeKey) {
      const existing = await this.getDeliveryByDedupeKey(input.dedupeKey);
      if (existing) return existing;
    }
    throw new Error('Email delivery insert returned no row and no matching dedupe key');
  }

  public async createDeliveryWithDedupe(input: EnqueueEmailInput, initialStatus: EmailDeliveryStatus = 'PENDING'): Promise<{ delivery: EmailDelivery; created: boolean }> {
    const before = input.dedupeKey ? await this.getDeliveryByDedupeKey(input.dedupeKey) : null;
    const delivery = await this.createDelivery(input, initialStatus);
    return { delivery, created: !before && delivery.createdAt.getTime() >= Date.now() - 5000 && delivery.dedupeKey === input.dedupeKey && delivery.status === initialStatus && delivery.attempts === 0 };
  }

  public async getDeliveryByDedupeKey(key: string): Promise<EmailDelivery | null> {
    const res = await this.db.query('SELECT * FROM email_deliveries WHERE dedupe_key = $1 LIMIT 1;', [key]);
    return res.rows[0] ? mapRowToDelivery(res.rows[0]) : null;
  }

  public async getDeliveryById(id: string): Promise<EmailDelivery | null> {
    const text = `SELECT * FROM email_deliveries WHERE id = $1 LIMIT 1;`;
    const res = await this.db.query(text, [id]);
    if (res.rows.length === 0) return null;
    return mapRowToDelivery(res.rows[0]);
  }

  public async listDeliveries(filter: EmailDeliveryFilter = {}): Promise<EmailDelivery[]> {
    const conditions: string[] = [];
    const params: any[] = [];
    let idx = 1;

    if (filter.invoiceId) {
      conditions.push(`invoice_id = $${idx++}`);
      params.push(filter.invoiceId);
    }
    if (filter.senderWallet) {
      conditions.push(`sender_wallet = $${idx++}`);
      params.push(filter.senderWallet);
    }
    if (filter.status) {
      conditions.push(`status = $${idx++}`);
      params.push(filter.status);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = filter.limit ? `LIMIT ${filter.limit}` : '';
    const offset = filter.offset ? `OFFSET ${filter.offset}` : '';

    const text = `SELECT * FROM email_deliveries ${whereClause} ORDER BY created_at DESC ${limit} ${offset};`;
    const res = await this.db.query(text, params);
    return res.rows.map(mapRowToDelivery);
  }

  public async getPendingDeliveries(maxCount = 50, now: Date = new Date()): Promise<EmailDelivery[]> {
    const text = `
      SELECT * FROM email_deliveries
      WHERE status = 'PENDING' AND next_attempt_at <= $1
      ORDER BY next_attempt_at ASC
      LIMIT $2;
    `;
    const res = await this.db.query(text, [now.toISOString(), maxCount]);
    return res.rows.map(mapRowToDelivery);
  }

  public async updateDeliveryStatus(
    id: string,
    update: {
      status: EmailDeliveryStatus;
      attempts: number;
      lastError?: string;
      isRetryable?: boolean;
      nextAttemptAt?: Date;
      lastAttemptAt?: Date;
      sentAt?: Date;
    }
  ): Promise<EmailDelivery | null> {
    const text = `
      UPDATE email_deliveries
      SET status = $1,
          attempts = $2,
          last_error = $3,
          is_retryable = $4,
          next_attempt_at = COALESCE($5, next_attempt_at),
          last_attempt_at = COALESCE($6, last_attempt_at),
          sent_at = COALESCE($7, sent_at),
          updated_at = NOW()
      WHERE id = $8
      RETURNING *;
    `;
    const params = [
      update.status,
      update.attempts,
      update.lastError || null,
      update.isRetryable !== false,
      update.nextAttemptAt ? update.nextAttemptAt.toISOString() : null,
      update.lastAttemptAt ? update.lastAttemptAt.toISOString() : null,
      update.sentAt ? update.sentAt.toISOString() : null,
      id,
    ];

    const res = await this.db.query(text, params);
    if (res.rows.length === 0) return null;
    return mapRowToDelivery(res.rows[0]);
  }

  public async resumePausedDeliveries(limit = 100): Promise<number> {
    const text = `
      UPDATE email_deliveries
      SET status = 'PENDING',
          next_attempt_at = NOW(),
          updated_at = NOW()
      WHERE id IN (
        SELECT id FROM email_deliveries WHERE status = 'PAUSED' LIMIT $1
      )
      RETURNING id;
    `;
    const res = await this.db.query(text, [limit]);
    return res.rows.length;
  }

  public async clear(): Promise<void> {
    await this.db.query('DELETE FROM email_deliveries;');
  }
}
