import { randomUUID } from 'node:crypto';
import type {
  EmailDelivery,
  EmailDeliveryFilter,
  EmailDeliveryStatus,
  EnqueueEmailInput,
} from '../types/email';
import type { EmailDeliveryStorage } from './email-delivery-storage';

export class MemoryEmailDeliveryStorage implements EmailDeliveryStorage {
  public readonly mode = 'memory';
  private deliveries: Map<string, EmailDelivery> = new Map();

  public async createDelivery(
    input: EnqueueEmailInput,
    initialStatus: EmailDeliveryStatus = 'PENDING'
  ): Promise<EmailDelivery> {
    if (input.dedupeKey) {
      const existing = Array.from(this.deliveries.values()).find((d) => d.dedupeKey === input.dedupeKey);
      if (existing) return { ...existing };
    }
    const now = new Date();
    const delivery: EmailDelivery = {
      id: randomUUID(),
      invoiceId: input.invoiceId,
      dedupeKey: input.dedupeKey,
      recipientEmail: input.recipientEmail,
      senderWallet: input.senderWallet,
      emailType: input.emailType,
      subject: input.subject,
      status: initialStatus,
      attempts: 0,
      maxAttempts: input.maxAttempts ?? 5,
      nextAttemptAt: now,
      isRetryable: true,
      payload: input.payload,
      createdAt: now,
      updatedAt: now,
    };

    this.deliveries.set(delivery.id, delivery);
    return { ...delivery };
  }

  public async getDeliveryByDedupeKey(key: string): Promise<EmailDelivery | null> {
    const found = Array.from(this.deliveries.values()).find((d) => d.dedupeKey === key);
    return found ? { ...found } : null;
  }

  public async getDeliveryById(id: string): Promise<EmailDelivery | null> {
    const found = this.deliveries.get(id);
    return found ? { ...found } : null;
  }

  public async listDeliveries(filter: EmailDeliveryFilter = {}): Promise<EmailDelivery[]> {
    let list = Array.from(this.deliveries.values());

    if (filter.invoiceId) {
      list = list.filter((d) => d.invoiceId === filter.invoiceId);
    }
    if (filter.senderWallet) {
      list = list.filter((d) => d.senderWallet === filter.senderWallet);
    }
    if (filter.status) {
      list = list.filter((d) => d.status === filter.status);
    }

    list.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

    const offset = filter.offset || 0;
    const limit = filter.limit || list.length;
    return list.slice(offset, offset + limit).map((d) => ({ ...d }));
  }

  public async getPendingDeliveries(maxCount = 50, now: Date = new Date()): Promise<EmailDelivery[]> {
    const list = Array.from(this.deliveries.values())
      .filter((d) => d.status === 'PENDING' && d.nextAttemptAt.getTime() <= now.getTime())
      .sort((a, b) => a.nextAttemptAt.getTime() - b.nextAttemptAt.getTime())
      .slice(0, maxCount);

    return list.map((d) => ({ ...d }));
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
    const existing = this.deliveries.get(id);
    if (!existing) {
      return null;
    }

    const updated: EmailDelivery = {
      ...existing,
      status: update.status,
      attempts: update.attempts,
      lastError: update.lastError !== undefined ? update.lastError : existing.lastError,
      isRetryable: update.isRetryable !== undefined ? update.isRetryable : existing.isRetryable,
      nextAttemptAt: update.nextAttemptAt ?? existing.nextAttemptAt,
      lastAttemptAt: update.lastAttemptAt ?? existing.lastAttemptAt,
      sentAt: update.sentAt ?? existing.sentAt,
      updatedAt: new Date(),
    };

    this.deliveries.set(id, updated);
    return { ...updated };
  }

  public async resumePausedDeliveries(limit = 100): Promise<number> {
    let count = 0;
    const now = new Date();
    for (const [id, delivery] of this.deliveries.entries()) {
      if (delivery.status === 'PAUSED') {
        this.deliveries.set(id, {
          ...delivery,
          status: 'PENDING',
          nextAttemptAt: now,
          updatedAt: now,
        });
        count++;
        if (count >= limit) break;
      }
    }
    return count;
  }

  public async clear(): Promise<void> {
    this.deliveries.clear();
  }
}

export const memoryEmailDeliveryStorage = new MemoryEmailDeliveryStorage();
export default memoryEmailDeliveryStorage;
