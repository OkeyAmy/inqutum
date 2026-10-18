import type {
  EmailDelivery,
  EmailDeliveryFilter,
  EmailDeliveryStatus,
  EnqueueEmailInput,
} from '../types/email';

export interface EmailDeliveryStorage {
  readonly mode: string;
  createDelivery(input: EnqueueEmailInput, initialStatus?: EmailDeliveryStatus): Promise<EmailDelivery>;
  getDeliveryByDedupeKey(key: string): Promise<EmailDelivery | null>;
  getDeliveryById(id: string): Promise<EmailDelivery | null>;
  listDeliveries(filter?: EmailDeliveryFilter): Promise<EmailDelivery[]>;
  getPendingDeliveries(maxCount?: number, now?: Date): Promise<EmailDelivery[]>;
  updateDeliveryStatus(
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
  ): Promise<EmailDelivery | null>;
  resumePausedDeliveries(limit?: number): Promise<number>;
  clear(): Promise<void>;
}
