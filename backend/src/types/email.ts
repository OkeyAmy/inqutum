/**
 * Types for Email Delivery Queue, Retry Policy, and Anti-Spam Relay Protection (Phase E).
 */

export type EmailDeliveryStatus =
  | 'PENDING'
  | 'SENDING'
  | 'SENT'
  | 'FAILED'
  | 'PERMANENTLY_FAILED'
  | 'PAUSED';

export type EmailType = 'INVOICE_SENT' | 'PAYMENT_PROOF' | 'PAYMENT_REMINDER';

export interface EmailDelivery {
  id: string;
  invoiceId: string;
  dedupeKey?: string;
  recipientEmail: string;
  senderWallet: string;
  emailType: EmailType;
  subject: string;
  status: EmailDeliveryStatus;
  attempts: number;
  maxAttempts: number;
  nextAttemptAt: Date;
  lastAttemptAt?: Date;
  lastError?: string;
  isRetryable: boolean;
  payload?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
  sentAt?: Date;
}

export interface EnqueueEmailInput {
  invoiceId: string;
  /** Stable caller-supplied event identity; reusing it suppresses duplicate queueing. */
  dedupeKey?: string;
  recipientEmail: string;
  senderWallet: string;
  emailType: EmailType;
  subject: string;
  payload?: Record<string, any>;
  maxAttempts?: number;
}

export interface EmailDeliveryFilter {
  invoiceId?: string;
  senderWallet?: string;
  status?: EmailDeliveryStatus;
  limit?: number;
  offset?: number;
}

export interface EmailSendResult {
  success: boolean;
  messageId?: string;
  error?: string;
  isRetryable?: boolean;
}

export interface EmailTransporter {
  sendMail(options: {
    to: string;
    from: string;
    subject: string;
    text?: string;
    html?: string;
    attachments?: Array<{ filename: string; content: string | Buffer; contentType?: string }>;
  }): Promise<EmailSendResult>;
}

export interface CircuitBreakerMetrics {
  totalSent: number;
  totalDelivered: number;
  totalBounces: number;
  totalComplaints: number;
  bounceRate: number;
  complaintRate: number;
  isTripped: boolean;
  trippedReason?: string;
  trippedAt?: Date;
}

export interface EmailRateLimitConfig {
  maxEmailsPerHourPerWallet: number;
  bounceRateThreshold: number; // e.g. 0.05 (5%)
  complaintRateThreshold: number; // e.g. 0.001 (0.1%)
  minSampleSizeForBreaker: number;
}
