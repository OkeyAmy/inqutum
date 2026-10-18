/**
 * Health probes for external dependencies.
 *
 * Each probe checks a single external dependency and returns a ProbeResult.
 * These are used by the public dependency-aware health endpoint.
 */
import type { DependencyProbe, ProbeResult, DependencyId } from './ops/dependency-degradation';
import { pool } from './config/database';
import { server } from './config/stellar';
import Redis from 'ioredis';

const TIMEOUT_MS = 3000;

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`${label} timeout after ${ms}ms`)), ms)
    ),
  ]);
}

/** PostgreSQL probe — simple SELECT 1 to verify connectivity. */
export async function postgresProbe(): Promise<ProbeResult> {
  const started = Date.now();
  try {
    await withTimeout(pool.query('SELECT 1'), TIMEOUT_MS, 'PostgreSQL');
    return { ok: true, latencyMs: Date.now() - started };
  } catch (err) {
    return { ok: false, latencyMs: Date.now() - started, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Stellar Horizon probe — lightweight account check or ledger fetch. */
export async function stellarHorizonProbe(): Promise<ProbeResult> {
  const started = Date.now();
  try {
    // Use a lightweight call: fetch the latest ledger sequence
    await withTimeout(server.ledgers().limit(1).call(), TIMEOUT_MS, 'Stellar Horizon');
    return { ok: true, latencyMs: Date.now() - started };
  } catch (err) {
    return { ok: false, latencyMs: Date.now() - started, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Redis probe — PING to verify connectivity using a fresh client with no retries. */
export async function redisQueueProbe(): Promise<ProbeResult> {
  const started = Date.now();
  const redisHost = process.env.REDIS_HOST || 'localhost';
  const redisPort = process.env.REDIS_PORT ? parseInt(process.env.REDIS_PORT, 10) : 6379;

  // Create a one-shot client with no retries for the probe
  const client = new Redis({
    host: redisHost,
    port: redisPort,
    maxRetriesPerRequest: 1,
    retryStrategy: () => null, // Disable retries
    connectTimeout: TIMEOUT_MS,
    lazyConnect: true,
  });

  // Suppress unhandled error events during probe
  client.on('error', () => {});

  try {
    await client.connect();
    const result = await withTimeout(client.ping(), TIMEOUT_MS, 'Redis');
    await client.quit();
    return { ok: result === 'PONG', latencyMs: Date.now() - started, error: result === 'PONG' ? undefined : 'unexpected response' };
  } catch (err) {
    try { await client.quit(); } catch {}
    return { ok: false, latencyMs: Date.now() - started, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Email provider probe — verify SMTP connection if configured. */
export async function emailProviderProbe(): Promise<ProbeResult> {
  const started = Date.now();
  const smtpHost = process.env.SMTP_HOST;
  const smtpPort = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587;
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;

  // If not configured, return unknown (not a hard failure)
  if (!smtpHost || !smtpUser || !smtpPass) {
    return { ok: true, latencyMs: 0, error: undefined };
  }

  // Dynamic import to avoid requiring nodemailer when not used
  // @ts-ignore - optional dependency, may not be installed
  let nodemailer: typeof import('nodemailer') | null = null;
  try {
    // @ts-ignore
    nodemailer = await import('nodemailer');
  } catch {
    return { ok: false, latencyMs: Date.now() - started, error: 'nodemailer not installed' };
  }

  try {
    const transporter = nodemailer!.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: { user: smtpUser, pass: smtpPass },
      connectionTimeout: TIMEOUT_MS,
      greetingTimeout: TIMEOUT_MS,
    });

    await withTimeout(transporter.verify(), TIMEOUT_MS, 'Email Provider');
    return { ok: true, latencyMs: Date.now() - started };
  } catch (err) {
    return { ok: false, latencyMs: Date.now() - started, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Build the probe map for all known dependencies. */
export function buildDependencyProbes(): Partial<Record<DependencyId, DependencyProbe>> {
  const probes: Partial<Record<DependencyId, DependencyProbe>> = {
    postgres: postgresProbe,
    stellar_horizon: stellarHorizonProbe,
    redis_queue: redisQueueProbe,
  };

  // Only include email provider probe if SMTP is configured
  const smtpHost = process.env.SMTP_HOST;
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  if (smtpHost && smtpUser && smtpPass) {
    probes.email_provider = emailProviderProbe;
  }

  return probes;
}