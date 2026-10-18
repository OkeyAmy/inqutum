/**
 * Public dependency-aware health endpoint tests.
 *
 * Tests the /api/health/dependencies endpoint which returns per-dependency
 * state (healthy/degraded/down) and overall status without requiring auth.
 */
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import express from 'express';

// Test with a shorter timeout for the probes
const PROBE_TIMEOUT_MS = 1000;

describe('public dependency health endpoint', () => {
  let server: Server;
  let baseUrl: string;

  before(async () => {
    // Set up environment for testing - use invalid endpoints to force failures
    // but with fast timeouts
    process.env.NODE_ENV = 'test';
    process.env.STELLAR_NETWORK = 'TESTNET';
    process.env.STELLAR_HORIZON_URL = 'http://127.0.0.1:1'; // Invalid - will fail fast
    process.env.DATABASE_URL = 'postgresql://test:test@localhost:1/test'; // Invalid port - fail fast
    process.env.REDIS_HOST = '127.0.0.1';
    process.env.REDIS_PORT = '1'; // Invalid - fail fast
    // SMTP not configured - email provider will return unknown

    const { dependencyHealthHandler } = await import('../src/health');

    const app = express();
    app.use(express.json());
    app.get('/api/health/dependencies', dependencyHealthHandler());

    server = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve) => server.once('listening', resolve));
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('returns 503 when all dependencies are down', async () => {
    const res = await fetch(`${baseUrl}/api/health/dependencies`);
    // When overall state is 'down', should return 503
    assert.equal(res.status, 503);

    const body = await res.json() as any;
    assert.equal(body.service, 'Quittance API');
    assert.ok(body.version);
    assert.ok(body.timestamp);
    assert.ok(Array.isArray(body.dependencies));
    assert.equal(body.dependencies.length, 4);

    // postgres, stellar_horizon, redis_queue should be 'down', email_provider 'unknown'
    for (const dep of body.dependencies) {
      assert.ok(['postgres', 'stellar_horizon', 'redis_queue', 'email_provider'].includes(dep.id));
      if (dep.id === 'email_provider') {
        assert.equal(dep.state, 'unknown');
      } else {
        assert.equal(dep.state, 'down');
      }
      assert.ok(typeof dep.retryAfterSeconds === 'number');
    }
  });

  it('response structure matches contract', async () => {
    const res = await fetch(`${baseUrl}/api/health/dependencies`);
    const body = await res.json() as any;

    // Required fields
    assert.ok(body.status);
    assert.ok(body.service);
    assert.ok(body.version);
    assert.ok(body.timestamp);
    assert.ok(Array.isArray(body.dependencies));

    // Each dependency has required fields
    for (const dep of body.dependencies) {
      assert.ok(dep.id);
      assert.ok(dep.name);
      assert.ok(['healthy', 'degraded', 'down', 'unknown'].includes(dep.state));
      assert.ok(typeof dep.latencyMs === 'number' || dep.latencyMs === null);
      assert.ok(dep.error === null || typeof dep.error === 'string');
      assert.ok(typeof dep.retryAfterSeconds === 'number');
    }
  });

  it('overall status reflects worst dependency state', async () => {
    const res = await fetch(`${baseUrl}/api/health/dependencies`);
    const body = await res.json() as any;
    
    // With postgres/stellar/redis down and email unknown, overall should be 'down'
    assert.equal(body.status, 'down');
  });
});