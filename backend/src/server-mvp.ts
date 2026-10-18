// MVP in-memory backend. Mirrors server.ts exactly in HTTP surface, route
// order, response envelopes and StoredInvoice shape — the only substantive
// difference is the storage adapter passed to createInvoiceRouter. Both
// servers export startServer(port?) with the same signature so the same
// integration harness (see invoice-payment-loop.test.ts) can drive either.
import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createInvoiceRouter } from './routes/invoice.routes';
import { createAuditRouter } from './routes/audit.routes';
import { createExportRouter } from './routes/export.routes';
import { createNotificationRouter } from './routes/notification.routes';
import { createObservabilityRouter } from './routes/observability.routes';
import memoryInvoiceStorage from './storage/memory-invoice-storage';
import { configuredFrontendOrigins, corsOptions } from './config/runtime';
import { healthHandler, readinessHandler, dependencyHealthHandler } from './health';
import { securityHeaders } from './security/content-safety';
import { correlationMiddleware } from './observability/telemetry';
import { buildUserSafeErrorResponse, classifyError } from './errors/error-taxonomy';

import { validateEnvironment } from './config/env-validator';
import { VERIFICATION_CONTRACT_VERSION } from './services/payment-verification';

// Load environment variables
dotenv.config();

// Validate startup environment and secrets safely
const envCheck = validateEnvironment(process.env, { strict: process.env.NODE_ENV === 'production' });
if (envCheck.issues.length > 0 && process.env.NODE_ENV !== 'test') {
  console.warn(`⚠️ Configuration warnings detected:\n  - ${envCheck.issues.join('\n  - ')}`);
}

const app: Application = express();
const PORT = envCheck.validated.PORT || process.env.PORT || 3001;

// Correlation ID & Latency Tracking
app.use(correlationMiddleware());

// Restrictive security headers on every API response
app.use(securityHeaders());

// Middleware
app.use(cors(corsOptions()));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`${new Date().toISOString()} [${req.correlationId}] - ${req.method} ${req.path}`);
  next();
});

// Root endpoint
app.get('/', (req: Request, res: Response) => {
  res.json({
    name: 'Quittance API (MVP)',
    version: '1.0.0',
    status: 'running',
    mode: memoryInvoiceStorage.mode,
    documentation: '/api/health',
  });
});

// Health check
app.get('/api/health', healthHandler(memoryInvoiceStorage.mode));
app.get('/api/health/dependencies', dependencyHealthHandler());
app.get('/api/ready', readinessHandler(memoryInvoiceStorage.mode));

// Invoice, Audit & Observability routes
app.use('/api', createInvoiceRouter({ storage: memoryInvoiceStorage }));
app.use('/api', createAuditRouter({ storage: memoryInvoiceStorage }));
app.use('/api', createObservabilityRouter({ storage: memoryInvoiceStorage }));
app.use('/api', createNotificationRouter());
app.use('/api', createExportRouter({ storage: memoryInvoiceStorage }));

// Mock Stellar endpoint (MVP only)
app.get('/api/stellar/account', (req: Request, res: Response) => {
  const { publicKey } = req.query;
  res.json({
    success: true,
    data: {
      publicKey: publicKey || 'EXAMPLE',
      balances: [
        { assetCode: 'XLM', balance: '1000.0000000' },
      ],
      sequence: '12345678',
      subentryCount: 0,
    },
    correlationId: req.correlationId,
  });
});

// User-Safe Error handling middleware with taxonomy and correlation tracking
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('Unhandled error:', err);
  const classified = classifyError(err);
  const status = (err as any).code === 'CORS_ORIGIN_DENIED' ? 403 : classified.httpStatus || 500;
  const payload = buildUserSafeErrorResponse(err, req.correlationId);

  res.status(status).json(payload);
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    code: 'NOT_FOUND',
    error: 'Endpoint not found',
    correlationId: req.correlationId,
  });
});

/**
 * Starts the HTTP listener.
 *
 * Exported so integration tests can bind an ephemeral port instead of the
 * configured one, and so importing this module never starts a server.
 */
export function startServer(port: number | string = PORT) {
  return app.listen(port, () => {
    console.log('\n🚀 Quittance Backend (MVP Mode)');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`✅ Server running on port ${port}`);
    console.log(`📍 API: http://localhost:${port}/api`);
    console.log(`🏥 Health: http://localhost:${port}/api/health`);
    console.log(`💾 Storage: In-Memory (No Database)`);
    console.log(`💰 Dynamic Seller: Each user uses their own wallet!`);
    console.log(`🌐 Frontends: ${configuredFrontendOrigins().join(', ') || 'not configured'}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  });
}

// Only listen when this file is the process entry point. Importing it — which
// the integration tests do — must not bind a port.
const entryPoint = process.argv[1] ?? '';
if (/server-mvp(\.[cm]?[jt]s)?$/.test(entryPoint)) {
  startServer();
}

export default app;
