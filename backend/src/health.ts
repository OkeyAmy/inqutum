import type { Request, Response } from 'express';
import { deploymentReadiness, simulationAllowed } from './config/runtime';
import { STELLAR_NETWORK } from './config/stellar';
import { featureFlagSnapshot } from './config/feature-flags';
import { runDependencyChecks, type DegradationReport, type DependencyState } from './ops/dependency-degradation';
import { buildDependencyProbes } from './health-probes';

export function healthPayload(storage: string) {
  return {
    status: 'ok',
    service: 'Quittance API',
    version: '1.0.0',
    storage,
    network: STELLAR_NETWORK,
    simulationEnabled: simulationAllowed(),
    features: featureFlagSnapshot(),
    timestamp: new Date().toISOString(),
  };
}

export function healthHandler(storage: string) {
  return (_req: Request, res: Response) => res.status(200).json(healthPayload(storage));
}

export function readinessHandler(storage: string) {
  return (_req: Request, res: Response) => {
    const readiness = deploymentReadiness();
    res.status(readiness.ready ? 200 : 503).json({
      status: readiness.ready ? 'ready' : 'not_ready',
      service: 'Quittance API',
      storage,
      ...readiness,
      timestamp: new Date().toISOString(),
    });
  };
}

/** Public dependency-aware health status (no auth required). */
export function dependencyHealthHandler() {
  return async (_req: Request, res: Response) => {
    try {
      const probes = buildDependencyProbes();
      const report = await runDependencyChecks(probes, { timeoutMs: 5000 });

      // Sanitize response for public consumption (no internal runbook URLs, no affectedCapabilities details)
      const sanitizedDeps = report.dependencies.map((d) => ({
        id: d.id,
        name: d.name,
        state: d.state,
        latencyMs: d.latencyMs,
        error: d.error,
        retryAfterSeconds: d.retryAfterSeconds,
      }));

      const response = {
        status: report.overall,
        service: 'Quittance API',
        version: '1.0.0',
        timestamp: report.generatedAt,
        dependencies: sanitizedDeps,
      };

      // Map overall state to HTTP status:
      // - healthy: 200
      // - degraded: 200 (service operational but with degraded deps)
      // - down: 503 (critical dependency down)
      // - unknown: 200 (no probes configured, but service running)
      const httpStatus = report.overall === 'down' ? 503 : 200;

      res.status(httpStatus).json(response);
    } catch (err) {
      // Never fail the health endpoint itself — return degraded status
      res.status(503).json({
        status: 'down',
        service: 'Quittance API',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        dependencies: [],
        error: 'Health check failed',
      });
    }
  };
}
