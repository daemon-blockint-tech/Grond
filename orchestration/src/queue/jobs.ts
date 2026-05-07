/**
 * BullMQ job producers and worker definitions.
 *
 * Queues:
 *   osint-scan — full orchestrator runs (long-lived, up to 30 min)
 *   report-gen — async report PDF generation
 *   graph-index — background Neo4j indexing after collection
 *   embed-index  — background vector embedding after collection
 */

import { Queue, Worker, type Job } from "bullmq";
import { Redis } from "ioredis";
import { runOsintOrchestrator, type OrchestratorRequest } from "../agents/osint-orchestrator.js";
import { runOpenRouterOsintAgent } from "../agents/openrouter-osint-agent.js";
import { logger } from "../observability/logger.js";

const connection = new Redis(process.env["REDIS_URL"] ?? "redis://localhost:6379", {
  maxRetriesPerRequest: null,
});

function orchestratorBackend(): "anthropic" | "openrouter" {
  const v = (process.env["ORCHESTRATOR_BACKEND"] ?? "anthropic").toLowerCase();
  return v === "openrouter" ? "openrouter" : "anthropic";
}

async function runOrchestratorForJob(req: OrchestratorRequest) {
  if (orchestratorBackend() === "openrouter") {
    return runOpenRouterOsintAgent(req);
  }
  return runOsintOrchestrator(req);
}

// ---------------------------------------------------------------------------
// Queue definitions
// ---------------------------------------------------------------------------

export const osintScanQueue = new Queue<OrchestratorRequest>("osint-scan", {
  connection,
  defaultJobOptions: {
    attempts: 2,
    backoff: { type: "exponential", delay: 5000 },
    removeOnComplete: { age: 86400 },
    removeOnFail: { age: 604800 },
  },
});

export const graphIndexQueue = new Queue<{ session_id: string; evidence_count: number }>(
  "graph-index",
  { connection },
);

export const embedIndexQueue = new Queue<{ session_id: string }>("embed-index", {
  connection,
});

// ---------------------------------------------------------------------------
// Job producers
// ---------------------------------------------------------------------------

export async function enqueueScan(req: OrchestratorRequest): Promise<{ jobId: string }> {
  const job = await osintScanQueue.add("scan", req, {
    jobId: `scan-${req.session_id.replace(/:/g, "_")}`,
  });
  logger.info({ session_id: req.session_id, job_id: job.id }, "scan_enqueued");
  return { jobId: job.id! };
}

export async function enqueueGraphIndex(
  session_id: string,
  evidence_count: number,
): Promise<void> {
  await graphIndexQueue.add("index", { session_id, evidence_count });
}

export async function enqueueEmbedIndex(session_id: string): Promise<void> {
  await embedIndexQueue.add("embed", { session_id });
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

export function startOsintScanWorker(): Worker {
  return new Worker<OrchestratorRequest>(
    "osint-scan",
    async (job: Job<OrchestratorRequest>) => {
      logger.info(
        {
          job_id: job.id,
          session_id: job.data.session_id,
          target: job.data.target,
          backend: orchestratorBackend(),
        },
        "scan_worker_start",
      );

      const report = await runOrchestratorForJob(job.data);

      // Trigger downstream indexing asynchronously
      await enqueueGraphIndex(job.data.session_id, report.total_evidence_items);
      await enqueueEmbedIndex(job.data.session_id);

      logger.info(
        {
          job_id: job.id,
          session_id: job.data.session_id,
          risk: report.overall_risk,
          evidence_count: report.total_evidence_items,
        },
        "scan_worker_complete",
      );

      return report;
    },
    {
      connection,
      concurrency: 4,
    },
  );
}
