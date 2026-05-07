/**
 * Grond Orchestration — main entry point.
 *
 * Starts the BullMQ workers and exports the programmatic API.
 */

import "dotenv/config";
import { initTracer } from "./observability/tracer.js";
import { startOsintScanWorker } from "./queue/jobs.js";
import { logger } from "./observability/logger.js";

export { runOsintOrchestrator, type OrchestratorRequest } from "./agents/osint-orchestrator.js";
export { runOpenRouterOsintAgent } from "./agents/openrouter-osint-agent.js";
export { runGrondScan, GrondScanRequest } from "./tools/grond-api.js";
export { enqueueScan, enqueueGraphIndex, enqueueEmbedIndex } from "./queue/jobs.js";
export { indexEvidence, findVulnsForTarget } from "./graph/client.js";

if (import.meta.url === new URL(process.argv[1]!, import.meta.url.replace(/\/[^/]+$/, "/")).href) {
  initTracer();
  const worker = startOsintScanWorker();
  logger.info(
    { orchestrator_backend: process.env["ORCHESTRATOR_BACKEND"] ?? "anthropic" },
    "Grond orchestration workers started",
  );

  const shutdown = async () => {
    logger.info("Shutting down...");
    await worker.close();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}
