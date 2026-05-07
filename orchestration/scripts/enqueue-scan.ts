/**
 * Enqueue one osint-scan job (BullMQ). Requires Redis and a running worker (`npm run dev`).
 *
 *   cd orchestration && npx tsx scripts/enqueue-scan.ts
 *   cd orchestration && npx tsx scripts/enqueue-scan.ts --target example.com --goal "Company OSINT"
 *
 * Env: REDIS_URL, ANTHROPIC_API_KEY (for worker), GROND_API_URL (worker → Python API).
 */
import "dotenv/config";
import { randomUUID } from "node:crypto";
import { parseArgs } from "node:util";

import { enqueueScan } from "../src/queue/jobs.js";

async function main() {
  const { values } = parseArgs({
    options: {
      target: { type: "string", default: "example.com" },
      goal: { type: "string", default: "Passive OSINT: public footprint" },
      analyst: { type: "string", default: "cli-user" },
      session: { type: "string", default: "" },
      active: { type: "boolean", default: false },
    },
  });

  const session_id = values.session && values.session.length > 0 ? values.session : randomUUID();
  const { jobId } = await enqueueScan({
    target: values.target ?? "example.com",
    goal: values.goal ?? "",
    analyst_id: values.analyst ?? "cli-user",
    session_id,
    allow_active_scan: values.active,
  });

  console.log(JSON.stringify({ jobId, session_id }, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
