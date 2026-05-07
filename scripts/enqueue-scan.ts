/**
 * Delegates to orchestration/scripts/enqueue-scan.ts so repo-root runs work:
 *   npx tsx scripts/enqueue-scan.ts [--target ...]
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const orchestrationDir = path.resolve(scriptDir, "..", "orchestration");
const childArgs = ["tsx", "scripts/enqueue-scan.ts", ...process.argv.slice(2)];

const result = spawnSync("npx", childArgs, {
  cwd: orchestrationDir,
  stdio: "inherit",
  env: process.env,
});

process.exit(result.status ?? 1);
