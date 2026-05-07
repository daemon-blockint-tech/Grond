/**
 * Structured logger for the TypeScript orchestration layer.
 * Uses pino for low-overhead JSON logs compatible with Loki / Grafana.
 */

import pino from "pino";

export const logger = pino({
  level: process.env["LOG_LEVEL"] ?? "info",
  base: { service: "grond-orchestration" },
});
