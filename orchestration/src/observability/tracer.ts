/**
 * OpenTelemetry tracing setup for the TypeScript orchestration layer.
 *
 * Each agent tool call and BullMQ job gets its own span, enabling
 * end-to-end trace correlation with the Python FastAPI service.
 */

import { NodeSDK } from "@opentelemetry/sdk-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { getNodeAutoInstrumentations } from "@opentelemetry/auto-instrumentations-node";
import { trace, context, SpanStatusCode, type Tracer } from "@opentelemetry/api";

let _tracer: Tracer | null = null;

export function initTracer(): void {
  const exporter = new OTLPTraceExporter({
    url: process.env["OTEL_EXPORTER_OTLP_ENDPOINT"] ?? "http://localhost:4318/v1/traces",
  });

  const sdk = new NodeSDK({
    traceExporter: exporter,
    instrumentations: [getNodeAutoInstrumentations()],
    serviceName: "grond-orchestration",
  });

  sdk.start();
  _tracer = trace.getTracer("grond-orchestration", "0.1.0");
}

export async function withSpan<T>(
  name: string,
  fn: () => Promise<T>,
  attributes?: Record<string, string | number | boolean>,
): Promise<T> {
  const tracer = _tracer ?? trace.getTracer("grond-orchestration");
  const span = tracer.startSpan(name, attributes !== undefined ? { attributes } : {});

  return context.with(trace.setSpan(context.active(), span), async () => {
    try {
      const result = await fn();
      span.setStatus({ code: SpanStatusCode.OK });
      return result;
    } catch (err) {
      span.setStatus({ code: SpanStatusCode.ERROR, message: String(err) });
      span.recordException(err instanceof Error ? err : new Error(String(err)));
      throw err;
    } finally {
      span.end();
    }
  });
}
