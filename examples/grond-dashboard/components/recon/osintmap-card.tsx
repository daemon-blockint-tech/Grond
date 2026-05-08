"use client";

import { useCallback, useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  ensureAnalystId,
  formatApiDetail,
  formatGrondReachabilityError,
  getGrondApiBase,
} from "@/lib/grond-api-base";
import { cn } from "@/lib/utils";

export function OsintmapCard() {
  const [regionQuery, setRegionQuery] = useState("");
  const [maxRows, setMaxRows] = useState("8");
  const [session, setSession] = useState("");
  const [loading, setLoading] = useState(false);
  const [output, setOutput] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { setSession(crypto.randomUUID()); }, []);

  const run = useCallback(async () => {
    setLoading(true);
    setError(null);
    setOutput(null);
    const analyst = ensureAnalystId();
    const base = getGrondApiBase();
    try {
      const res = await fetch(`${base}/api/v1/tools/osintmap`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: regionQuery.trim(),
          analyst_id: analyst,
          session_id: session,
          region_query: regionQuery.trim(),
          max_rows: parseInt(maxRows, 10) || 8,
        }),
      });
      const data: unknown = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(formatApiDetail(data, `Request failed (${res.status})`));
        return;
      }
      setOutput(JSON.stringify(data, null, 2));
    } catch (e) {
      setError(formatGrondReachabilityError(e, base));
    } finally {
      setLoading(false);
    }
  }, [regionQuery, maxRows, session]);

  return (
    <section className="mt-10 space-y-4" aria-labelledby="osintmap-tool-heading">
      <h2 id="osintmap-tool-heading" className="text-lg font-semibold tracking-tight text-foreground">
        OSINTMap
      </h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Regional OSINT links</CardTitle>
          <CardDescription className="text-pretty">
            Endpoint{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">POST /api/v1/tools/osintmap</code>.
            Lookup regional entries in cipher387&apos;s worldwide curated public OSINT link table.
            Passive — no API key required.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-0 p-0">
          <div className="space-y-3 px-6 pb-4 pt-0">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <label htmlFor="osintmap-region" className="text-xs font-medium text-foreground">
                  Region / country
                </label>
                <Input
                  id="osintmap-region"
                  value={regionQuery}
                  onChange={(e) => setRegionQuery(e.target.value)}
                  placeholder="e.g. Indonesia, United States"
                  autoComplete="off"
                />
              </div>
              <div className="space-y-1.5">
                <label htmlFor="osintmap-maxrows" className="text-xs font-medium text-foreground">
                  Max rows
                </label>
                <Input
                  id="osintmap-maxrows"
                  type="number"
                  value={maxRows}
                  onChange={(e) => setMaxRows(e.target.value)}
                  min={1}
                  max={50}
                  className="w-32"
                />
              </div>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
              <Button
                type="button"
                onClick={() => void run()}
                disabled={loading || !regionQuery.trim() || !session}
                className="min-h-11 w-full sm:w-auto sm:min-w-[10rem]"
              >
                {loading ? "Searching…" : "Search OSINTMap"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => setSession(crypto.randomUUID())}
                className="min-h-11 w-full sm:w-auto"
              >
                New session id
              </Button>
            </div>
          </div>

          <div className="border-t border-border px-6 pb-6 pt-4 dark:border-white/10">
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Result
            </h3>
            <div
              className={cn(
                "flex min-h-[14rem] flex-col overflow-hidden rounded-xl border border-border bg-zinc-50/80 dark:border-white/10 dark:bg-zinc-950/60",
                error && "border-red-500/40 bg-red-50/50 dark:bg-red-950/25",
              )}
            >
              {loading ? (
                <div className="flex flex-1 items-center justify-center gap-3 px-4 py-8 text-sm text-muted-foreground">
                  <span className="inline-block size-2 animate-pulse rounded-full bg-emerald-500" aria-hidden />
                  Searching OSINT links…
                </div>
              ) : error ? (
                <p className="flex-1 whitespace-pre-wrap p-4 text-sm text-red-900 dark:text-red-100" role="alert">
                  {error}
                </p>
              ) : output ? (
                <pre className="max-h-[min(24rem,55vh)] flex-1 overflow-auto p-4 text-xs leading-relaxed text-zinc-900 dark:text-zinc-100">
                  <code>{output}</code>
                </pre>
              ) : (
                <p className="flex flex-1 items-center justify-center px-4 py-8 text-center text-xs text-muted-foreground">
                  OSINT link results appear here after a successful search.
                </p>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
