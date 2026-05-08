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

const DATE_RANGES = ["all", "10y", "5y", "1y", "30d", "custom"] as const;

export function EdgarCard() {
  const [entity, setEntity] = useState("");
  const [keywords, setKeywords] = useState("");
  const [singleForms, setSingleForms] = useState("");
  const [dateRange, setDateRange] = useState<(typeof DATE_RANGES)[number]>("5y");
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
      const body: Record<string, unknown> = {
        target: entity.trim(),
        analyst_id: analyst,
        session_id: session,
        entity: entity.trim(),
        keywords: keywords.split(",").map((k) => k.trim()).filter(Boolean),
        date_range_select: dateRange,
        max_results: 25,
      };
      const forms = singleForms.split(",").map((f) => f.trim()).filter(Boolean);
      if (forms.length) body.single_forms = forms;
      const res = await fetch(`${base}/api/v1/tools/edgar`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
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
  }, [entity, keywords, singleForms, dateRange, session]);

  return (
    <section className="mt-10 space-y-4" aria-labelledby="edgar-tool-heading">
      <h2 id="edgar-tool-heading" className="text-lg font-semibold tracking-tight text-foreground">
        SEC EDGAR
      </h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Regulatory filings search</CardTitle>
          <CardDescription className="text-pretty">
            Endpoint{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">POST /api/v1/tools/edgar</code>.
            SEC EDGAR full-text search via Bellingcat{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">edgar-tool</code>. Passive public
            regulatory filings index — no API key required.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-0 p-0">
          <div className="space-y-3 px-6 pb-4 pt-0">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <label htmlFor="edgar-entity" className="text-xs font-medium text-foreground">
                  Entity (company / ticker / CIK)
                </label>
                <Input
                  id="edgar-entity"
                  value={entity}
                  onChange={(e) => setEntity(e.target.value)}
                  placeholder="e.g. Apple or AAPL"
                  autoComplete="off"
                />
              </div>
              <div className="space-y-1.5">
                <label htmlFor="edgar-keywords" className="text-xs font-medium text-foreground">
                  Keywords (comma-separated)
                </label>
                <Input
                  id="edgar-keywords"
                  value={keywords}
                  onChange={(e) => setKeywords(e.target.value)}
                  placeholder="e.g. revenue,cloud"
                  autoComplete="off"
                />
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <label htmlFor="edgar-forms" className="text-xs font-medium text-foreground">
                  Form types (comma-separated, optional)
                </label>
                <Input
                  id="edgar-forms"
                  value={singleForms}
                  onChange={(e) => setSingleForms(e.target.value)}
                  placeholder="e.g. 10-K,8-K"
                  autoComplete="off"
                />
              </div>
              <div className="space-y-1.5">
                <label htmlFor="edgar-range" className="text-xs font-medium text-foreground">
                  Date range
                </label>
                <select
                  id="edgar-range"
                  value={dateRange}
                  onChange={(e) => setDateRange(e.target.value as (typeof DATE_RANGES)[number])}
                  className="flex h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 py-1 text-sm shadow-sm dark:border-white/10 dark:bg-zinc-950"
                >
                  {DATE_RANGES.map((r) => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
              <Button
                type="button"
                onClick={() => void run()}
                disabled={loading || !entity.trim() || !session}
                className="min-h-11 w-full sm:w-auto sm:min-w-[10rem]"
              >
                {loading ? "Searching…" : "Search EDGAR"}
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
                  Searching SEC filings…
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
                  SEC filing results appear here after a successful search.
                </p>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
