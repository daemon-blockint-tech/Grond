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

export function TavilySearchCard() {
  const [query, setQuery] = useState("");
  const [searchDepth, setSearchDepth] = useState<"basic" | "advanced">("advanced");
  const [topic, setTopic] = useState<"general" | "news" | "finance" | "">("");
  const [timeRange, setTimeRange] = useState<"day" | "week" | "month" | "year" | "">("");
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
        target: query.trim(),
        query: query.trim(),
        analyst_id: analyst,
        session_id: session,
        search_depth: searchDepth,
      };
      if (topic) body.topic = topic;
      if (timeRange) body.time_range = timeRange;
      const res = await fetch(`${base}/api/v1/tools/tavily`, {
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
  }, [query, searchDepth, topic, timeRange, session]);

  return (
    <section className="mt-10 space-y-4" aria-labelledby="tavily-search-tool-heading">
      <h2 id="tavily-search-tool-heading" className="text-lg font-semibold tracking-tight text-foreground">
        Tavily Search
      </h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Web intelligence search</CardTitle>
          <CardDescription className="text-pretty">
            Endpoint{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">POST /api/v1/tools/tavily</code>.
            Direct Tavily web intelligence — returns search-result snippets as Evidence.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-0 p-0">
          <div className="space-y-3 px-6 pb-4 pt-0">
            <div className="space-y-1.5">
              <label htmlFor="tavily-search-query" className="text-xs font-medium text-foreground">
                Query
              </label>
              <Input
                id="tavily-search-query"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="e.g. example.com security breach"
                autoComplete="off"
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1.5">
                <label htmlFor="tavily-search-depth" className="text-xs font-medium text-foreground">
                  Search depth
                </label>
                <select
                  id="tavily-search-depth"
                  value={searchDepth}
                  onChange={(e) => setSearchDepth(e.target.value as "basic" | "advanced")}
                  className="flex h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 py-1 text-sm shadow-sm dark:border-white/10 dark:bg-zinc-950"
                >
                  <option value="advanced">advanced</option>
                  <option value="basic">basic</option>
                </select>
              </div>
              <div className="space-y-1.5">
                <label htmlFor="tavily-search-topic" className="text-xs font-medium text-foreground">
                  Topic
                </label>
                <select
                  id="tavily-search-topic"
                  value={topic}
                  onChange={(e) => setTopic(e.target.value as typeof topic)}
                  className="flex h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 py-1 text-sm shadow-sm dark:border-white/10 dark:bg-zinc-950"
                >
                  <option value="">auto</option>
                  <option value="general">general</option>
                  <option value="news">news</option>
                  <option value="finance">finance</option>
                </select>
              </div>
              <div className="space-y-1.5">
                <label htmlFor="tavily-search-range" className="text-xs font-medium text-foreground">
                  Time range
                </label>
                <select
                  id="tavily-search-range"
                  value={timeRange}
                  onChange={(e) => setTimeRange(e.target.value as typeof timeRange)}
                  className="flex h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 py-1 text-sm shadow-sm dark:border-white/10 dark:bg-zinc-950"
                >
                  <option value="">all</option>
                  <option value="day">day</option>
                  <option value="week">week</option>
                  <option value="month">month</option>
                  <option value="year">year</option>
                </select>
              </div>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
              <Button
                type="button"
                onClick={() => void run()}
                disabled={loading || !query.trim() || !session}
                className="min-h-11 w-full sm:w-auto sm:min-w-[10rem]"
              >
                {loading ? "Searching…" : "Search Tavily"}
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
                  Searching…
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
                  Tavily search results appear here after a successful run.
                </p>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
