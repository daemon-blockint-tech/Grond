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
import { Textarea } from "@/components/ui/textarea";
import {
  ensureAnalystId,
  formatApiDetail,
  formatGrondReachabilityError,
  getGrondApiBase,
} from "@/lib/grond-api-base";
import { cn } from "@/lib/utils";

export function TavilyExtractCard() {
  const [urls, setUrls] = useState("");
  const [extractDepth, setExtractDepth] = useState<"basic" | "advanced">("advanced");
  const [format, setFormat] = useState<"markdown" | "text">("markdown");
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
    const urlList = urls.split("\n").map((u) => u.trim()).filter(Boolean);
    if (!urlList.length) {
      setError("Enter at least one URL.");
      setLoading(false);
      return;
    }
    try {
      const res = await fetch(`${base}/api/v1/tools/tavily/extract`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: urlList[0],
          urls: urlList,
          analyst_id: analyst,
          session_id: session,
          extract_depth: extractDepth,
          format,
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
  }, [urls, extractDepth, format, session]);

  return (
    <section className="mt-10 space-y-4" aria-labelledby="tavily-extract-tool-heading">
      <h2 id="tavily-extract-tool-heading" className="text-lg font-semibold tracking-tight text-foreground">
        Tavily Extract
      </h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">URL content extraction</CardTitle>
          <CardDescription className="text-pretty">
            Endpoint{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">POST /api/v1/tools/tavily/extract</code>.
            Clean markdown/text from URLs — batch up to 20. Returns extracted Evidence per URL.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-0 p-0">
          <div className="space-y-3 px-6 pb-4 pt-0">
            <div className="space-y-1.5">
              <label htmlFor="tavily-extract-urls" className="text-xs font-medium text-foreground">
                URLs (one per line, max 20)
              </label>
              <Textarea
                id="tavily-extract-urls"
                value={urls}
                onChange={(e) => setUrls(e.target.value)}
                placeholder={"https://example.com\nhttps://example.com/about"}
                className="min-h-[80px] font-mono text-xs"
                autoComplete="off"
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <label htmlFor="tavily-extract-depth" className="text-xs font-medium text-foreground">
                  Extract depth
                </label>
                <select
                  id="tavily-extract-depth"
                  value={extractDepth}
                  onChange={(e) => setExtractDepth(e.target.value as "basic" | "advanced")}
                  className="flex h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 py-1 text-sm shadow-sm dark:border-white/10 dark:bg-zinc-950"
                >
                  <option value="advanced">advanced</option>
                  <option value="basic">basic</option>
                </select>
              </div>
              <div className="space-y-1.5">
                <label htmlFor="tavily-extract-format" className="text-xs font-medium text-foreground">
                  Output format
                </label>
                <select
                  id="tavily-extract-format"
                  value={format}
                  onChange={(e) => setFormat(e.target.value as "markdown" | "text")}
                  className="flex h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 py-1 text-sm shadow-sm dark:border-white/10 dark:bg-zinc-950"
                >
                  <option value="markdown">markdown</option>
                  <option value="text">text</option>
                </select>
              </div>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
              <Button
                type="button"
                onClick={() => void run()}
                disabled={loading || !urls.trim() || !session}
                className="min-h-11 w-full sm:w-auto sm:min-w-[10rem]"
              >
                {loading ? "Extracting…" : "Extract URLs"}
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
                  Extracting content…
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
                  Extracted content appears here after a successful run.
                </p>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
