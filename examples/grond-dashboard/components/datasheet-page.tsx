"use client";

import {
  ChevronDown,
  Download,
  ExternalLink,
  Loader2,
  Menu,
  Plus,
  Trash2,
  X,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useId, useRef, useState } from "react";

import { AnalystSidebarNav } from "@/components/analyst-sidebar-nav";
import { GrondLogo } from "@/components/grond-logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import {
  ensureAnalystId,
  formatApiDetail,
  formatGrondReachabilityError,
  getGrondApiBase,
} from "@/lib/grond-api-base";
import { cn } from "@/lib/utils";
import {
  loadRecent,
  type RecentItem,
} from "@/lib/recent-investigations";

type SourceLink = {
  title: string;
  url: string;
  snippet: string;
};

type SheetRow = {
  id: string;
  entity: string;
  enrichmentPrompt: string;
  status: "idle" | "loading" | "done" | "error";
  result: string;
  sources: SourceLink[];
  error: string;
};

function newRow(): SheetRow {
  return {
    id: crypto.randomUUID(),
    entity: "",
    enrichmentPrompt: "",
    status: "idle",
    result: "",
    sources: [],
    error: "",
  };
}

function toCsv(rows: SheetRow[]): string {
  const esc = (s: string) => {
    const q = /[",\n\r]/.test(s);
    const t = s.replace(/"/g, '""');
    return q ? `"${t}"` : t;
  };
  const header = "entity,enrichment_prompt,enriched_result,sources";
  const lines = rows.map((r) => {
    const srcs = r.sources
      .map((s) => `${s.title}: ${s.url}`)
      .join("; ");
    return `${esc(r.entity.trim())},${esc(r.enrichmentPrompt.trim())},${esc(r.result.trim())},${esc(srcs)}`;
  });
  return [header, ...lines].join("\n");
}

export function DatasheetPage() {
  const router = useRouter();
  const entityId = useId();
  const promptId = useId();
  const [sheetOpen, setSheetOpen] = useState(false);
  const [recent, setRecent] = useState<RecentItem[]>([]);
  const [rows, setRows] = useState<SheetRow[]>(() => [
    newRow(),
    newRow(),
    newRow(),
    newRow(),
    newRow(),
  ]);
  const [enrichingAll, setEnrichingAll] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    setRecent(loadRecent());
  }, []);

  const handleNewIntel = useCallback(() => {
    router.push("/");
  }, [router]);

  const updateRow = useCallback(
    (id: string, patch: Partial<SheetRow>) => {
      setRows((prev) =>
        prev.map((r) => (r.id === id ? { ...r, ...patch } : r)),
      );
    },
    [],
  );

  const enrichRow = useCallback(
    async (row: SheetRow, signal?: AbortSignal) => {
      const entity = row.entity.trim();
      const prompt = row.enrichmentPrompt.trim();
      if (!entity || !prompt) return;

      updateRow(row.id, { status: "loading", error: "", result: "", sources: [] });

      const analyst = ensureAnalystId();
      const base = getGrondApiBase();
      const session = crypto.randomUUID();

      const query = `${entity} ${prompt}`;

      try {
        const res = await fetch(`${base}/api/v1/tools/tavily`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target: entity,
            query,
            analyst_id: analyst,
            session_id: session,
            search_depth: "advanced",
            max_results: 5,
          }),
          signal,
        });

        const data = await res.json();
        if (!res.ok) {
          updateRow(row.id, {
            status: "error",
            error: formatApiDetail(data, `Failed (${res.status})`),
          });
          return;
        }

        const evidence: Array<{
          value?: { title?: string; url?: string; snippet?: string };
        }> = data.evidence ?? [];

        const sources: SourceLink[] = evidence
          .filter((ev) => ev.value?.url)
          .map((ev) => ({
            title: ev.value?.title ?? "",
            url: ev.value?.url ?? "",
            snippet: ev.value?.snippet ?? "",
          }));

        const resultParts = evidence
          .filter((ev) => ev.value?.snippet)
          .map((ev, i) => {
            const s = ev.value?.snippet ?? "";
            return s.length > 400 ? s.slice(0, 400) + "\u2026" : s;
          });

        const result = resultParts.join("\n\n") || "No relevant results found.";

        updateRow(row.id, { status: "done", result, sources });
      } catch (e: unknown) {
        if (signal?.aborted) {
          updateRow(row.id, { status: "idle" });
          return;
        }
        updateRow(row.id, {
          status: "error",
          error: formatGrondReachabilityError(e, base),
        });
      }
    },
    [updateRow],
  );

  const enrichAll = useCallback(async () => {
    setEnrichingAll(true);
    const ac = new AbortController();
    abortRef.current = ac;

    const pending = rows.filter(
      (r) => r.entity.trim() && r.enrichmentPrompt.trim() && r.status !== "done",
    );

    for (const row of pending) {
      if (ac.signal.aborted) break;
      await enrichRow(row, ac.signal);
    }

    setEnrichingAll(false);
    abortRef.current = null;
  }, [rows, enrichRow]);

  const cancelEnrich = useCallback(() => {
    abortRef.current?.abort();
    setEnrichingAll(false);
  }, []);

  const downloadCsv = useCallback(() => {
    const nonEmpty = rows.some(
      (r) => r.entity.trim() || r.enrichmentPrompt.trim(),
    );
    if (!nonEmpty) return;
    const blob = new Blob([toCsv(rows)], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `grond-enriched-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [rows]);

  const sidebar = (
    <AnalystSidebarNav
      recent={recent}
      onNew={handleNewIntel}
      onSelectRecent={() => {
        router.push("/");
      }}
    />
  );

  const openMobileNav = (
    <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
      <SheetTrigger asChild>
        <Button
          variant="secondary"
          size="icon"
          className="lg:hidden"
          type="button"
          aria-label="Open navigation menu"
        >
          <Menu className="size-5" />
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="w-[min(100%-2rem,20rem)] p-0">
        <SheetHeader className="sr-only">
          <SheetTitle>Navigation</SheetTitle>
        </SheetHeader>
        <AnalystSidebarNav
          recent={recent}
          onNew={() => {
            handleNewIntel();
            setSheetOpen(false);
          }}
          onSelectRecent={() => {
            router.push("/");
            setSheetOpen(false);
          }}
        />
      </SheetContent>
    </Sheet>
  );

  const hasEnrichable = rows.some(
    (r) => r.entity.trim() && r.enrichmentPrompt.trim() && r.status !== "done",
  );
  const hasResults = rows.some((r) => r.status === "done");
  const isLoading = rows.some((r) => r.status === "loading");

  return (
    <div className="flex min-h-screen bg-background">
      <aside
        className="hidden h-svh max-h-svh w-72 shrink-0 overflow-hidden border-r border-zinc-200 bg-white lg:flex lg:flex-col dark:border-white/10 dark:bg-zinc-950"
        aria-label="Workspace"
      >
        {sidebar}
      </aside>

      <div className="flex h-svh max-h-svh min-w-0 flex-1 flex-col overflow-hidden">
        <header className="flex shrink-0 items-center justify-between gap-3 border-b border-border bg-background px-4 py-3 lg:hidden">
          {openMobileNav}
          <div className="flex flex-1 justify-center px-2">
            <GrondLogo className="max-w-[8.5rem] justify-center [&_img]:object-center" />
          </div>
          <ThemeToggle />
        </header>

        <main
          id="main-content"
          className="min-h-0 flex-1 overflow-y-auto overscroll-contain"
          aria-label="Data enrichment"
        >
          <div className="mx-auto max-w-5xl px-4 py-6 sm:px-6 sm:py-10">
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Data enrichment
              </p>
              <h1 className="text-2xl font-semibold tracking-[-0.02em] text-foreground sm:text-3xl">
                Enrich your spreadsheet
              </h1>
              <p className="max-w-2xl text-sm leading-[1.7] text-muted-foreground">
                Add entities and what you want to know about each one. Hit{" "}
                <strong className="font-medium text-foreground">Enrich all</strong>{" "}
                and Grond fills every row with web-sourced intelligence and citations.
                Export the enriched data as CSV.
              </p>
            </div>

            <details className="group mt-4 max-w-2xl rounded-xl border border-white/[0.06] bg-white/[0.02] dark:border-white/[0.06] dark:bg-white/[0.02]">
              <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2.5 text-xs font-medium text-foreground [&::-webkit-details-marker]:hidden">
                <ChevronDown
                  className="size-4 shrink-0 stroke-[1.25] text-muted-foreground opacity-80 transition group-open:rotate-180"
                  aria-hidden
                />
                How it works
              </summary>
              <div className="space-y-2 border-t border-white/[0.06] px-3 pb-3 pt-3 text-xs leading-[1.7] text-muted-foreground">
                <p>
                  Each row sends <code className="rounded bg-muted px-1 py-0.5 text-[0.85em] text-foreground">entity + enrichment prompt</code> as a
                  Tavily advanced search query through the Grond API. The top results are
                  summarized into the <strong className="text-foreground">Result</strong> column with
                  source links preserved as citations.
                </p>
                <p>
                  Powered by{" "}
                  <a
                    href="https://docs.tavily.com/examples/use-cases/data-enrichment"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-0.5 font-medium text-foreground underline decoration-zinc-400 underline-offset-2 hover:decoration-foreground dark:decoration-zinc-500"
                  >
                    Tavily Data Enrichment
                    <ExternalLink className="size-3 opacity-70" aria-hidden />
                  </a>
                  {" "}via{" "}
                  <code className="rounded bg-muted px-1 py-0.5 text-[0.85em] text-foreground">
                    POST /api/v1/tools/tavily
                  </code>
                </p>
              </div>
            </details>

            <div className="mt-8 flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="secondary"
                className="rounded-xl gap-1.5 stroke-[1.25]"
                onClick={() => setRows((r) => [...r, newRow()])}
              >
                <Plus className="size-4" aria-hidden />
                Add row
              </Button>
              <Button
                type="button"
                className="rounded-xl gap-1.5 spring-sm transition-all"
                onClick={() => void enrichAll()}
                disabled={!hasEnrichable || enrichingAll}
              >
                {enrichingAll ? (
                  <>
                    <Loader2 className="size-4 animate-spin" aria-hidden />
                    Enriching\u2026
                  </>
                ) : (
                  "Enrich all"
                )}
              </Button>
              {enrichingAll && (
                <Button
                  type="button"
                  variant="outline"
                  className="rounded-xl gap-1.5"
                  onClick={cancelEnrich}
                >
                  <X className="size-4" aria-hidden />
                  Cancel
                </Button>
              )}
              <Button
                type="button"
                variant="outline"
                className="rounded-xl gap-1.5 stroke-[1.25]"
                onClick={downloadCsv}
                disabled={!hasResults}
              >
                <Download className="size-4" aria-hidden />
                Export CSV
              </Button>
            </div>

            <div className="mt-6 overflow-x-auto rounded-2xl border border-white/[0.06] bg-card dark:bg-zinc-900/40 animate-fade-in">
              <table className="w-full min-w-[52rem] border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-white/[0.06] bg-white/[0.03]">
                    <th
                      scope="col"
                      className="w-[14rem] px-3 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground sm:px-4"
                    >
                      Entity
                    </th>
                    <th
                      scope="col"
                      className="w-[18rem] px-3 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground sm:px-4"
                    >
                      Enrichment prompt
                    </th>
                    <th
                      scope="col"
                      className="px-3 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground sm:px-4"
                    >
                      Enriched result
                    </th>
                    <th
                      scope="col"
                      className="w-[10rem] px-3 py-3 text-xs font-medium uppercase tracking-wider text-muted-foreground sm:px-4"
                    >
                      Sources
                    </th>
                    <th
                      scope="col"
                      className="w-12 px-2 py-3 sm:w-14"
                    >
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row, index) => (
                    <tr
                      key={row.id}
                      className={cn(
                        "border-b border-white/[0.04] last:border-0 transition-colors",
                        row.status === "loading" && "bg-amber-50/30 dark:bg-amber-950/10",
                        row.status === "done" && "bg-emerald-50/20 dark:bg-emerald-950/10",
                        row.status === "error" && "bg-red-50/30 dark:bg-red-950/10",
                      )}
                    >
                      <td className="align-top p-2 sm:p-3">
                        <label htmlFor={`${entityId}-${row.id}`} className="sr-only">
                          Entity row {index + 1}
                        </label>
                        <Input
                          id={`${entityId}-${row.id}`}
                          placeholder="e.g. Tesla, ACME Corp"
                          value={row.entity}
                          onChange={(e) =>
                            updateRow(row.id, { entity: e.target.value })
                          }
                          className="rounded-xl bg-background text-sm dark:bg-zinc-950/80"
                          autoComplete="off"
                          disabled={row.status === "loading"}
                        />
                      </td>
                      <td className="align-top p-2 sm:p-3">
                        <label htmlFor={`${promptId}-${row.id}`} className="sr-only">
                          Prompt row {index + 1}
                        </label>
                        <Textarea
                          id={`${promptId}-${row.id}`}
                          placeholder="e.g. Recent funding or leadership changes"
                          value={row.enrichmentPrompt}
                          onChange={(e) =>
                            updateRow(row.id, {
                              enrichmentPrompt: e.target.value,
                            })
                          }
                          className="min-h-[3rem] rounded-xl bg-background text-sm dark:bg-zinc-950/80"
                          rows={2}
                          disabled={row.status === "loading"}
                        />
                      </td>
                      <td className="align-top p-2 sm:p-3">
                        {row.status === "loading" ? (
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <span className="inline-block size-2 animate-pulse rounded-full bg-amber-500" />
                            Searching\u2026
                          </div>
                        ) : row.status === "error" ? (
                          <p className="text-xs text-red-600 dark:text-red-400 whitespace-pre-wrap">
                            {row.error}
                          </p>
                        ) : row.result ? (
                          <div className="text-xs leading-[1.7] text-foreground/80 whitespace-pre-wrap max-h-[10rem] overflow-y-auto">
                            {row.result}
                          </div>
                        ) : (
                          <p className="text-xs text-muted-foreground/50">
                            Result appears after enrichment
                          </p>
                        )}
                        {row.status === "idle" && !row.result && row.entity.trim() && row.enrichmentPrompt.trim() && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="mt-1 h-7 gap-1 text-xs text-muted-foreground hover:text-foreground"
                            onClick={() => void enrichRow(row)}
                          >
                            Enrich this row
                          </Button>
                        )}
                      </td>
                      <td className="align-top p-2 sm:p-3">
                        {row.sources.length > 0 ? (
                          <div className="flex flex-col gap-1">
                            {row.sources.slice(0, 4).map((src, si) => (
                              <a
                                key={si}
                                href={src.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 truncate rounded-lg border border-white/[0.06] bg-white/[0.03] px-2 py-1 text-[0.7rem] leading-tight text-foreground/70 transition spring-sm hover:bg-white/[0.06] hover:text-foreground"
                              >
                                <ExternalLink className="size-2.5 shrink-0 stroke-[1.5] opacity-60" aria-hidden />
                                <span className="truncate">{src.title || src.url}</span>
                              </a>
                            ))}
                            {row.sources.length > 4 && (
                              <span className="text-[0.65rem] text-muted-foreground">
                                +{row.sources.length - 4} more
                              </span>
                            )}
                          </div>
                        ) : row.status === "done" ? (
                          <span className="text-[0.7rem] text-muted-foreground/40">No sources</span>
                        ) : null}
                      </td>
                      <td className="align-top p-2 text-center sm:p-3">
                        <div className="flex flex-col items-center gap-1">
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="size-8 text-muted-foreground stroke-[1.25] hover:text-destructive"
                            aria-label={`Remove row ${index + 1}`}
                            disabled={rows.length <= 1 || row.status === "loading"}
                            onClick={() =>
                              setRows((prev) =>
                                prev.length <= 1
                                  ? prev
                                  : prev.filter((r) => r.id !== row.id),
                              )
                            }
                          >
                            <Trash2 className="size-3.5" aria-hidden />
                          </Button>
                          {row.status === "done" && (
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon"
                              className="size-8 text-muted-foreground stroke-[1.25] hover:text-foreground"
                              aria-label={`Re-enrich row ${index + 1}`}
                              onClick={() => {
                                updateRow(row.id, { status: "idle", result: "", sources: [] });
                                void enrichRow({ ...row, status: "idle", result: "", sources: [] });
                              }}
                            >
                              <Loader2 className="size-3.5 rotate-0" aria-hidden />
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {isLoading && (
              <div className="mt-4 flex items-center gap-3 rounded-xl border border-amber-200/60 bg-amber-50/50 px-4 py-3 text-xs text-amber-900 dark:border-amber-500/20 dark:bg-amber-950/20 dark:text-amber-100 animate-slide-down">
                <Loader2 className="size-4 animate-spin stroke-[1.25]" aria-hidden />
                Enriching rows sequentially via Tavily advanced search\u2026
              </div>
            )}

            <p className="mt-8 text-xs text-muted-foreground">
              <Link
                href="/"
                className="font-medium text-foreground underline underline-offset-2"
              >
                Back to Intel
              </Link>
              {" \u00b7 "}
              <Link
                href="/recon"
                className="font-medium text-foreground underline underline-offset-2"
              >
                Recon tools
              </Link>
              {" \u00b7 "}
              <Link
                href="/admin"
                className="font-medium text-foreground underline underline-offset-2"
              >
                Admin
              </Link>
            </p>
          </div>
        </main>
      </div>
    </div>
  );
}
