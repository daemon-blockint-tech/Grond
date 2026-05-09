"use client";

import {
  CheckCircle2,
  ChevronDown,
  Download,
  ExternalLink,
  Loader2,
  Menu,
  Plus,
  RefreshCw,
  Trash2,
  X,
  Zap,
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
import {
  ensureAnalystId,
  formatApiDetail,
  formatGrondReachabilityError,
  getGrondApiBase,
} from "@/lib/grond-api-base";
import { cn } from "@/lib/utils";
import { loadRecent, type RecentItem } from "@/lib/recent-investigations";

// ─── Types ────────────────────────────────────────────────────────────────────

type Source = { title: string; url: string; snippet: string };

type EnrichRow = {
  id: string;
  entity: string;
  prompt: string;
  status: "idle" | "loading" | "done" | "error";
  result: string;           // cleaned prose summary
  resultItems: string[];    // individual bullet items from snippets
  sources: Source[];
  error: string;
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function newRow(entity = "", prompt = ""): EnrichRow {
  return {
    id: crypto.randomUUID(),
    entity,
    prompt,
    status: "idle",
    result: "",
    resultItems: [],
    sources: [],
    error: "",
  };
}

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

function toCsv(rows: EnrichRow[]): string {
  const esc = (s: string) => {
    const q = /[",\n\r]/.test(s);
    return q ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const header = "entity,prompt,result,sources";
  const lines = rows.map((r) => {
    const srcStr = r.sources.map((s) => `${s.title} (${s.url})`).join("; ");
    return [esc(r.entity), esc(r.prompt), esc(r.result), esc(srcStr)].join(",");
  });
  return [header, ...lines].join("\n");
}

// Parse Tavily snippets into readable bullet items
function parseSnippets(snippets: string[]): { items: string[]; summary: string } {
  const items: string[] = [];
  for (const raw of snippets) {
    // Split on markdown ## headings or double newlines, keep non-empty lines
    const parts = raw
      .split(/\n{2,}|(?=## )/)
      .map((s) => s.replace(/^#+\s+/, "").trim())
      .filter((s) => s.length > 20 && s.length < 600);
    items.push(...parts.slice(0, 3));
    if (items.length >= 6) break;
  }
  const summary = items.slice(0, 3).join(" — ");
  return { items: items.slice(0, 6), summary };
}

// ─── Row Card ────────────────────────────────────────────────────────────────

function RowCard({
  row,
  index,
  totalRows,
  enrichingAll,
  onUpdate,
  onEnrich,
  onDelete,
  onReenrich,
}: {
  row: EnrichRow;
  index: number;
  totalRows: number;
  enrichingAll: boolean;
  onUpdate: (id: string, patch: Partial<EnrichRow>) => void;
  onEnrich: (row: EnrichRow) => void;
  onDelete: (id: string) => void;
  onReenrich: (row: EnrichRow) => void;
}) {
  const entityId = useId();
  const promptId = useId();
  const canEnrich = row.entity.trim() && row.prompt.trim();
  const isActive = row.status === "loading";

  return (
    <div
      className={cn(
        "group relative rounded-2xl border transition-all duration-300 ease-out-expo",
        "animate-fade-in-up",
        row.status === "idle" &&
          "border-white/[0.06] bg-white/[0.02] dark:border-white/[0.06] dark:bg-white/[0.02]",
        row.status === "loading" &&
          "border-amber-300/40 bg-amber-50/20 dark:border-amber-500/20 dark:bg-amber-950/10",
        row.status === "done" &&
          "border-white/[0.08] bg-white dark:border-white/[0.08] dark:bg-white/[0.025]",
        row.status === "error" &&
          "border-red-300/40 bg-red-50/20 dark:border-red-500/20 dark:bg-red-950/10",
      )}
    >
      {/* Loading shimmer bar */}
      {isActive && (
        <div className="absolute inset-x-0 top-0 h-[2px] overflow-hidden rounded-t-2xl">
          <div className="shimmer-bg h-full w-full" />
        </div>
      )}

      {/* Card header — row number + status + actions */}
      <div className="flex items-center justify-between gap-3 border-b border-white/[0.05] px-4 py-2.5">
        <div className="flex items-center gap-2.5">
          <span className="flex size-5 shrink-0 items-center justify-center rounded-md border border-white/[0.08] bg-white/[0.04] text-[0.6rem] font-semibold tabular-nums text-muted-foreground">
            {index + 1}
          </span>
          {row.status === "loading" && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-300/40 bg-amber-50 px-2 py-0.5 text-[0.65rem] font-medium text-amber-700 dark:border-amber-500/20 dark:bg-amber-950/40 dark:text-amber-300 animate-fade-in">
              <span className="size-1.5 animate-pulse rounded-full bg-amber-500" />
              Enriching
            </span>
          )}
          {row.status === "done" && (
            <span className="inline-flex items-center gap-1 rounded-full border border-emerald-300/40 bg-emerald-50 px-2 py-0.5 text-[0.65rem] font-medium text-emerald-700 dark:border-emerald-500/20 dark:bg-emerald-950/40 dark:text-emerald-300 animate-fade-in">
              <CheckCircle2 className="size-2.5 stroke-[2]" aria-hidden />
              Enriched
            </span>
          )}
          {row.status === "error" && (
            <span className="inline-flex items-center gap-1 rounded-full border border-red-300/40 bg-red-50 px-2 py-0.5 text-[0.65rem] font-medium text-red-700 dark:border-red-500/20 dark:bg-red-950/40 dark:text-red-300 animate-fade-in">
              Error
            </span>
          )}
        </div>

        <div className="flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
          {row.status === "done" && (
            <button
              type="button"
              onClick={() => onReenrich(row)}
              className="flex size-7 items-center justify-center rounded-lg text-muted-foreground transition spring-sm hover:bg-white/[0.06] hover:text-foreground"
              aria-label={`Re-enrich row ${index + 1}`}
              title="Re-enrich"
            >
              <RefreshCw className="size-3.5 stroke-[1.5]" aria-hidden />
            </button>
          )}
          {row.status === "idle" && canEnrich && !enrichingAll && (
            <button
              type="button"
              onClick={() => onEnrich(row)}
              className="flex h-7 items-center gap-1 rounded-lg px-2 text-[0.65rem] font-medium text-muted-foreground transition spring-sm hover:bg-white/[0.06] hover:text-foreground"
              aria-label={`Enrich row ${index + 1}`}
            >
              <Zap className="size-3 stroke-[1.5]" aria-hidden />
              Enrich
            </button>
          )}
          <button
            type="button"
            onClick={() => onDelete(row.id)}
            disabled={totalRows <= 1 || isActive}
            className="flex size-7 items-center justify-center rounded-lg text-muted-foreground transition spring-sm hover:bg-red-50 hover:text-red-600 disabled:pointer-events-none disabled:opacity-30 dark:hover:bg-red-950/30 dark:hover:text-red-400"
            aria-label={`Remove row ${index + 1}`}
            title="Remove"
          >
            <Trash2 className="size-3.5 stroke-[1.5]" aria-hidden />
          </button>
        </div>
      </div>

      {/* Input area — entity + prompt side by side */}
      <div className="grid gap-3 p-4 sm:grid-cols-[1fr_2fr]">
        <div className="space-y-1.5">
          <label
            htmlFor={entityId}
            className="block text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground"
          >
            Entity
          </label>
          <Input
            id={entityId}
            value={row.entity}
            onChange={(e) => onUpdate(row.id, { entity: e.target.value })}
            placeholder="e.g. Tesla, Stripe, OpenAI"
            className="h-9 rounded-xl border-white/[0.08] bg-background/60 text-sm dark:bg-zinc-950/60"
            autoComplete="off"
            disabled={isActive}
          />
        </div>
        <div className="space-y-1.5">
          <label
            htmlFor={promptId}
            className="block text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground"
          >
            What to enrich
          </label>
          <Input
            id={promptId}
            value={row.prompt}
            onChange={(e) => onUpdate(row.id, { prompt: e.target.value })}
            placeholder="e.g. Latest funding round and valuation"
            className="h-9 rounded-xl border-white/[0.08] bg-background/60 text-sm dark:bg-zinc-950/60"
            autoComplete="off"
            disabled={isActive}
          />
        </div>
      </div>

      {/* Result area */}
      {(row.status !== "idle" || row.result) && (
        <div className="border-t border-white/[0.05] px-4 pb-4 pt-3">
          {row.status === "loading" && (
            <div className="flex items-center gap-2.5 py-3 text-xs text-muted-foreground animate-fade-in">
              <Loader2 className="size-4 shrink-0 animate-spin stroke-[1.5] text-amber-500" />
              <span>Searching the web for <strong className="text-foreground">{row.entity}</strong>&thinsp;—&thinsp;{row.prompt.length > 60 ? row.prompt.slice(0, 60) + "…" : row.prompt}</span>
            </div>
          )}

          {row.status === "error" && (
            <p className="py-2 text-xs leading-[1.7] text-red-600 dark:text-red-400">
              {row.error}
            </p>
          )}

          {row.status === "done" && row.resultItems.length > 0 && (
            <div className="animate-fade-in-up space-y-3">
              {/* Bullet findings */}
              <ul className="space-y-2">
                {row.resultItems.map((item, i) => (
                  <li
                    key={i}
                    className={cn(
                      "flex gap-2.5 text-[0.8rem] leading-[1.65] text-foreground/80",
                      `stagger-${Math.min(i + 1, 6) as 1 | 2 | 3 | 4 | 5 | 6}`,
                      "animate-fade-in-up",
                    )}
                  >
                    <span className="mt-[0.45em] size-1.5 shrink-0 rounded-full bg-foreground/20" aria-hidden />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>

              {/* Source chips */}
              {row.sources.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  <span className="self-center text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground/60 mr-0.5">
                    Sources
                  </span>
                  {row.sources.map((src, si) => (
                    <a
                      key={si}
                      href={src.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      title={src.title || src.url}
                      className={cn(
                        "inline-flex items-center gap-1 rounded-md border border-white/[0.08] bg-white/[0.03] px-2 py-0.5",
                        "text-[0.65rem] font-medium text-muted-foreground",
                        "transition spring-sm hover:border-white/[0.14] hover:bg-white/[0.07] hover:text-foreground",
                        `stagger-${Math.min(si + 1, 6) as 1 | 2 | 3 | 4 | 5 | 6}`,
                        "animate-fade-in",
                      )}
                    >
                      <span>{extractDomain(src.url)}</span>
                      <ExternalLink className="size-2.5 shrink-0 stroke-[1.5] opacity-50" aria-hidden />
                    </a>
                  ))}
                </div>
              )}
            </div>
          )}

          {row.status === "done" && row.resultItems.length === 0 && (
            <p className="py-2 text-xs text-muted-foreground">
              No relevant results found for this query.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

const SEED_ROWS: [string, string][] = [
  ["Tesla", "Latest product launches and delivery numbers"],
  ["Stripe", "Recent funding round or valuation changes"],
  ["Anthropic", "Key partnerships or enterprise customer news"],
];

export function DatasheetPage() {
  const router = useRouter();
  const [navOpen, setNavOpen] = useState(false);
  const [recent, setRecent] = useState<RecentItem[]>([]);
  const [rows, setRows] = useState<EnrichRow[]>(() =>
    SEED_ROWS.map(([e, p]) => newRow(e, p)),
  );
  const [enrichingAll, setEnrichingAll] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // Track progress
  const doneCount = rows.filter((r) => r.status === "done").length;
  const loadingCount = rows.filter((r) => r.status === "loading").length;
  const enrichableCount = rows.filter(
    (r) => r.entity.trim() && r.prompt.trim() && r.status !== "done",
  ).length;
  const hasResults = doneCount > 0;
  const totalFilled = rows.filter((r) => r.entity.trim() && r.prompt.trim()).length;

  useEffect(() => {
    setRecent(loadRecent());
  }, []);

  const updateRow = useCallback((id: string, patch: Partial<EnrichRow>) => {
    setRows((prev) => prev.map((r) => (r.id === id ? { ...r, ...patch } : r)));
  }, []);

  const enrichRow = useCallback(
    async (row: EnrichRow, signal?: AbortSignal) => {
      const entity = row.entity.trim();
      const prompt = row.prompt.trim();
      if (!entity || !prompt) return;

      updateRow(row.id, {
        status: "loading",
        error: "",
        result: "",
        resultItems: [],
        sources: [],
      });

      const analyst = ensureAnalystId();
      const base = getGrondApiBase();

      try {
        const res = await fetch(`${base}/api/v1/tools/tavily`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target: entity,
            query: `${entity} ${prompt}`,
            analyst_id: analyst,
            session_id: crypto.randomUUID(),
            search_depth: "advanced",
            max_results: 5,
          }),
          signal,
        });

        const data: {
          evidence?: Array<{
            value?: { title?: string; url?: string; snippet?: string };
          }>;
          error?: string;
        } = await res.json();

        if (!res.ok) {
          updateRow(row.id, {
            status: "error",
            error: formatApiDetail(data, `Failed (${res.status})`),
          });
          return;
        }

        const evidence = data.evidence ?? [];

        const sources: Source[] = evidence
          .filter((ev) => ev.value?.url)
          .map((ev) => ({
            title: ev.value?.title ?? "",
            url: ev.value?.url ?? "",
            snippet: ev.value?.snippet ?? "",
          }));

        const snippets = evidence
          .map((ev) => ev.value?.snippet ?? "")
          .filter(Boolean);

        const { items, summary } = parseSnippets(snippets);

        updateRow(row.id, {
          status: "done",
          result: summary,
          resultItems: items,
          sources,
        });
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

    // snapshot so we don't re-read state mid-loop
    const pending = rows.filter(
      (r) => r.entity.trim() && r.prompt.trim() && r.status !== "done",
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

  const handleReenrich = useCallback(
    (row: EnrichRow) => {
      const reset: EnrichRow = {
        ...row,
        status: "idle",
        result: "",
        resultItems: [],
        sources: [],
        error: "",
      };
      updateRow(row.id, reset);
      void enrichRow(reset);
    },
    [updateRow, enrichRow],
  );

  const downloadCsv = useCallback(() => {
    if (!hasResults) return;
    const blob = new Blob([toCsv(rows)], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `grond-enriched-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [rows, hasResults]);

  const sidebar = (
    <AnalystSidebarNav
      recent={recent}
      onNew={() => router.push("/")}
      onSelectRecent={() => router.push("/")}
    />
  );

  return (
    <div className="flex min-h-screen bg-background">
      {/* Sidebar */}
      <aside
        className="hidden h-svh max-h-svh w-72 shrink-0 overflow-hidden border-r border-zinc-200 bg-white lg:flex lg:flex-col dark:border-white/10 dark:bg-zinc-950"
        aria-label="Workspace"
      >
        {sidebar}
      </aside>

      <div className="flex h-svh max-h-svh min-w-0 flex-1 flex-col overflow-hidden">
        {/* Mobile header */}
        <header className="flex shrink-0 items-center justify-between gap-3 border-b border-border bg-background px-4 py-3 lg:hidden">
          <Sheet open={navOpen} onOpenChange={setNavOpen}>
            <SheetTrigger asChild>
              <Button variant="secondary" size="icon" type="button" aria-label="Open navigation">
                <Menu className="size-5" />
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-[min(100%-2rem,20rem)] p-0">
              <SheetHeader className="sr-only">
                <SheetTitle>Navigation</SheetTitle>
              </SheetHeader>
              <AnalystSidebarNav
                recent={recent}
                onNew={() => { router.push("/"); setNavOpen(false); }}
                onSelectRecent={() => { router.push("/"); setNavOpen(false); }}
              />
            </SheetContent>
          </Sheet>
          <div className="flex flex-1 justify-center px-2">
            <GrondLogo className="max-w-[8.5rem] justify-center [&_img]:object-center" />
          </div>
          <ThemeToggle />
        </header>

        {/* Main */}
        <main className="min-h-0 flex-1 overflow-y-auto overscroll-contain" aria-label="Data enrichment">
          <div className="mx-auto max-w-3xl px-4 py-8 sm:px-6 sm:py-12">

            {/* Page header */}
            <div className="space-y-2 animate-fade-in-up">
              <p className="text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                Data enrichment
              </p>
              <h1 className="text-2xl font-semibold tracking-[-0.02em] text-foreground sm:text-[1.75rem]">
                Enrich your dataset
              </h1>
              <p className="max-w-xl text-[0.85rem] leading-[1.7] text-muted-foreground">
                Add entities and what you want to know — Grond searches the web and fills each row with sourced intelligence.
              </p>
            </div>

            {/* Toolbar */}
            <div className="mt-7 flex flex-wrap items-center gap-2 animate-fade-in-up stagger-1">
              <Button
                type="button"
                onClick={() => void enrichAll()}
                disabled={enrichableCount === 0 || enrichingAll}
                className="gap-2 rounded-xl"
              >
                {enrichingAll ? (
                  <>
                    <Loader2 className="size-4 animate-spin stroke-[1.5]" />
                    Enriching {loadingCount > 0 ? `row ${doneCount + 1} of ${totalFilled}` : "…"}
                  </>
                ) : (
                  <>
                    <Zap className="size-4 stroke-[1.5]" />
                    Enrich all{enrichableCount > 0 ? ` (${enrichableCount})` : ""}
                  </>
                )}
              </Button>

              {enrichingAll && (
                <Button
                  type="button"
                  variant="outline"
                  onClick={cancelEnrich}
                  className="gap-2 rounded-xl"
                >
                  <X className="size-4 stroke-[1.5]" />
                  Cancel
                </Button>
              )}

              <Button
                type="button"
                variant="secondary"
                onClick={() => setRows((r) => [...r, newRow()])}
                className="gap-2 rounded-xl"
              >
                <Plus className="size-4 stroke-[1.5]" />
                Add row
              </Button>

              <Button
                type="button"
                variant="outline"
                onClick={downloadCsv}
                disabled={!hasResults}
                className="gap-2 rounded-xl"
              >
                <Download className="size-4 stroke-[1.5]" />
                Export CSV
              </Button>

              {/* Progress indicator */}
              {totalFilled > 0 && (
                <span className="ml-auto text-[0.7rem] tabular-nums text-muted-foreground">
                  {doneCount}/{totalFilled} enriched
                </span>
              )}
            </div>

            {/* Progress bar */}
            {enrichingAll && totalFilled > 0 && (
              <div className="mt-3 h-[3px] w-full overflow-hidden rounded-full bg-white/[0.06] animate-slide-down">
                <div
                  className="h-full rounded-full bg-primary transition-all duration-700 ease-out-expo"
                  style={{ width: `${Math.round((doneCount / totalFilled) * 100)}%` }}
                />
              </div>
            )}

            {/* How it works */}
            <details className="group mt-5 rounded-xl border border-white/[0.06] animate-fade-in-up stagger-2">
              <summary className="flex cursor-pointer list-none items-center gap-2 px-3.5 py-2.5 text-[0.72rem] font-medium text-muted-foreground [&::-webkit-details-marker]:hidden hover:text-foreground transition">
                <ChevronDown className="size-3.5 shrink-0 stroke-[1.5] transition-transform group-open:rotate-180" aria-hidden />
                How it works
              </summary>
              <div className="border-t border-white/[0.06] px-3.5 pb-3.5 pt-3 text-[0.75rem] leading-[1.75] text-muted-foreground space-y-1.5">
                <p>Each row sends <strong className="text-foreground">entity + prompt</strong> as a Tavily advanced search query via <code className="rounded bg-muted px-1 py-0.5 text-foreground">POST /api/v1/tools/tavily</code>. Results are extracted into readable bullet points with source citations.</p>
                <p>Rows are enriched sequentially to respect API rate limits. Use <strong className="text-foreground">Enrich all</strong> to process the full dataset, or click the ⚡ icon on any individual row.</p>
              </div>
            </details>

            {/* Row cards */}
            <div className="mt-6 space-y-3">
              {rows.map((row, i) => (
                <RowCard
                  key={row.id}
                  row={row}
                  index={i}
                  totalRows={rows.length}
                  enrichingAll={enrichingAll}
                  onUpdate={updateRow}
                  onEnrich={(r) => void enrichRow(r)}
                  onDelete={(id) =>
                    setRows((prev) =>
                      prev.length <= 1 ? prev : prev.filter((r) => r.id !== id),
                    )
                  }
                  onReenrich={handleReenrich}
                />
              ))}
            </div>

            {/* Add row inline CTA */}
            <button
              type="button"
              onClick={() => setRows((r) => [...r, newRow()])}
              className="mt-3 flex w-full items-center justify-center gap-2 rounded-2xl border border-dashed border-white/[0.08] py-3 text-[0.75rem] text-muted-foreground transition spring-sm hover:border-white/[0.16] hover:text-foreground"
            >
              <Plus className="size-3.5 stroke-[1.5]" aria-hidden />
              Add another row
            </button>

            {/* Footer nav */}
            <p className="mt-10 text-[0.72rem] text-muted-foreground">
              <Link href="/" className="font-medium text-foreground underline underline-offset-2">Intel</Link>
              {" · "}
              <Link href="/recon" className="font-medium text-foreground underline underline-offset-2">Recon</Link>
              {" · "}
              <Link href="/admin" className="font-medium text-foreground underline underline-offset-2">Admin</Link>
            </p>
          </div>
        </main>
      </div>
    </div>
  );
}
