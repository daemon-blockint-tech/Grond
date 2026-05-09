"use client";

import {
  CheckCircle2,
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
import { useCallback, useEffect, useRef, useState } from "react";

import { AnalystSidebarNav } from "@/components/analyst-sidebar-nav";
import { GrondLogo } from "@/components/grond-logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
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
  result: string;
  resultItems: string[];
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
  // Wrap field in quotes and escape internal quotes — RFC 4180
  const esc = (s: string) => `"${s.replace(/"/g, '""')}"`;

  const header = [esc("entity"), esc("prompt"), esc("result"), esc("sources")].join(",");

  const lines = rows.map((r) => {
    // Join bullet items with a line break inside the quoted cell
    const resultStr = r.resultItems.length > 0
      ? r.resultItems.join("\n")
      : r.result;

    // Each source on its own line inside the quoted cell
    const srcStr = r.sources
      .map((s) => `${s.title} — ${s.url}`)
      .join("\n");

    return [esc(r.entity), esc(r.prompt), esc(resultStr), esc(srcStr)].join(",");
  });

  // UTF-8 BOM so Excel opens correctly without garbled characters
  return "\uFEFF" + [header, ...lines].join("\r\n");
}

function parseSnippets(snippets: string[]): { items: string[]; summary: string } {
  const items: string[] = [];
  for (const raw of snippets) {
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

// ─── Column widths (px) ───────────────────────────────────────────────────────

const COL_CHECK  = 36;
const COL_NUM    = 32;
const COL_ENTITY = 180;
const COL_PROMPT = 220;
const COL_STATUS = 90;

// ─── Inline editable cell ────────────────────────────────────────────────────

function EditableCell({
  value,
  onChange,
  placeholder,
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  disabled?: boolean;
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      disabled={disabled}
      spellCheck={false}
      autoComplete="off"
      className={cn(
        "w-full bg-transparent px-2.5 py-0 text-[0.8rem] text-foreground outline-none",
        "placeholder:text-muted-foreground/40",
        "disabled:opacity-50 disabled:cursor-not-allowed",
        "focus:bg-primary/[0.04]",
      )}
    />
  );
}

// ─── Sheet Row ───────────────────────────────────────────────────────────────

function SheetRow({
  row,
  index,
  totalRows,
  selected,
  enriching,
  onToggleSelect,
  onUpdate,
  onEnrich,
  onDelete,
  onReenrich,
}: {
  row: EnrichRow;
  index: number;
  totalRows: number;
  selected: boolean;
  enriching: boolean;
  onToggleSelect: (id: string) => void;
  onUpdate: (id: string, patch: Partial<EnrichRow>) => void;
  onEnrich: (row: EnrichRow) => void;
  onDelete: (id: string) => void;
  onReenrich: (row: EnrichRow) => void;
}) {
  const isLoading = row.status === "loading";
  const canEnrich = row.entity.trim() && row.prompt.trim();

  const rowBg = {
    idle:    "",
    loading: "bg-amber-500/[0.04]",
    done:    "bg-emerald-500/[0.03]",
    error:   "bg-red-500/[0.04]",
  }[row.status];

  return (
    <>
      {/* ── main data row ── */}
      <tr
        className={cn(
          "group border-b border-border/50 transition-colors",
          rowBg,
          selected ? "bg-primary/[0.04]" : "hover:bg-muted/30",
        )}
      >
        {/* Checkbox */}
        <td
          style={{ width: COL_CHECK, minWidth: COL_CHECK }}
          className="border-r border-border/50 text-center"
        >
          <input
            type="checkbox"
            checked={selected}
            onChange={() => onToggleSelect(row.id)}
            aria-label={`Select row ${index + 1}`}
            className="size-3.5 cursor-pointer accent-primary"
          />
        </td>

        {/* # */}
        <td
          style={{ width: COL_NUM, minWidth: COL_NUM }}
          className="border-r border-border/50 text-center text-[0.68rem] tabular-nums text-muted-foreground/40 select-none"
        >
          {index + 1}
        </td>

        {/* Entity */}
        <td
          style={{ width: COL_ENTITY, minWidth: COL_ENTITY }}
          className="border-r border-border/50 py-0"
        >
          <EditableCell
            value={row.entity}
            onChange={(v) => onUpdate(row.id, { entity: v })}
            placeholder="Entity…"
            disabled={isLoading}
          />
        </td>

        {/* Prompt */}
        <td
          style={{ width: COL_PROMPT, minWidth: COL_PROMPT }}
          className="border-r border-border/50 py-0"
        >
          <EditableCell
            value={row.prompt}
            onChange={(v) => onUpdate(row.id, { prompt: v })}
            placeholder="What to find out…"
            disabled={isLoading}
          />
        </td>

        {/* Status */}
        <td
          style={{ width: COL_STATUS, minWidth: COL_STATUS }}
          className="border-r border-border/50 px-2 text-center"
        >
          {row.status === "idle" && (
            <span className="text-[0.65rem] text-muted-foreground/40">—</span>
          )}
          {row.status === "loading" && (
            <span className="inline-flex items-center gap-1 rounded-full border border-amber-400/40 bg-amber-50 px-1.5 py-0.5 text-[0.6rem] font-medium text-amber-700 dark:border-amber-500/30 dark:bg-amber-950/40 dark:text-amber-300">
              <Loader2 className="size-2.5 animate-spin stroke-[2]" aria-hidden />
              Loading
            </span>
          )}
          {row.status === "done" && (
            <span className="inline-flex items-center gap-1 rounded-full border border-emerald-400/40 bg-emerald-50 px-1.5 py-0.5 text-[0.6rem] font-medium text-emerald-700 dark:border-emerald-500/30 dark:bg-emerald-950/40 dark:text-emerald-300">
              <CheckCircle2 className="size-2.5 stroke-[2]" aria-hidden />
              Done
            </span>
          )}
          {row.status === "error" && (
            <span className="inline-flex items-center gap-1 rounded-full border border-red-400/40 bg-red-50 px-1.5 py-0.5 text-[0.6rem] font-medium text-red-700 dark:border-red-500/30 dark:bg-red-950/40 dark:text-red-300">
              Error
            </span>
          )}
        </td>

        {/* Result */}
        <td className="min-w-0 border-r border-border/50 px-2.5 py-1.5">
          {row.status === "idle" && (
            <span className="text-[0.75rem] text-muted-foreground/30">
              {canEnrich ? "Ready to enrich" : "Fill entity & prompt"}
            </span>
          )}
          {row.status === "loading" && (
            <span className="animate-pulse text-[0.75rem] text-muted-foreground/50">
              Searching the web for <strong className="text-foreground">{row.entity}</strong>…
            </span>
          )}
          {row.status === "error" && (
            <span className="text-[0.75rem] text-red-500">{row.error}</span>
          )}
          {row.status === "done" && row.resultItems.length > 0 && (
            <div className="scrollbar-thin max-h-[7rem] overflow-y-auto">
              <div className="space-y-0.5 py-0.5 pr-1">
                {row.resultItems.map((item, i) => (
                  <div key={i} className="flex gap-1.5 text-[0.76rem] leading-[1.55] text-foreground/80">
                    <span className="mt-[0.5em] size-1 shrink-0 rounded-full bg-foreground/20" aria-hidden />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {row.status === "done" && row.resultItems.length === 0 && (
            <span className="text-[0.75rem] text-muted-foreground/50">No results found.</span>
          )}
        </td>

        {/* Actions */}
        <td style={{ width: 88, minWidth: 88 }} className="px-1 text-center">
          <div className="flex items-center justify-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
            {row.status === "idle" && canEnrich && !enriching && (
              <button
                type="button"
                onClick={() => onEnrich(row)}
                title="Enrich this row"
                className="flex size-6 items-center justify-center rounded text-muted-foreground transition hover:bg-primary/10 hover:text-primary"
              >
                <Zap className="size-3 stroke-[1.5]" aria-hidden />
              </button>
            )}
            {row.status === "done" && (
              <button
                type="button"
                onClick={() => onReenrich(row)}
                title="Re-enrich"
                className="flex size-6 items-center justify-center rounded text-muted-foreground transition hover:bg-muted hover:text-foreground"
              >
                <RefreshCw className="size-3 stroke-[1.5]" aria-hidden />
              </button>
            )}
            <button
              type="button"
              onClick={() => onDelete(row.id)}
              disabled={totalRows <= 1 || isLoading}
              title="Delete row"
              className="flex size-6 items-center justify-center rounded text-muted-foreground transition hover:bg-red-50 hover:text-red-500 disabled:pointer-events-none disabled:opacity-20 dark:hover:bg-red-950/30 dark:hover:text-red-400"
            >
              <Trash2 className="size-3 stroke-[1.5]" aria-hidden />
            </button>
          </div>
        </td>
      </tr>

      {/* ── sources sub-row ── */}
      {row.status === "done" && row.sources.length > 0 && (
        <tr className={cn("border-b border-border/40", rowBg)}>
          <td colSpan={5} />
          <td className="px-2.5 pb-2 pt-0.5" colSpan={2}>
            <div className="flex flex-wrap gap-1">
              <span className="mr-0.5 self-center text-[0.6rem] font-semibold uppercase tracking-wider text-muted-foreground/50">
                Sources
              </span>
              {row.sources.map((src, si) => (
                <a
                  key={si}
                  href={src.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={src.title || src.url}
                  className="inline-flex items-center gap-1 rounded border border-border/60 bg-muted/40 px-1.5 py-0.5 text-[0.62rem] text-muted-foreground transition hover:border-border hover:bg-muted hover:text-foreground"
                >
                  {extractDomain(src.url)}
                  <ExternalLink className="size-2 shrink-0 opacity-50" aria-hidden />
                </a>
              ))}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

const SEED_ROWS: [string, string][] = [
  ["", ""],
  ["", ""],
  ["", ""],
];

export function DatasheetPage() {
  const router  = useRouter();
  const [navOpen, setNavOpen]   = useState(false);
  const [recent, setRecent]     = useState<RecentItem[]>([]);
  const [rows, setRows]         = useState<EnrichRow[]>(() =>
    SEED_ROWS.map(([e, p]) => newRow(e, p)),
  );
  // selected: Set of row IDs
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [enriching, setEnriching] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // ── derived ──
  const doneCount   = rows.filter((r) => r.status === "done").length;
  const loadingCount = rows.filter((r) => r.status === "loading").length;
  const hasResults  = doneCount > 0;
  const totalFilled = rows.filter((r) => r.entity.trim() && r.prompt.trim()).length;

  const selectedRows  = rows.filter((r) => selected.has(r.id));
  const hasSelection  = selectedRows.length > 0;

  // rows eligible for enrichment given current mode
  const targetRows = hasSelection
    ? selectedRows.filter((r) => r.entity.trim() && r.prompt.trim() && r.status !== "done")
    : rows.filter((r) => r.entity.trim() && r.prompt.trim() && r.status !== "done");

  const enrichableCount = targetRows.length;

  // select-all state: true only if every row is selected
  const allSelected = rows.length > 0 && rows.every((r) => selected.has(r.id));
  const someSelected = !allSelected && rows.some((r) => selected.has(r.id));

  useEffect(() => { setRecent(loadRecent()); }, []);

  // keep selected clean when rows are deleted
  useEffect(() => {
    const ids = new Set(rows.map((r) => r.id));
    setSelected((prev) => {
      const next = new Set([...prev].filter((id) => ids.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [rows]);

  // ── callbacks ──
  const toggleSelect = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) { next.delete(id); } else { next.add(id); }
      return next;
    });
  }, []);

  const toggleSelectAll = useCallback(() => {
    setSelected(allSelected ? new Set() : new Set(rows.map((r) => r.id)));
  }, [allSelected, rows]);

  const updateRow = useCallback((id: string, patch: Partial<EnrichRow>) => {
    setRows((prev) => prev.map((r) => (r.id === id ? { ...r, ...patch } : r)));
  }, []);

  const enrichRow = useCallback(
    async (row: EnrichRow, signal?: AbortSignal) => {
      const entity = row.entity.trim();
      const prompt = row.prompt.trim();
      if (!entity || !prompt) return;

      updateRow(row.id, { status: "loading", error: "", result: "", resultItems: [], sources: [] });

      const analyst = ensureAnalystId();
      const base    = getGrondApiBase();

      try {
        const res = await fetch(`${base}/api/v1/tools/tavily`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target:       entity,
            query:        `${entity} ${prompt}`,
            analyst_id:   analyst,
            session_id:   crypto.randomUUID(),
            search_depth: "advanced",
            max_results:  5,
          }),
          signal,
        });

        const data: {
          evidence?: Array<{ value?: { title?: string; url?: string; snippet?: string } }>;
          error?: string;
        } = await res.json();

        if (!res.ok) {
          updateRow(row.id, { status: "error", error: formatApiDetail(data, `Failed (${res.status})`) });
          return;
        }

        const evidence = data.evidence ?? [];
        const sources: Source[] = evidence
          .filter((ev) => ev.value?.url)
          .map((ev) => ({ title: ev.value?.title ?? "", url: ev.value?.url ?? "", snippet: ev.value?.snippet ?? "" }));

        const snippets = evidence.map((ev) => ev.value?.snippet ?? "").filter(Boolean);
        const { items, summary } = parseSnippets(snippets);

        updateRow(row.id, { status: "done", result: summary, resultItems: items, sources });
      } catch (e: unknown) {
        if (signal?.aborted) { updateRow(row.id, { status: "idle" }); return; }
        updateRow(row.id, { status: "error", error: formatGrondReachabilityError(e, base) });
      }
    },
    [updateRow],
  );

  const runEnrich = useCallback(async () => {
    setEnriching(true);
    const ac = new AbortController();
    abortRef.current = ac;

    // snapshot target rows at time of click
    const pending = (
      hasSelection
        ? rows.filter((r) => selected.has(r.id))
        : rows
    ).filter((r) => r.entity.trim() && r.prompt.trim() && r.status !== "done");

    for (const row of pending) {
      if (ac.signal.aborted) break;
      await enrichRow(row, ac.signal);
    }

    setEnriching(false);
    abortRef.current = null;
  }, [rows, selected, hasSelection, enrichRow]);

  const cancelEnrich = useCallback(() => {
    abortRef.current?.abort();
    setEnriching(false);
  }, []);

  const handleReenrich = useCallback(
    (row: EnrichRow) => {
      const reset: EnrichRow = { ...row, status: "idle", result: "", resultItems: [], sources: [], error: "" };
      updateRow(row.id, reset);
      void enrichRow(reset);
    },
    [updateRow, enrichRow],
  );

  const downloadCsv = useCallback(() => {
    if (!hasResults) return;
    const blob = new Blob([toCsv(rows)], { type: "text/csv;charset=utf-8" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url;
    a.download = `grond-datasheet-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [rows, hasResults]);

  // ── enrich button label ──
  const enrichLabel = (() => {
    if (enriching) {
      return loadingCount > 0
        ? `Enriching ${doneCount + 1}/${totalFilled}…`
        : "Enriching…";
    }
    if (hasSelection) {
      return enrichableCount > 0
        ? `Enrich selected (${enrichableCount})`
        : "Enrich selected";
    }
    return enrichableCount > 0
      ? `Enrich all (${enrichableCount})`
      : "Enrich all";
  })();

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

        {/* Toolbar */}
        <div className="relative flex shrink-0 items-center gap-2 border-b border-border bg-background/80 px-4 py-2 backdrop-blur-sm">
          <span className="mr-2 text-[0.7rem] font-semibold uppercase tracking-wider text-muted-foreground">
            Datasheet
          </span>

          <Button
            type="button"
            size="sm"
            onClick={() => void runEnrich()}
            disabled={enrichableCount === 0 || enriching}
            className="h-7 rounded-lg px-3 text-xs"
          >
            {enriching && <Loader2 className="mr-1.5 size-3.5 animate-spin stroke-[1.5]" />}
            {enrichLabel}
          </Button>

          {enriching && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={cancelEnrich}
              className="h-7 gap-1.5 rounded-lg px-3 text-xs"
            >
              <X className="size-3.5 stroke-[1.5]" />
              Cancel
            </Button>
          )}

          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setRows((r) => [...r, newRow()])}
            className="h-7 gap-1.5 rounded-lg px-3 text-xs"
          >
            <Plus className="size-3.5 stroke-[1.5]" />
            Add row
          </Button>

          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={downloadCsv}
            disabled={!hasResults}
            className="h-7 gap-1.5 rounded-lg px-3 text-xs"
          >
            <Download className="size-3.5 stroke-[1.5]" />
            Export CSV
          </Button>

          {/* selection / progress counter */}
          <span className="ml-auto text-[0.68rem] tabular-nums text-muted-foreground">
            {hasSelection
              ? `${selectedRows.length} selected · ${doneCount}/${totalFilled} enriched`
              : totalFilled > 0
                ? `${doneCount}/${totalFilled} enriched`
                : ""}
          </span>

          {/* progress bar */}
          {enriching && totalFilled > 0 && (
            <div className="absolute inset-x-0 bottom-0 h-[2px] overflow-hidden">
              <div
                className="h-full bg-primary transition-all duration-700 ease-out"
                style={{ width: `${Math.round((doneCount / totalFilled) * 100)}%` }}
              />
            </div>
          )}
        </div>

        {/* Sheet table */}
        <main className="min-h-0 flex-1 overflow-auto" aria-label="Datasheet">
          <table className="w-full border-collapse text-sm" style={{ minWidth: 720 }}>
            {/* ── Fixed header ── */}
            <thead className="sticky top-0 z-10 bg-muted/80 backdrop-blur-sm">
              <tr className="border-b border-border">
                {/* select-all checkbox */}
                <th
                  style={{ width: COL_CHECK, minWidth: COL_CHECK }}
                  className="border-r border-border/60 py-2 text-center"
                >
                  <input
                    type="checkbox"
                    checked={allSelected}
                    ref={(el) => { if (el) el.indeterminate = someSelected; }}
                    onChange={toggleSelectAll}
                    aria-label="Select all rows"
                    className="size-3.5 cursor-pointer accent-primary"
                  />
                </th>
                <th
                  style={{ width: COL_NUM, minWidth: COL_NUM }}
                  className="border-r border-border/60 py-2 text-center text-[0.6rem] font-semibold uppercase tracking-wider text-muted-foreground/50 select-none"
                >
                  #
                </th>
                <th
                  style={{ width: COL_ENTITY, minWidth: COL_ENTITY }}
                  className="border-r border-border/60 px-2.5 py-2 text-left text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground"
                >
                  Entity
                </th>
                <th
                  style={{ width: COL_PROMPT, minWidth: COL_PROMPT }}
                  className="border-r border-border/60 px-2.5 py-2 text-left text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground"
                >
                  Prompt
                </th>
                <th
                  style={{ width: COL_STATUS, minWidth: COL_STATUS }}
                  className="border-r border-border/60 px-2.5 py-2 text-center text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground"
                >
                  Status
                </th>
                <th className="border-r border-border/60 px-2.5 py-2 text-left text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground">
                  Result
                </th>
                <th
                  style={{ width: 88, minWidth: 88 }}
                  className="px-2 py-2 text-center text-[0.65rem] font-semibold uppercase tracking-wider text-muted-foreground"
                >
                  Actions
                </th>
              </tr>
            </thead>

            {/* ── Body ── */}
            <tbody>
              {rows.map((row, i) => (
                <SheetRow
                  key={row.id}
                  row={row}
                  index={i}
                  totalRows={rows.length}
                  selected={selected.has(row.id)}
                  enriching={enriching}
                  onToggleSelect={toggleSelect}
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

              {/* ── Add row as table row ── */}
              <tr>
                <td colSpan={7} className="border-b border-border/30 px-0">
                  <button
                    type="button"
                    onClick={() => setRows((r) => [...r, newRow()])}
                    className="flex w-full items-center gap-2 px-4 py-2.5 text-[0.73rem] text-muted-foreground/50 transition hover:bg-muted/40 hover:text-muted-foreground"
                  >
                    <Plus className="size-3.5 stroke-[1.5]" aria-hidden />
                    Add row
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </main>

        {/* Footer */}
        <footer className="shrink-0 border-t border-border/40 px-4 py-2">
          <p className="text-[0.68rem] text-muted-foreground">
            <Link href="/" className="font-medium text-foreground underline underline-offset-2">Intel</Link>
            {" · "}
            <Link href="/recon" className="font-medium text-foreground underline underline-offset-2">Recon</Link>
            {" · "}
            <Link href="/admin" className="font-medium text-foreground underline underline-offset-2">Admin</Link>
          </p>
        </footer>
      </div>
    </div>
  );
}
