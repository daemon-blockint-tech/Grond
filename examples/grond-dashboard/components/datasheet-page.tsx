"use client";

import { Download, ExternalLink, Menu, Plus, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useId, useState } from "react";

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
  loadRecent,
  type RecentItem,
} from "@/lib/recent-investigations";

type SheetRow = {
  id: string;
  /** Row key / entity label (e.g. company domain, person, product). */
  entity: string;
  /** Question or column instruction answered with web-sourced evidence in Tavily Sheets. */
  enrichmentPrompt: string;
};

function newRow(): SheetRow {
  return {
    id: crypto.randomUUID(),
    entity: "",
    enrichmentPrompt: "",
  };
}

function toCsv(rows: SheetRow[]): string {
  const esc = (s: string) => {
    const q = /[",\n\r]/.test(s);
    const t = s.replace(/"/g, '""');
    return q ? `"${t}"` : t;
  };
  const header = "entity,enrichment_prompt";
  const lines = rows.map((r) => `${esc(r.entity.trim())},${esc(r.enrichmentPrompt.trim())}`);
  return [header, ...lines].join("\n");
}

/**
 * End-user workspace to **prepare** datasheet input for Tavily-style enrichment
 * ([tavily-sheets](https://github.com/tavily-ai/tavily-sheets): Tavily search + LLM + citations).
 * Full enrichment runs in hosted Sheets or a self-hosted clone — not via Grond `POST /api/v1/scan`.
 */
export function DatasheetPage() {
  const router = useRouter();
  const entityId = useId();
  const promptId = useId();
  const [sheetOpen, setSheetOpen] = useState(false);
  const [recent, setRecent] = useState<RecentItem[]>([]);
  const [rows, setRows] = useState<SheetRow[]>(() => [newRow(), newRow(), newRow()]);

  useEffect(() => {
    setRecent(loadRecent());
  }, []);

  const handleNewIntel = useCallback(() => {
    router.push("/");
  }, [router]);

  const downloadCsv = useCallback(() => {
    const nonEmpty = rows.some((r) => r.entity.trim() || r.enrichmentPrompt.trim());
    if (!nonEmpty) return;
    const blob = new Blob([toCsv(rows)], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `grond-datasheet-seed-${new Date().toISOString().slice(0, 10)}.csv`;
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
          aria-label="Datasheet enrichment"
        >
          <div className="mx-auto max-w-4xl px-4 py-6 sm:px-6 sm:py-10">
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                New · End user
              </p>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
                Datasheet enrichment
              </h1>
              <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground">
                Build rows for{" "}
                <strong className="font-medium text-foreground">entity</strong> +{" "}
                <strong className="font-medium text-foreground">enrichment prompt</strong> (what each
                cell should answer using the open web). Export CSV and continue in{" "}
                <a
                  href="https://sheets.tavily.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-medium text-foreground underline decoration-zinc-400 underline-offset-2 hover:decoration-foreground dark:decoration-zinc-500"
                >
                  Tavily Sheets
                </a>{" "}
                or self-host{" "}
                <a
                  href="https://github.com/tavily-ai/tavily-sheets"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-0.5 font-medium text-foreground underline decoration-zinc-400 underline-offset-2 hover:decoration-foreground dark:decoration-zinc-500"
                >
                  tavily-ai/tavily-sheets
                  <ExternalLink className="size-3.5 opacity-70" aria-hidden />
                </a>
                . This page does not call the Grond scan pipeline.
              </p>
            </div>

            <div className="mt-8 flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="secondary"
                className="rounded-xl gap-1.5"
                onClick={() => setRows((r) => [...r, newRow()])}
              >
                <Plus className="size-4" aria-hidden />
                Add row
              </Button>
              <Button
                type="button"
                className="rounded-xl gap-1.5"
                onClick={downloadCsv}
                disabled={!rows.some((r) => r.entity.trim() || r.enrichmentPrompt.trim())}
              >
                <Download className="size-4" aria-hidden />
                Export CSV
              </Button>
            </div>

            <div className="mt-6 overflow-x-auto rounded-2xl border border-border bg-card shadow-sm dark:border-white/10 dark:bg-zinc-900/40">
              <table className="w-full min-w-[36rem] border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/40 dark:bg-white/5">
                    <th scope="col" className="px-3 py-3 font-medium sm:px-4">
                      Entity / key
                    </th>
                    <th scope="col" className="px-3 py-3 font-medium sm:px-4">
                      Enrichment prompt (column instruction)
                    </th>
                    <th scope="col" className="w-12 px-2 py-3 sm:w-14">
                      <span className="sr-only">Remove</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row, index) => (
                    <tr
                      key={row.id}
                      className="border-b border-border/80 last:border-0 dark:border-white/10"
                    >
                      <td className="align-top p-2 sm:p-3">
                        <label htmlFor={`${entityId}-${row.id}`} className="sr-only">
                          Entity row {index + 1}
                        </label>
                        <Input
                          id={`${entityId}-${row.id}`}
                          placeholder="e.g. example.com, ACME Corp"
                          value={row.entity}
                          onChange={(e) =>
                            setRows((prev) =>
                              prev.map((r) =>
                                r.id === row.id ? { ...r, entity: e.target.value } : r,
                              ),
                            )
                          }
                          className="rounded-xl bg-background dark:bg-zinc-950/80"
                          autoComplete="off"
                        />
                      </td>
                      <td className="align-top p-2 sm:p-3">
                        <label htmlFor={`${promptId}-${row.id}`} className="sr-only">
                          Prompt row {index + 1}
                        </label>
                        <Textarea
                          id={`${promptId}-${row.id}`}
                          placeholder="e.g. Recent funding or leadership change (cite sources)."
                          value={row.enrichmentPrompt}
                          onChange={(e) =>
                            setRows((prev) =>
                              prev.map((r) =>
                                r.id === row.id
                                  ? { ...r, enrichmentPrompt: e.target.value }
                                  : r,
                              ),
                            )
                          }
                          className="min-h-[3rem] rounded-xl bg-background dark:bg-zinc-950/80"
                          rows={2}
                        />
                      </td>
                      <td className="align-top p-2 text-center sm:p-3">
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="size-9 text-muted-foreground hover:text-destructive"
                          aria-label={`Remove row ${index + 1}`}
                          disabled={rows.length <= 1}
                          onClick={() =>
                            setRows((prev) =>
                              prev.length <= 1 ? prev : prev.filter((r) => r.id !== row.id),
                            )
                          }
                        >
                          <Trash2 className="size-4" aria-hidden />
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <p className="mt-6 text-xs text-muted-foreground">
              Need full OSINT reports from Grond?{" "}
              <Link href="/" className="font-medium text-foreground underline underline-offset-2">
                Back to Intel
              </Link>
              .
            </p>
          </div>
        </main>
      </div>
    </div>
  );
}
