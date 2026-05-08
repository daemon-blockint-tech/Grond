"use client";

import { ChevronDown, ExternalLink, Menu } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import type { ReactNode } from "react";
import { useCallback, useEffect, useState } from "react";

import { AnalystSidebarNav } from "@/components/analyst-sidebar-nav";
import { EdgarCard } from "@/components/recon/edgar-card";
import { HarvesterCard } from "@/components/recon/harvester-card";
import { MetadataCard } from "@/components/recon/metadata-card";
import { NcrackCard } from "@/components/recon/ncrack-card";
import { NmapCard } from "@/components/recon/nmap-card";
import { NpcapCard } from "@/components/recon/npcap-card";
import { OsintmapCard } from "@/components/recon/osintmap-card";
import { TavilyExtractCard } from "@/components/recon/tavily-extract-card";
import { TavilySearchCard } from "@/components/recon/tavily-search-card";
import { GrondLogo } from "@/components/grond-logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import {
  loadRecent,
  type RecentItem,
} from "@/lib/recent-investigations";

function ExternalDocLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 font-medium text-foreground underline decoration-zinc-400 underline-offset-2 hover:decoration-foreground dark:decoration-zinc-500"
    >
      {children}
      <ExternalLink className="size-3.5 shrink-0 opacity-70" aria-hidden />
    </a>
  );
}

export function ReconPage() {
  const router = useRouter();
  const [sheetOpen, setSheetOpen] = useState(false);
  const [recent, setRecent] = useState<RecentItem[]>([]);

  useEffect(() => { setRecent(loadRecent()); }, []);

  const handleNewIntel = useCallback(() => { router.push("/"); }, [router]);

  const sidebar = (
    <AnalystSidebarNav
      recent={recent}
      onNew={handleNewIntel}
      onSelectRecent={() => { router.push("/"); }}
    />
  );

  const openMobileNav = (
    <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
      <SheetTrigger asChild>
        <Button variant="secondary" size="icon" className="lg:hidden" type="button" aria-label="Open navigation menu">
          <Menu className="size-5" />
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="w-[min(100%-2rem,20rem)] p-0">
        <SheetHeader className="sr-only">
          <SheetTitle>Navigation</SheetTitle>
        </SheetHeader>
        <AnalystSidebarNav
          recent={recent}
          onNew={() => { handleNewIntel(); setSheetOpen(false); }}
          onSelectRecent={() => { router.push("/"); setSheetOpen(false); }}
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
          aria-labelledby="recon-page-heading"
        >
          <div className="mx-auto max-w-4xl px-4 py-6 sm:px-6 sm:py-10">
            <header className="space-y-3">
              <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Developer · Network recon
              </p>
              <h1
                id="recon-page-heading"
                className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl"
              >
                Recon tools
              </h1>
              <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground">
                Run server-side OSINT and recon tools against targets allowed in your Grond configuration.
              </p>
              <details className="group max-w-2xl rounded-xl border border-border/70 bg-muted/20 dark:bg-zinc-900/50">
                <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2.5 text-xs font-medium text-foreground [&::-webkit-details-marker]:hidden">
                  <ChevronDown
                    className="size-4 shrink-0 text-muted-foreground opacity-80 transition group-open:rotate-180"
                    aria-hidden
                  />
                  About active vs. passive tools and analyst id
                </summary>
                <div className="space-y-2 border-t border-border/60 px-3 pb-3 pt-3 text-xs leading-relaxed text-muted-foreground dark:border-white/10">
                  <p>
                    <strong className="font-medium text-foreground">Active</strong> — Nmap and Ncrack
                    hit live systems. Use them inside written scope and your own policy.
                  </p>
                  <p>
                    <strong className="font-medium text-foreground">Passive</strong> — theHarvester,
                    Tavily, EDGAR, OSINTMap, and metadata extraction query public data or analyst-supplied files.
                  </p>
                  <p>
                    <strong className="font-medium text-foreground">Analyst id</strong> — matches
                    Intel; stored in this browser&apos;s{" "}
                    <code className="rounded bg-muted px-1 py-0.5 text-[0.85em] text-foreground">
                      localStorage
                    </code>{" "}
                    for API audit fields.
                  </p>
                </div>
              </details>
            </header>

            <div
              className="mt-6 rounded-2xl border border-amber-200/80 bg-amber-50 px-4 py-3 text-sm leading-snug text-amber-950 dark:border-amber-500/30 dark:bg-amber-950/40 dark:text-amber-100"
              role="note"
              aria-label="Authorized use reminder"
            >
              <strong className="font-semibold">Authorized use only.</strong> Nmap and Ncrack hit live
              systems. Use them inside written scope and your own policy. In development, seed allowed
              hosts with{" "}
              <code className="rounded bg-black/5 px-1 py-0.5 text-xs dark:bg-white/10">
                GROND_AUTHORIZED_SCAN_TARGETS
              </code>.
            </div>

            <NmapCard />
            <NcrackCard />
            <NpcapCard />
            <HarvesterCard />
            <EdgarCard />
            <OsintmapCard />
            <TavilySearchCard />
            <TavilyExtractCard />
            <MetadataCard />

            <section className="mt-10 space-y-4" aria-labelledby="local-build-heading">
              <h2 id="local-build-heading" className="text-lg font-semibold tracking-tight text-foreground">
                Local build (repo)
              </h2>
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Vendored sources</CardTitle>
                  <CardDescription className="text-pretty">
                    Optional: build pinned Nmap and Ncrack from the{" "}
                    <code className="rounded bg-muted px-1 py-0.5 text-xs">recon/</code> directory
                    in this repository. Npcap is distributed separately for Windows (
                    <ExternalDocLink href="https://npcap.com/">npcap.com</ExternalDocLink>
                    ).
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <pre className="overflow-x-auto rounded-xl border border-zinc-200 bg-zinc-50 p-3 text-xs text-zinc-900 dark:border-white/10 dark:bg-zinc-950 dark:text-zinc-100">
                    <code>./recon/build.sh all-install</code>
                  </pre>
                </CardContent>
              </Card>
            </section>

            <p className="mt-8 text-xs text-muted-foreground">
              <Link href="/" className="font-medium text-foreground underline underline-offset-2">
                Back to Intel
              </Link>
              {" · "}
              <Link href="/datasheet" className="font-medium text-foreground underline underline-offset-2">
                Datasheet enrichment
              </Link>
              {" · "}
              <Link href="/admin" className="font-medium text-foreground underline underline-offset-2">
                Admin
              </Link>
            </p>
          </div>
        </main>
      </div>
    </div>
  );
}
