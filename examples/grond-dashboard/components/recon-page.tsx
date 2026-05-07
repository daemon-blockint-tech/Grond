"use client";

import { ChevronDown, ExternalLink, Menu } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import type { ReactNode } from "react";
import { useCallback, useEffect, useId, useState } from "react";

import { AnalystSidebarNav } from "@/components/analyst-sidebar-nav";
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
import {
  loadRecent,
  type RecentItem,
} from "@/lib/recent-investigations";
import { cn } from "@/lib/utils";

type NpcapInfo = {
  name: string;
  role: string;
  install_url: string;
  guide_url: string;
  devguide_url: string;
  note: string;
};

const NMAP_PROFILES = [
  "quick",
  "standard",
  "thorough",
  "udp",
  "vuln",
] as const;

/**
 * Sent as `timeout_seconds` to FastAPI (max 1800 in `nmap_tool`).
 * 300s is often too short for `standard`/`vuln` on public hosts; 900s reduces false timeouts.
 */
const NMAP_SERVER_TIMEOUT_SECONDS = 900;

function formatElapsedMmSs(totalSec: number): string {
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

function ExternalDocLink({
  href,
  children,
}: {
  href: string;
  children: ReactNode;
}) {
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

/** Interact with Grond Nmap/Ncrack/Npcap surfaces (API or orientation). */
export function ReconPage() {
  const router = useRouter();
  const [sheetOpen, setSheetOpen] = useState(false);
  const [recent, setRecent] = useState<RecentItem[]>([]);

  const nmapTargetId = useId();
  const nmapTargetHintId = useId();
  const nmapPortsId = useId();
  const nmapAuthId = useId();
  const ncrackTargetId = useId();

  const [nmapTarget, setNmapTarget] = useState("");
  const [nmapProfile, setNmapProfile] =
    useState<(typeof NMAP_PROFILES)[number]>("quick");
  const [nmapPorts, setNmapPorts] = useState("");
  const [nmapAuthRef, setNmapAuthRef] = useState("");
  const [nmapSession, setNmapSession] = useState("");
  const [nmapLoading, setNmapLoading] = useState(false);
  const [nmapElapsedSec, setNmapElapsedSec] = useState(0);
  const [nmapOutput, setNmapOutput] = useState<string | null>(null);
  const [nmapError, setNmapError] = useState<string | null>(null);

  const [ncrackTarget, setNcrackTarget] = useState("");
  const [ncrackSession, setNcrackSession] = useState("");
  const [ncrackLoading, setNcrackLoading] = useState(false);
  const [ncrackOutput, setNcrackOutput] = useState<string | null>(null);

  const [npcapInfo, setNpcapInfo] = useState<NpcapInfo | null>(null);
  const [npcapError, setNpcapError] = useState<string | null>(null);

  useEffect(() => {
    setRecent(loadRecent());
  }, []);

  useEffect(() => {
    setNmapSession(crypto.randomUUID());
    setNcrackSession(crypto.randomUUID());
  }, []);

  useEffect(() => {
    if (!nmapLoading) {
      setNmapElapsedSec(0);
      return;
    }
    setNmapElapsedSec(0);
    const id = window.setInterval(() => {
      setNmapElapsedSec((n) => n + 1);
    }, 1000);
    return () => window.clearInterval(id);
  }, [nmapLoading]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(
          `${getGrondApiBase()}/api/v1/tools/npcap/info`,
          { method: "GET" },
        );
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        const data = (await res.json()) as NpcapInfo;
        if (!cancelled) {
          setNpcapInfo(data);
          setNpcapError(null);
        }
      } catch (e) {
        if (!cancelled) {
          setNpcapInfo(null);
          setNpcapError(
            e instanceof Error ? e.message : "Could not load Npcap info",
          );
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleNewIntel = useCallback(() => {
    router.push("/");
  }, [router]);

  const runNmap = useCallback(async () => {
    setNmapLoading(true);
    setNmapError(null);
    setNmapOutput(null);
    const analyst = ensureAnalystId();
    const base = getGrondApiBase();
    const clientTimeoutMs = NMAP_SERVER_TIMEOUT_SECONDS * 1000 + 25_000;
    const signal =
      typeof AbortSignal !== "undefined" &&
      typeof AbortSignal.timeout === "function"
        ? AbortSignal.timeout(clientTimeoutMs)
        : undefined;
    try {
      const res = await fetch(`${base}/api/v1/tools/nmap`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal,
        body: JSON.stringify({
          target: nmapTarget.trim(),
          analyst_id: analyst,
          session_id: nmapSession,
          profile: nmapProfile,
          port_range: nmapPorts.trim(),
          timeout_seconds: NMAP_SERVER_TIMEOUT_SECONDS,
          authorization_ref: nmapAuthRef.trim() || null,
        }),
      });
      const data: unknown = await res.json().catch(() => ({}));
      if (!res.ok) {
        setNmapError(formatApiDetail(data, `Request failed (${res.status})`));
        return;
      }
      setNmapOutput(JSON.stringify(data, null, 2));
    } catch (e) {
      setNmapError(formatGrondReachabilityError(e, base));
    } finally {
      setNmapLoading(false);
    }
  }, [nmapAuthRef, nmapPorts, nmapProfile, nmapSession, nmapTarget]);

  const probeNcrack = useCallback(async () => {
    setNcrackLoading(true);
    setNcrackOutput(null);
    const analyst = ensureAnalystId();
    const base = getGrondApiBase();
    try {
      const res = await fetch(`${base}/api/v1/tools/ncrack`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: ncrackTarget.trim() || "—",
          analyst_id: analyst,
          session_id: ncrackSession,
        }),
      });
      const data: unknown = await res.json().catch(() => ({}));
      const text =
        res.status === 501 ?
          formatApiDetail(
            data,
            "Ncrack is not implemented. The server returned HTTP 501 with the following detail:",
          )
        : formatApiDetail(data, `HTTP ${res.status}`);
      setNcrackOutput(text);
    } catch (e) {
      setNcrackOutput(e instanceof Error ? e.message : "Network error");
    } finally {
      setNcrackLoading(false);
    }
  }, [ncrackSession, ncrackTarget]);

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
                Run server-side Nmap on the API host for targets allowed in your Grond configuration.
              </p>
              <details className="group max-w-2xl rounded-xl border border-border/70 bg-muted/20 dark:bg-zinc-900/50">
                <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2.5 text-xs font-medium text-foreground [&::-webkit-details-marker]:hidden">
                  <ChevronDown
                    className="size-4 shrink-0 text-muted-foreground opacity-80 transition group-open:rotate-180"
                    aria-hidden
                  />
                  About Ncrack, Npcap, and analyst id
                </summary>
                <div className="space-y-2 border-t border-border/60 px-3 pb-3 pt-3 text-xs leading-relaxed text-muted-foreground dark:border-white/10">
                  <p>
                    <strong className="font-medium text-foreground">Ncrack</strong> — not implemented
                    in this release; the API returns{" "}
                    <span className="whitespace-nowrap">HTTP 501</span> with JSON (see the Ncrack card).
                  </p>
                  <p>
                    <strong className="font-medium text-foreground">Npcap</strong> — Windows packet
                    capture on analyst workstations only; not run on the API (see Npcap card).
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
              </code>
              .
            </div>

            <section className="mt-10 space-y-4" aria-labelledby="nmap-tool-heading">
              <h2
                id="nmap-tool-heading"
                className="text-lg font-semibold tracking-tight text-foreground"
              >
                Nmap
              </h2>
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Server-side scan</CardTitle>
                  <CardDescription className="text-pretty">
                    Endpoint{" "}
                    <code className="rounded bg-muted px-1 py-0.5 text-xs">
                      POST /api/v1/tools/nmap
                    </code>
                    . The API invokes Nmap on the application host. Requires the{" "}
                    <code className="rounded bg-muted px-1 py-0.5 text-xs">nmap</code> binary and{" "}
                    <code className="rounded bg-muted px-1 py-0.5 text-xs">python-nmap</code>. Only
                    use targets covered by your authorization settings.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-0 p-0">
                  <div className="space-y-3 px-6 pb-4 pt-0">
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="space-y-1.5">
                        <label
                          htmlFor={nmapTargetId}
                          className="text-xs font-medium text-foreground"
                        >
                          Target
                        </label>
                        <Input
                          id={nmapTargetId}
                          value={nmapTarget}
                          onChange={(e) => setNmapTarget(e.target.value)}
                          placeholder="IP, hostname, or CIDR"
                          autoComplete="off"
                          aria-describedby={nmapTargetHintId}
                        />
                        <p
                          id={nmapTargetHintId}
                          className="text-pretty text-xs leading-snug text-muted-foreground"
                        >
                          This field only sets the target sent to the API — it does{" "}
                          <span className="font-medium text-foreground/90">not</span> grant permission.
                          The server runs Nmap only if that host/IP matches an authorization record (in
                          development, typically{" "}
                          <code className="rounded bg-muted px-1 py-0.5 text-[0.8em]">
                            GROND_AUTHORIZED_SCAN_TARGETS
                          </code>
                          ; in production, grants from your approval workflow).
                        </p>
                      </div>
                      <div className="space-y-1.5">
                        <label
                          htmlFor="nmap-profile"
                          className="text-xs font-medium text-foreground"
                        >
                          Profile
                        </label>
                        <select
                          id="nmap-profile"
                          value={nmapProfile}
                          onChange={(e) =>
                            setNmapProfile(e.target.value as (typeof NMAP_PROFILES)[number])
                          }
                          className="flex h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 py-1 text-sm shadow-sm dark:border-white/10 dark:bg-zinc-950"
                        >
                          {NMAP_PROFILES.map((p) => (
                            <option key={p} value={p}>
                              {p}
                            </option>
                          ))}
                        </select>
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <label
                        htmlFor={nmapPortsId}
                        className="text-xs font-medium text-foreground"
                      >
                        Port range (optional)
                      </label>
                      <Input
                        id={nmapPortsId}
                        value={nmapPorts}
                        onChange={(e) => setNmapPorts(e.target.value)}
                        placeholder="e.g. 22,80,443 or 8000-8010"
                        autoComplete="off"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label htmlFor={nmapAuthId} className="text-xs font-medium text-foreground">
                        Authorization ref (optional)
                      </label>
                      <Input
                        id={nmapAuthId}
                        value={nmapAuthRef}
                        onChange={(e) => setNmapAuthRef(e.target.value)}
                        placeholder="SOW / ticket id (audit trail)"
                        autoComplete="off"
                      />
                    </div>
                    <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
                      <Button
                        type="button"
                        onClick={() => void runNmap()}
                        disabled={nmapLoading || !nmapTarget.trim() || !nmapSession}
                        className="min-h-11 w-full sm:w-auto sm:min-w-[10rem]"
                      >
                        {nmapLoading ? "Scanning…" : "Run Nmap"}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => setNmapSession(crypto.randomUUID())}
                        className="min-h-11 w-full sm:w-auto"
                      >
                        New session id
                      </Button>
                    </div>
                    <p className="text-[11px] leading-snug text-muted-foreground">
                      <span className="font-medium text-foreground/90">Audit session</span>{" "}
                      {nmapSession ? (
                        <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-foreground">
                          {nmapSession.slice(0, 8)}…{nmapSession.slice(-4)}
                        </code>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                      <span className="text-muted-foreground">
                        {" "}
                        · included on each request for server audit logs; generate a new id if you
                        split work across tickets.
                      </span>
                    </p>
                  </div>

                  <div
                    className="border-t border-border px-6 pb-6 pt-4 dark:border-white/10"
                    aria-labelledby="nmap-result-heading"
                  >
                    <h3
                      id="nmap-result-heading"
                      className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground"
                    >
                      Result
                    </h3>
                    <div
                      className={cn(
                        "flex min-h-[14rem] flex-col overflow-hidden rounded-xl border border-border bg-zinc-50/80 dark:border-white/10 dark:bg-zinc-950/60",
                        nmapError && "border-red-500/40 bg-red-50/50 dark:bg-red-950/25",
                      )}
                    >
                      {nmapLoading ? (
                        <div className="flex flex-1 flex-col items-center justify-center gap-3 px-4 py-8 text-center text-sm text-muted-foreground">
                          <span
                            className="inline-block size-2 animate-pulse rounded-full bg-emerald-500"
                            aria-hidden
                          />
                          <div className="space-y-1">
                            <p className="font-medium text-foreground/90">Scanning…</p>
                            <p className="max-w-md text-pretty text-xs leading-relaxed">
                              Nmap runs on the API server inside this request.{" "}
                              <strong className="font-medium text-foreground/80">
                                Standard, thorough, UDP, and vuln
                              </strong>{" "}
                              scans against public hosts often take several minutes{" "}
                              <span className="font-medium text-foreground/80">
                                (server limit {Math.floor(NMAP_SERVER_TIMEOUT_SECONDS / 60)} min)
                              </span>
                              .
                            </p>
                            <p className="font-mono text-xs text-foreground/80">
                              Elapsed {formatElapsedMmSs(nmapElapsedSec)}
                            </p>
                          </div>
                        </div>
                      ) : nmapError ? (
                        <p
                          className="flex-1 whitespace-pre-wrap p-4 text-sm text-red-900 dark:text-red-100"
                          role="alert"
                        >
                          {nmapError}
                        </p>
                      ) : nmapOutput ? (
                        <pre className="max-h-[min(24rem,55vh)] flex-1 overflow-auto p-4 text-xs leading-relaxed text-zinc-900 dark:text-zinc-100">
                          <code>{nmapOutput}</code>
                        </pre>
                      ) : (
                        <p className="flex flex-1 items-center justify-center px-4 py-8 text-center text-xs text-muted-foreground">
                          Response JSON from{" "}
                          <code className="mx-1 rounded bg-muted px-1 py-0.5 text-[10px]">
                            POST /api/v1/tools/nmap
                          </code>{" "}
                          appears here after a successful run.
                        </p>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </section>

            <section className="mt-10 space-y-4" aria-labelledby="ncrack-tool-heading">
              <h2
                id="ncrack-tool-heading"
                className="text-lg font-semibold tracking-tight text-foreground"
              >
                Ncrack
              </h2>
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Integration status</CardTitle>
                  <CardDescription className="text-pretty">
                    Endpoint{" "}
                    <code className="rounded bg-muted px-1 py-0.5 text-xs">
                      POST /api/v1/tools/ncrack
                    </code>
                    . Ncrack support is not implemented in this release. The API responds with{" "}
                    <span className="whitespace-nowrap">HTTP 501</span> and a JSON payload. Use this
                    action only to verify routing, authentication, and client error handling.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="space-y-1.5">
                    <label
                      htmlFor={ncrackTargetId}
                      className="text-xs font-medium text-foreground"
                    >
                      Target (optional)
                    </label>
                    <Input
                      id={ncrackTargetId}
                      value={ncrackTarget}
                      onChange={(e) => setNcrackTarget(e.target.value)}
                      placeholder="Reserved for future requests"
                      autoComplete="off"
                    />
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Button
                      type="button"
                      variant="secondary"
                      onClick={() => void probeNcrack()}
                      disabled={ncrackLoading || !ncrackSession}
                    >
                      {ncrackLoading ? "Requesting…" : "Send test request"}
                    </Button>
                    <Button
                      type="button"
                      variant="secondary"
                      onClick={() => setNcrackSession(crypto.randomUUID())}
                    >
                      New session id
                    </Button>
                  </div>
                  {ncrackOutput ? (
                    <Textarea
                      readOnly
                      value={ncrackOutput}
                      className="min-h-[100px] font-mono text-xs"
                      aria-label="Ncrack API response message"
                    />
                  ) : null}
                  <p className="text-sm text-muted-foreground">
                    <ExternalDocLink href="https://nmap.org/ncrack/">Ncrack project</ExternalDocLink>
                  </p>
                </CardContent>
              </Card>
            </section>

            <section className="mt-10 space-y-4" aria-labelledby="npcap-tool-heading">
              <h2
                id="npcap-tool-heading"
                className="text-lg font-semibold tracking-tight text-foreground"
              >
                Npcap
              </h2>
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Workstation reference</CardTitle>
                  <CardDescription className="text-pretty">
                    Metadata from{" "}
                    <code className="rounded bg-muted px-1 py-0.5 text-xs">
                      GET /api/v1/tools/npcap/info
                    </code>
                    . Npcap is a Windows packet capture driver installed on analyst workstations. It
                    is not bundled with or executed by the Grond API.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  {npcapError ? (
                    <p className="text-amber-800 dark:text-amber-200" role="status">
                      {npcapError}
                    </p>
                  ) : null}
                  {npcapInfo ? (
                    <ul className="list-inside list-disc space-y-1 text-muted-foreground marker:text-foreground">
                      <li>
                        <span className="font-medium text-foreground">{npcapInfo.name}</span>:{" "}
                        {npcapInfo.role}
                      </li>
                      <li>{npcapInfo.note}</li>
                    </ul>
                  ) : (
                    !npcapError && (
                      <p className="text-muted-foreground" role="status">
                        Loading reference…
                      </p>
                    )
                  )}
                  {npcapInfo ? (
                    <p className="flex flex-wrap gap-x-3 gap-y-1">
                      <ExternalDocLink href={npcapInfo.install_url}>Download</ExternalDocLink>
                      <ExternalDocLink href={npcapInfo.guide_url}>User guide</ExternalDocLink>
                      <ExternalDocLink href={npcapInfo.devguide_url}>Developer guide</ExternalDocLink>
                    </p>
                  ) : null}
                </CardContent>
              </Card>
            </section>

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
            </p>
          </div>
        </main>
      </div>
    </div>
  );
}
