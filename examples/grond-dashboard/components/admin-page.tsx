"use client";

import { Menu } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

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
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
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

type HealthStatus = "unknown" | "ok" | "error";

export function AdminPage() {
  const router = useRouter();
  const [sheetOpen, setSheetOpen] = useState(false);
  const [recent, setRecent] = useState<RecentItem[]>([]);

  const [healthStatus, setHealthStatus] = useState<HealthStatus>("unknown");
  const [healthLatencyMs, setHealthLatencyMs] = useState<number | null>(null);

  const [grantTarget, setGrantTarget] = useState("");
  const [grantTool, setGrantTool] = useState("nmap");
  const [grantLegalRef, setGrantLegalRef] = useState("");
  const [grantNotes, setGrantNotes] = useState("");
  const [grantExpires, setGrantExpires] = useState("");
  const [adminKey, setAdminKey] = useState("");
  const [grantLoading, setGrantLoading] = useState(false);
  const [grantOutput, setGrantOutput] = useState<string | null>(null);
  const [grantError, setGrantError] = useState<string | null>(null);

  useEffect(() => { setRecent(loadRecent()); }, []);

  const checkHealth = useCallback(async () => {
    setHealthStatus("unknown");
    const base = getGrondApiBase();
    const t0 = performance.now();
    try {
      const res = await fetch(`${base}/api/v1/health`, { method: "GET" });
      const elapsed = Math.round(performance.now() - t0);
      if (res.ok) {
        setHealthStatus("ok");
        setHealthLatencyMs(elapsed);
      } else {
        setHealthStatus("error");
        setHealthLatencyMs(null);
      }
    } catch {
      setHealthStatus("error");
      setHealthLatencyMs(null);
    }
  }, []);

  useEffect(() => { void checkHealth(); }, [checkHealth]);

  const createGrant = useCallback(async () => {
    setGrantLoading(true);
    setGrantError(null);
    setGrantOutput(null);
    const analyst = ensureAnalystId();
    const base = getGrondApiBase();
    try {
      const body: Record<string, unknown> = {
        target: grantTarget.trim(),
        analyst_id: analyst,
        tool: grantTool.trim(),
        legal_ref: grantLegalRef.trim(),
        notes: grantNotes.trim(),
      };
      if (grantExpires) body.expires_at = grantExpires;
      const res = await fetch(`${base}/api/v1/admin/active-scan-authorizations`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Grond-Authorization-Admin-Key": adminKey.trim(),
        },
        body: JSON.stringify(body),
      });
      const data: unknown = await res.json().catch(() => ({}));
      if (!res.ok) {
        setGrantError(formatApiDetail(data, `Request failed (${res.status})`));
        return;
      }
      setGrantOutput(JSON.stringify(data, null, 2));
    } catch (e) {
      setGrantError(formatGrondReachabilityError(e, base));
    } finally {
      setGrantLoading(false);
    }
  }, [grantTarget, grantTool, grantLegalRef, grantNotes, grantExpires, adminKey]);

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
          aria-labelledby="admin-page-heading"
        >
          <div className="mx-auto max-w-4xl px-4 py-6 sm:px-6 sm:py-10">
            <header className="space-y-3">
              <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Admin · System management
              </p>
              <h1
                id="admin-page-heading"
                className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl"
              >
                Admin
              </h1>
              <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground">
                Health checks and active-scan authorization grants. Admin key is required for grant creation.
              </p>
            </header>

            <section className="mt-10 space-y-4" aria-labelledby="health-heading">
              <h2 id="health-heading" className="text-lg font-semibold tracking-tight text-foreground">
                API Health
              </h2>
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Status check</CardTitle>
                  <CardDescription className="text-pretty">
                    <code className="rounded bg-muted px-1 py-0.5 text-xs">GET /api/v1/health</code>
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-3">
                    <span
                      className={cn(
                        "inline-block size-3 rounded-full",
                        healthStatus === "ok" && "bg-emerald-500",
                        healthStatus === "error" && "bg-red-500",
                        healthStatus === "unknown" && "animate-pulse bg-zinc-400",
                      )}
                      aria-hidden
                    />
                    <span className="text-sm font-medium text-foreground">
                      {healthStatus === "ok" ? "Healthy" : healthStatus === "error" ? "Unreachable" : "Checking…"}
                    </span>
                    {healthLatencyMs !== null && (
                      <span className="text-xs text-muted-foreground">{healthLatencyMs}ms</span>
                    )}
                  </div>
                  <Button type="button" variant="outline" onClick={() => void checkHealth()}>
                    Re-check
                  </Button>
                </CardContent>
              </Card>
            </section>

            <section className="mt-10 space-y-4" aria-labelledby="grant-heading">
              <h2 id="grant-heading" className="text-lg font-semibold tracking-tight text-foreground">
                Active-scan authorization
              </h2>
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Create grant</CardTitle>
                  <CardDescription className="text-pretty">
                    <code className="rounded bg-muted px-1 py-0.5 text-xs">
                      POST /api/v1/admin/active-scan-authorizations
                    </code>
                    . Requires{" "}
                    <code className="rounded bg-muted px-1 py-0.5 text-xs">
                      X-Grond-Authorization-Admin-Key
                    </code>{" "}
                    header matching server env{" "}
                    <code className="rounded bg-muted px-1 py-0.5 text-xs">
                      GROND_AUTHORIZATION_ADMIN_KEY
                    </code>.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-0 p-0">
                  <div className="space-y-3 px-6 pb-4 pt-0">
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="space-y-1.5">
                        <label htmlFor="grant-target" className="text-xs font-medium text-foreground">
                          Target
                        </label>
                        <Input
                          id="grant-target"
                          value={grantTarget}
                          onChange={(e) => setGrantTarget(e.target.value)}
                          placeholder="IP, CIDR, hostname, or *.sub.example.com"
                          autoComplete="off"
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label htmlFor="grant-tool" className="text-xs font-medium text-foreground">
                          Tool
                        </label>
                        <select
                          id="grant-tool"
                          value={grantTool}
                          onChange={(e) => setGrantTool(e.target.value)}
                          className="flex h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 py-1 text-sm shadow-sm dark:border-white/10 dark:bg-zinc-950"
                        >
                          <option value="nmap">nmap</option>
                          <option value="ncrack">ncrack</option>
                          <option value="theharvester">theharvester</option>
                          <option value="*">*</option>
                        </select>
                      </div>
                    </div>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="space-y-1.5">
                        <label htmlFor="grant-legal-ref" className="text-xs font-medium text-foreground">
                          Legal reference
                        </label>
                        <Input
                          id="grant-legal-ref"
                          value={grantLegalRef}
                          onChange={(e) => setGrantLegalRef(e.target.value)}
                          placeholder="SOW / ticket / contract id"
                          autoComplete="off"
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label htmlFor="grant-expires" className="text-xs font-medium text-foreground">
                          Expires at (optional)
                        </label>
                        <Input
                          id="grant-expires"
                          type="datetime-local"
                          value={grantExpires}
                          onChange={(e) => setGrantExpires(e.target.value)}
                          autoComplete="off"
                        />
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <label htmlFor="grant-notes" className="text-xs font-medium text-foreground">
                        Notes
                      </label>
                      <Input
                        id="grant-notes"
                        value={grantNotes}
                        onChange={(e) => setGrantNotes(e.target.value)}
                        placeholder="Internal context (defaults to admin_api)"
                        autoComplete="off"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label htmlFor="grant-admin-key" className="text-xs font-medium text-foreground">
                        Admin key
                      </label>
                      <Input
                        id="grant-admin-key"
                        type="password"
                        value={adminKey}
                        onChange={(e) => setAdminKey(e.target.value)}
                        placeholder="GROND_AUTHORIZATION_ADMIN_KEY"
                        autoComplete="off"
                      />
                    </div>
                    <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
                      <Button
                        type="button"
                        onClick={() => void createGrant()}
                        disabled={grantLoading || !grantTarget.trim() || !adminKey.trim()}
                        className="min-h-11 w-full sm:w-auto sm:min-w-[10rem]"
                      >
                        {grantLoading ? "Creating…" : "Create grant"}
                      </Button>
                    </div>
                  </div>

                  <div className="border-t border-border px-6 pb-6 pt-4 dark:border-white/10">
                    <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      Result
                    </h3>
                    <div
                      className={cn(
                        "flex min-h-[10rem] flex-col overflow-hidden rounded-xl border border-border bg-zinc-50/80 dark:border-white/10 dark:bg-zinc-950/60",
                        grantError && "border-red-500/40 bg-red-50/50 dark:bg-red-950/25",
                      )}
                    >
                      {grantLoading ? (
                        <div className="flex flex-1 items-center justify-center gap-3 px-4 py-8 text-sm text-muted-foreground">
                          <span className="inline-block size-2 animate-pulse rounded-full bg-emerald-500" aria-hidden />
                          Creating authorization…
                        </div>
                      ) : grantError ? (
                        <p className="flex-1 whitespace-pre-wrap p-4 text-sm text-red-900 dark:text-red-100" role="alert">
                          {grantError}
                        </p>
                      ) : grantOutput ? (
                        <pre className="max-h-[min(16rem,40vh)] flex-1 overflow-auto p-4 text-xs leading-relaxed text-zinc-900 dark:text-zinc-100">
                          <code>{grantOutput}</code>
                        </pre>
                      ) : (
                        <p className="flex flex-1 items-center justify-center px-4 py-8 text-center text-xs text-muted-foreground">
                          Grant response appears here after creation.
                        </p>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </section>

            <p className="mt-8 text-xs text-muted-foreground">
              <Link href="/" className="font-medium text-foreground underline underline-offset-2">
                Back to Intel
              </Link>
              {" · "}
              <Link href="/recon" className="font-medium text-foreground underline underline-offset-2">
                Recon tools
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
