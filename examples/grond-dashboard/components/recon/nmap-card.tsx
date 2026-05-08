"use client";

import { useCallback, useEffect, useId, useState } from "react";

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

const NMAP_PROFILES = ["quick", "standard", "thorough", "udp", "vuln"] as const;
const NMAP_SERVER_TIMEOUT_SECONDS = 900;

function formatElapsedMmSs(totalSec: number): string {
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

export function NmapCard() {
  const nmapTargetId = useId();
  const nmapTargetHintId = useId();
  const nmapPortsId = useId();
  const nmapAuthId = useId();

  const [nmapTarget, setNmapTarget] = useState("");
  const [nmapProfile, setNmapProfile] = useState<(typeof NMAP_PROFILES)[number]>("quick");
  const [nmapPorts, setNmapPorts] = useState("");
  const [nmapAuthRef, setNmapAuthRef] = useState("");
  const [nmapSession, setNmapSession] = useState("");
  const [nmapLoading, setNmapLoading] = useState(false);
  const [nmapElapsedSec, setNmapElapsedSec] = useState(0);
  const [nmapOutput, setNmapOutput] = useState<string | null>(null);
  const [nmapError, setNmapError] = useState<string | null>(null);

  useEffect(() => {
    setNmapSession(crypto.randomUUID());
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

  const runNmap = useCallback(async () => {
    setNmapLoading(true);
    setNmapError(null);
    setNmapOutput(null);
    const analyst = ensureAnalystId();
    const base = getGrondApiBase();
    const clientTimeoutMs = NMAP_SERVER_TIMEOUT_SECONDS * 1000 + 25_000;
    const signal =
      typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function"
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

  return (
    <section className="mt-10 space-y-4" aria-labelledby="nmap-tool-heading">
      <h2 id="nmap-tool-heading" className="text-lg font-semibold tracking-tight text-foreground">
        Nmap
      </h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Server-side scan</CardTitle>
          <CardDescription className="text-pretty">
            Endpoint{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">POST /api/v1/tools/nmap</code>.
            The API invokes Nmap on the application host. Requires the{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">nmap</code> binary and{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">python-nmap</code>. Only use
            targets covered by your authorization settings.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-0 p-0">
          <div className="space-y-3 px-6 pb-4 pt-0">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <label htmlFor={nmapTargetId} className="text-xs font-medium text-foreground">
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
                <p id={nmapTargetHintId} className="text-pretty text-xs leading-snug text-muted-foreground">
                  This field only sets the target sent to the API — it does{" "}
                  <span className="font-medium text-foreground/90">not</span> grant permission. The
                  server runs Nmap only if that host/IP matches an authorization record.
                </p>
              </div>
              <div className="space-y-1.5">
                <label htmlFor="nmap-profile" className="text-xs font-medium text-foreground">
                  Profile
                </label>
                <select
                  id="nmap-profile"
                  value={nmapProfile}
                  onChange={(e) => setNmapProfile(e.target.value as (typeof NMAP_PROFILES)[number])}
                  className="flex h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 py-1 text-sm shadow-sm dark:border-white/10 dark:bg-zinc-950"
                >
                  {NMAP_PROFILES.map((p) => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="space-y-1.5">
              <label htmlFor={nmapPortsId} className="text-xs font-medium text-foreground">
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
            </p>
          </div>

          <div className="border-t border-border px-6 pb-6 pt-4 dark:border-white/10" aria-labelledby="nmap-result-heading">
            <h3 id="nmap-result-heading" className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
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
                  <span className="inline-block size-2 animate-pulse rounded-full bg-emerald-500" aria-hidden />
                  <div className="space-y-1">
                    <p className="font-medium text-foreground/90">Scanning…</p>
                    <p className="max-w-md text-pretty text-xs leading-relaxed">
                      Nmap runs on the API server inside this request.{" "}
                      <strong className="font-medium text-foreground/80">Standard, thorough, UDP, and vuln</strong>{" "}
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
                <p className="flex-1 whitespace-pre-wrap p-4 text-sm text-red-900 dark:text-red-100" role="alert">
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
  );
}
