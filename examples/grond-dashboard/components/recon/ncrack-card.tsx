"use client";

import { ExternalLink } from "lucide-react";
import type { ReactNode } from "react";
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
import { Textarea } from "@/components/ui/textarea";
import {
  ensureAnalystId,
  formatApiDetail,
  getGrondApiBase,
} from "@/lib/grond-api-base";

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

export function NcrackCard() {
  const ncrackTargetId = "ncrack-target";
  const [ncrackTarget, setNcrackTarget] = useState("");
  const [ncrackSession, setNcrackSession] = useState("");
  const [ncrackLoading, setNcrackLoading] = useState(false);
  const [ncrackOutput, setNcrackOutput] = useState<string | null>(null);

  useEffect(() => {
    setNcrackSession(crypto.randomUUID());
  }, []);

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
        res.status === 501
          ? formatApiDetail(data, "Ncrack is not implemented. The server returned HTTP 501.")
          : formatApiDetail(data, `HTTP ${res.status}`);
      setNcrackOutput(text);
    } catch (e) {
      setNcrackOutput(e instanceof Error ? e.message : "Network error");
    } finally {
      setNcrackLoading(false);
    }
  }, [ncrackSession, ncrackTarget]);

  return (
    <section className="mt-10 space-y-4" aria-labelledby="ncrack-tool-heading">
      <h2 id="ncrack-tool-heading" className="text-lg font-semibold tracking-tight text-foreground">
        Ncrack
      </h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Integration status</CardTitle>
          <CardDescription className="text-pretty">
            Endpoint{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">POST /api/v1/tools/ncrack</code>.
            Ncrack support is not implemented in this release. The API responds with{" "}
            <span className="whitespace-nowrap">HTTP 501</span> and a JSON payload.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1.5">
            <label htmlFor={ncrackTargetId} className="text-xs font-medium text-foreground">
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
  );
}
