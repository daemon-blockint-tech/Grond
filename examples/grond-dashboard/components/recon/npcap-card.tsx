"use client";

import { ExternalLink } from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useState } from "react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { getGrondApiBase } from "@/lib/grond-api-base";

type NpcapInfo = {
  name: string;
  role: string;
  install_url: string;
  guide_url: string;
  devguide_url: string;
  note: string;
};

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

export function NpcapCard() {
  const [npcapInfo, setNpcapInfo] = useState<NpcapInfo | null>(null);
  const [npcapError, setNpcapError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`${getGrondApiBase()}/api/v1/tools/npcap/info`, { method: "GET" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = (await res.json()) as NpcapInfo;
        if (!cancelled) {
          setNpcapInfo(data);
          setNpcapError(null);
        }
      } catch (e) {
        if (!cancelled) {
          setNpcapInfo(null);
          setNpcapError(e instanceof Error ? e.message : "Could not load Npcap info");
        }
      }
    })();
    return () => { cancelled = true; };
  }, []);

  return (
    <section className="mt-10 space-y-4" aria-labelledby="npcap-tool-heading">
      <h2 id="npcap-tool-heading" className="text-lg font-semibold tracking-tight text-foreground">
        Npcap
      </h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Workstation reference</CardTitle>
          <CardDescription className="text-pretty">
            Metadata from{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">GET /api/v1/tools/npcap/info</code>.
            Npcap is a Windows packet capture driver installed on analyst workstations. It is not
            bundled with or executed by the Grond API.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          {npcapError ? (
            <p className="text-amber-800 dark:text-amber-200" role="status">{npcapError}</p>
          ) : null}
          {npcapInfo ? (
            <ul className="list-inside list-disc space-y-1 text-muted-foreground marker:text-foreground">
              <li>
                <span className="font-medium text-foreground">{npcapInfo.name}</span>: {npcapInfo.role}
              </li>
              <li>{npcapInfo.note}</li>
            </ul>
          ) : (
            !npcapError && (
              <p className="text-muted-foreground" role="status">Loading reference…</p>
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
  );
}
