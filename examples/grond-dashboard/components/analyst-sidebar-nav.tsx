"use client";

import {
  History,
  LayoutDashboard,
  Radar,
  Shield,
  Table2,
  Plus,
  User,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { GrondLogo } from "@/components/grond-logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { getGrondApiBase } from "@/lib/grond-api-base";
import type { RecentItem } from "@/lib/recent-investigations";
import { cn } from "@/lib/utils";

type HealthStatus = "unknown" | "ok" | "error";

const iconCls = "size-[16px] stroke-[1.25] shrink-0 text-foreground/25";

export function AnalystSidebarNav({
  recent,
  onNew,
  onSelectRecent,
}: {
  recent: RecentItem[];
  onNew: () => void;
  onSelectRecent: (item: RecentItem) => void;
}) {
  const pathname = usePathname();
  const [health, setHealth] = useState<HealthStatus>("unknown");

  useEffect(() => {
    let cancelled = false;
    const base = getGrondApiBase();
    (async () => {
      try {
        const res = await fetch(`${base}/api/v1/health`, { method: "GET" });
        if (!cancelled) setHealth(res.ok ? "ok" : "error");
      } catch {
        if (!cancelled) setHealth("error");
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const navBtn =
    "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-[13px] text-foreground/60 hover:bg-white/[0.04] hover:text-foreground/80 transition-colors duration-200";
  const navBtnActive = "bg-white/[0.06] text-foreground font-medium";

  return (
    <div className="flex h-full flex-col bg-background">
      <div className="flex items-center gap-2.5 px-4 py-4">
        <GrondLogo className="min-w-0 flex-1" />
        <span
          className={cn(
            "inline-block size-2 shrink-0 rounded-full",
            health === "ok" && "bg-emerald-500/80",
            health === "error" && "bg-red-500/80",
            health === "unknown" && "animate-pulse bg-foreground/15",
          )}
          title={health === "ok" ? "API healthy" : health === "error" ? "API unreachable" : "Checking API…"}
          aria-label={health === "ok" ? "API healthy" : health === "error" ? "API unreachable" : "Checking API…"}
        />
        <ThemeToggle />
      </div>

      <div className="px-3">
        <Button
          type="button"
          onClick={onNew}
          variant="outline"
          className="w-full justify-center gap-2 rounded-lg border-white/[0.08] bg-white/[0.03] text-[12px] font-medium text-foreground/70 hover:bg-white/[0.06] hover:text-foreground/90"
        >
          <Plus className="size-3.5 stroke-[1.5]" aria-hidden />
          New investigation
        </Button>
      </div>

      <nav className="mt-6 space-y-0.5 px-2" aria-label="Primary">
        <Link
          href="/"
          className={`${navBtn} ${pathname === "/" ? navBtnActive : ""}`}
        >
          <LayoutDashboard className={iconCls} aria-hidden />
          Intel
        </Link>
        <Link
          href="/datasheet"
          className={`${navBtn} ${pathname === "/datasheet" ? navBtnActive : ""}`}
        >
          <Table2 className={iconCls} aria-hidden />
          Datasheet
        </Link>
        <button type="button" className={navBtn}>
          <History className={iconCls} aria-hidden />
          History
        </button>
      </nav>

      <p className="mt-6 px-4 text-[10px] font-semibold uppercase tracking-[0.1em] text-foreground/20">
        Recon
      </p>
      <nav className="mt-1.5 space-y-0.5 px-2" aria-label="Recon">
        <Link
          href="/recon"
          className={`${navBtn} ${pathname === "/recon" ? navBtnActive : ""}`}
        >
          <Radar className={iconCls} aria-hidden />
          Recon
        </Link>
      </nav>

      <p className="mt-6 px-4 text-[10px] font-semibold uppercase tracking-[0.1em] text-foreground/20">
        System
      </p>
      <nav className="mt-1.5 space-y-0.5 px-2" aria-label="System">
        <Link
          href="/admin"
          className={`${navBtn} ${pathname === "/admin" ? navBtnActive : ""}`}
        >
          <Shield className={iconCls} aria-hidden />
          Admin
        </Link>
      </nav>

      <Separator className="my-4 bg-white/[0.04]" />

      <p className="px-4 text-[10px] font-semibold uppercase tracking-[0.1em] text-foreground/20">
        Recent
      </p>
      <ScrollArea className="mt-1.5 flex-1 px-2">
        <ul className="space-y-0.5 pb-4">
          {recent.length === 0 ? (
            <li className="px-2 py-3 text-[12px] text-foreground/20">
              Saved locally after each successful run.
            </li>
          ) : (
            recent.map((item) => (
              <li key={item.id}>
                <button
                  type="button"
                  onClick={() => onSelectRecent(item)}
                  className="w-full rounded-lg px-3 py-2 text-left transition-colors duration-200 hover:bg-white/[0.04]"
                >
                  <span className="line-clamp-1 text-[12px] font-medium text-foreground/70">
                    {item.label}
                  </span>
                  <span className="line-clamp-1 text-[10px] text-foreground/25">
                    {item.target}
                  </span>
                </button>
              </li>
            ))
          )}
        </ul>
      </ScrollArea>

      <div className="mt-auto border-t border-white/[0.04] p-3">
        <div className="flex items-center gap-3 rounded-lg border border-white/[0.05] bg-white/[0.02] px-3 py-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-foreground/[0.06]">
            <User className="size-3.5 stroke-[1.25] text-foreground/30" aria-hidden />
          </div>
          <div className="min-w-0">
            <p className="truncate text-[12px] font-medium text-foreground/60">Analyst</p>
            <p className="truncate text-[10px] text-foreground/25">Signed-in user</p>
          </div>
        </div>
      </div>
    </div>
  );
}
