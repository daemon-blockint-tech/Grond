"use client";

import {
  History,
  LayoutDashboard,
  Radar,
  Table2,
  Plus,
  User,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { GrondLogo } from "@/components/grond-logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import type { RecentItem } from "@/lib/recent-investigations";

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
  const navBtn =
    "flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-white/5";
  const navBtnActive = "bg-zinc-100 font-medium dark:bg-white/10";

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 px-3 py-4">
        <GrondLogo className="min-w-0 flex-1" />
        <ThemeToggle />
      </div>

      <div className="px-3">
        <Button
          type="button"
          onClick={onNew}
          className="w-full justify-center gap-2 rounded-xl"
        >
          <Plus className="size-4" aria-hidden />
          New investigation
        </Button>
      </div>

      <nav className="mt-6 space-y-1 px-2" aria-label="Primary">
        <Link
          href="/"
          className={`${navBtn} ${pathname === "/" ? navBtnActive : ""}`}
        >
          <LayoutDashboard className="size-4 shrink-0 text-zinc-500 dark:text-zinc-400" aria-hidden />
          Intel
        </Link>
        <Link
          href="/datasheet"
          className={`${navBtn} ${pathname === "/datasheet" ? navBtnActive : ""}`}
        >
          <Table2 className="size-4 shrink-0 text-zinc-500 dark:text-zinc-400" aria-hidden />
          Datasheet enrichment
        </Link>
        <button type="button" className={navBtn}>
          <History className="size-4 shrink-0 text-zinc-500 dark:text-zinc-400" aria-hidden />
          History
        </button>
      </nav>

      <p className="mt-5 px-4 text-xs font-medium uppercase tracking-wider text-zinc-600 dark:text-zinc-500">
        Recon
      </p>
      <nav className="mt-2 space-y-1 px-2" aria-label="Recon">
        <Link
          href="/recon"
          className={`${navBtn} ${pathname === "/recon" ? navBtnActive : ""}`}
        >
          <Radar className="size-4 shrink-0 text-zinc-500 dark:text-zinc-400" aria-hidden />
          Recon
        </Link>
      </nav>

      <Separator className="my-4 bg-zinc-200 dark:bg-white/10" />

      <p className="px-4 text-xs font-medium uppercase tracking-wider text-zinc-600 dark:text-zinc-500">
        Recent
      </p>
      <ScrollArea className="mt-2 flex-1 px-2">
        <ul className="space-y-1 pb-4">
          {recent.length === 0 ? (
            <li className="px-2 py-3 text-sm text-zinc-600 dark:text-zinc-500">
              Saved locally after each successful run.
            </li>
          ) : (
            recent.map((item) => (
              <li key={item.id}>
                <button
                  type="button"
                  onClick={() => onSelectRecent(item)}
                  className="w-full rounded-lg px-3 py-2.5 text-left text-sm text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-white/5"
                >
                  <span className="line-clamp-1 font-medium text-zinc-900 dark:text-zinc-100">
                    {item.label}
                  </span>
                  <span className="line-clamp-1 text-xs text-zinc-600 dark:text-zinc-500">
                    {item.target}
                  </span>
                </button>
              </li>
            ))
          )}
        </ul>
      </ScrollArea>

      <div className="mt-auto border-t border-zinc-200 p-3 dark:border-white/10">
        <div className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-zinc-50 px-3 py-2.5 dark:border-white/10 dark:bg-zinc-900/50">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-zinc-200 dark:bg-white/10">
            <User className="size-4 text-zinc-600 dark:text-zinc-300" aria-hidden />
          </div>
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-zinc-800 dark:text-zinc-200">Analyst</p>
            <p className="truncate text-xs text-zinc-600 dark:text-zinc-500">Signed-in user (stub)</p>
          </div>
        </div>
      </div>
    </div>
  );
}
