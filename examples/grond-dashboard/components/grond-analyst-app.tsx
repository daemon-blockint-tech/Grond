"use client";

import {
  ChevronDown,
  Menu,
  SendHorizontal,
  Settings2,

} from "lucide-react";
import { useCallback, useEffect, useId, useRef, useState } from "react";

import { AnalystSidebarNav } from "@/components/analyst-sidebar-nav";
import {
  IntelThreadAnswerPanel,
  UserQueryBubble,
} from "@/components/intel-thread-view";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { GrondLogo } from "@/components/grond-logo";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Textarea } from "@/components/ui/textarea";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  emptyIntelReport,
  parseIntelReport,
  sourceCount,
  type IntelReport,
} from "@/lib/intel-report";
import {
  ensureAnalystId,
  formatGrondReachabilityError,
  formatScanApiError,
  getGrondApiBase,
} from "@/lib/grond-api-base";

import {
  loadRecent,
  saveRecent,
  type RecentItem,
} from "@/lib/recent-investigations";

type ThreadEntry = {
  id: string;
  user: {
    target: string;
    goal: string;
    displayPrompt: string;
  };
  status: "loading" | "ok" | "error";
  assistant?: {
    report: IntelReport;
    raw: unknown;
    parseWarning: boolean;
  };
  error?: string;
};

export function GrondAnalystApp() {
  const [message, setMessage] = useState("");
  const [target, setTarget] = useState("");
  const [runNmap, setRunNmap] = useState(false);
  const [investigationProfile, setInvestigationProfile] = useState<"general" | "company" | "social">("general");
  const [tavilyTimeRange, setTavilyTimeRange] = useState<"" | "day" | "week" | "month" | "year">("");
  const [recent, setRecent] = useState<RecentItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [sheetOpen, setSheetOpen] = useState(false);
  const [entries, setEntries] = useState<ThreadEntry[]>([]);
  const [optionsOpen, setOptionsOpen] = useState(false);

  const lastSubmittedGoalRef = useRef("");
  const threadEndRef = useRef<HTMLDivElement>(null);
  const messageRef = useRef<HTMLTextAreaElement>(null);
  const nmapId = useId();

  useEffect(() => { setRecent(loadRecent()); }, []);

  useEffect(() => {
    const t = window.setTimeout(() => {
      threadEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
    }, 60);
    return () => clearTimeout(t);
  }, [entries]);

  const handleNew = useCallback(() => {
    setMessage("");
    setTarget("");
    setRunNmap(false);
    setInvestigationProfile("general");
    setTavilyTimeRange("");
    setOptionsOpen(false);
    setEntries([]);
    lastSubmittedGoalRef.current = "";
  }, []);

  const pushRecent = useCallback((label: string, t: string) => {
    const item: RecentItem = { id: crypto.randomUUID(), label, target: t, ts: Date.now() };
    const next = [item, ...loadRecent()].slice(0, 50);
    saveRecent(next);
    setRecent(next);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedTarget = target.trim();
    const trimmedMessage = message.trim();
    if (!trimmedTarget || !trimmedMessage) return;

    const goalToSend = entries.length > 0
      ? `${lastSubmittedGoalRef.current}\n\n---\nFollow-up: ${trimmedMessage}`
      : trimmedMessage;

    const displayPrompt = trimmedMessage;
    const entryId = crypto.randomUUID();

    setEntries((prev) => [
      ...prev,
      { id: entryId, user: { target: trimmedTarget, goal: goalToSend, displayPrompt }, status: "loading" },
    ]);

    const body: Record<string, unknown> = {
      target: trimmedTarget,
      goal: goalToSend,
      analyst_id: ensureAnalystId(),
      run_nmap: runNmap,
      investigation_profile: investigationProfile,
    };
    if (tavilyTimeRange) body.tavily_time_range = tavilyTimeRange;

    setLoading(true);
    try {
      const res = await fetch(`${getGrondApiBase()}/api/v1/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      const text = await res.text();
      let data: unknown;
      try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }

      if (!res.ok) {
        const detail = formatScanApiError(data, res.statusText);
        const msg = `Request failed (${res.status}): ${detail}`;
        setEntries((prev) => prev.map((en) => en.id === entryId ? { ...en, status: "error", error: msg } : en));
        return;
      }

      const parsed = parseIntelReport(data);
      lastSubmittedGoalRef.current = goalToSend;
      setMessage("");

      setEntries((prev) =>
        prev.map((en) =>
          en.id === entryId
            ? { ...en, status: "ok", assistant: { report: parsed.data, raw: data, parseWarning: !parsed.ok } }
            : en,
        ),
      );

      const title = trimmedTarget.length > 48 ? `${trimmedTarget.slice(0, 45)}…` : trimmedTarget;
      pushRecent(title, trimmedTarget);
      queueMicrotask(() => messageRef.current?.focus());
    } catch (err) {
      const friendly = formatGrondReachabilityError(err, getGrondApiBase());
      setEntries((prev) => prev.map((en) => en.id === entryId ? { ...en, status: "error", error: friendly } : en));
    } finally {
      setLoading(false);
    }
  };

  const hasThread = entries.length > 0;
  const lastAssistant = [...entries].reverse().find((e) => e.assistant)?.assistant ?? null;
  const footerSources = lastAssistant ? sourceCount(lastAssistant.report) : 0;

  const openMobileNav = (
    <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
      <SheetTrigger asChild>
        <Button variant="ghost" size="icon" className="lg:hidden" type="button" aria-label="Open navigation menu">
          <Menu className="size-[18px] stroke-[1.25]" />
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="w-[min(100%-2rem,20rem)] p-0">
        <SheetHeader className="sr-only"><SheetTitle>Navigation</SheetTitle></SheetHeader>
        <AnalystSidebarNav
          recent={recent}
          onNew={() => { handleNew(); setSheetOpen(false); }}
          onSelectRecent={(item) => { setTarget(item.target); setSheetOpen(false); }}
        />
      </SheetContent>
    </Sheet>
  );

  const renderOptionsPanel = () => (
    <details
      open={optionsOpen}
      onToggle={(e) => setOptionsOpen(e.currentTarget.open)}
      className="group rounded-lg border border-white/[0.06] bg-white/[0.02] dark:border-white/[0.06] dark:bg-white/[0.02]"
    >
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-[11px] text-muted-foreground [&::-webkit-details-marker]:hidden">
        <Settings2 className="size-3 stroke-[1.5] opacity-60" aria-hidden />
        <span className="font-medium tracking-wide uppercase">Parameters</span>
        <ChevronDown className="ml-auto size-3 stroke-[1.5] shrink-0 opacity-40 transition-transform duration-300 spring-sm group-open:rotate-180" aria-hidden />
      </summary>
      <div className="space-y-3 border-t border-white/[0.04] px-3 pb-3 pt-3">
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="space-y-1">
            <label htmlFor="investigation-profile" className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground/70">
              Profile
            </label>
            <select
              id="investigation-profile"
              value={investigationProfile}
              onChange={(e) => setInvestigationProfile(e.target.value as typeof investigationProfile)}
              className="flex h-8 w-full rounded-md border border-white/[0.08] bg-transparent px-2.5 text-xs ring-offset-background focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              <option value="general">General OSINT</option>
              <option value="company">Organization</option>
              <option value="social">Social discourse</option>
            </select>
          </div>
          <div className="space-y-1">
            <label htmlFor="tavily-time-range" className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground/70">
              Recency
            </label>
            <select
              id="tavily-time-range"
              value={tavilyTimeRange}
              onChange={(e) => setTavilyTimeRange(e.target.value as typeof tavilyTimeRange)}
              className="flex h-8 w-full rounded-md border border-white/[0.08] bg-transparent px-2.5 text-xs ring-offset-background focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              <option value="">Any</option>
              <option value="day">Day</option>
              <option value="week">Week</option>
              <option value="month">Month</option>
              <option value="year">Year</option>
            </select>
          </div>
          <div className="space-y-1">
            <label htmlFor={nmapId} className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground/70">
              Nmap
            </label>
            <label className="flex h-8 items-center gap-2 rounded-md border border-white/[0.08] bg-transparent px-2.5 text-xs cursor-pointer">
              <input
                id={nmapId}
                type="checkbox"
                checked={runNmap}
                onChange={(e) => setRunNmap(e.target.checked)}
                className="size-3 rounded accent-foreground"
              />
              <span className={runNmap ? "text-amber-500 font-medium" : "text-muted-foreground"}>
                {runNmap ? "Enabled (auth)" : "Off"}
              </span>
            </label>
          </div>
        </div>
        {runNmap && (
          <p className="rounded-md border border-amber-500/20 bg-amber-500/[0.06] px-2.5 py-1.5 text-[11px] leading-snug text-amber-400/90">
            Nmap probes live systems — only use on pre-authorized targets.
          </p>
        )}
      </div>
    </details>
  );

  const renderChatInput = (variant: "hero" | "footer") => (
    <form onSubmit={handleSubmit} className={variant === "hero" ? "mx-auto max-w-2xl space-y-3" : "mx-auto max-w-2xl space-y-2"}>
      {variant === "hero" && (
        <div className="space-y-2">
          <div>
            <label htmlFor="target" className="mb-1.5 block text-[10px] font-medium uppercase tracking-wider text-muted-foreground/70">
              Target
            </label>
            <Input
              id="target"
              name="target"
              placeholder="URL, domain, host, or entity label"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              autoComplete="off"
              className="h-11 rounded-lg border-white/[0.08] bg-white/[0.03] text-sm placeholder:text-muted-foreground/50 focus-visible:border-white/[0.15] focus-visible:ring-0"
            />
          </div>
          {renderOptionsPanel()}
        </div>
      )}

      {variant === "footer" && (
        <div className="flex items-center gap-2 px-1 text-[11px] text-muted-foreground">
          <span className="font-medium text-foreground/80">{target}</span>
          {investigationProfile !== "general" && (
            <>
              <span aria-hidden className="text-muted-foreground/30">·</span>
              <span className="capitalize">{investigationProfile}</span>
            </>
          )}
          <button type="button" onClick={() => setOptionsOpen((o) => !o)} className="ml-auto text-muted-foreground/50 hover:text-foreground/60 transition-colors duration-200">
            <Settings2 className="size-3 stroke-[1.5]" />
          </button>
        </div>
      )}

      {optionsOpen && variant === "footer" && renderOptionsPanel()}

      <div className="flex items-end gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] p-1.5 backdrop-blur-sm transition-colors duration-200 focus-within:border-white/[0.14]">
        <label htmlFor={variant === "hero" ? "chat-message-hero" : "chat-message-footer"} className="sr-only">
          {hasThread ? "Follow-up" : "Ask anything"}
        </label>
        <Textarea
          ref={messageRef}
          id={variant === "hero" ? "chat-message-hero" : "chat-message-footer"}
          name="chat-message"
          rows={1}
          placeholder={hasThread ? "Follow-up on this target…" : "What should this investigation establish?"}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              const form = e.currentTarget.form;
              if (!loading && form) form.requestSubmit();
            }
          }}
          className="max-h-[160px] min-h-[40px] flex-1 resize-none rounded-lg border-0 bg-transparent px-3 py-2.5 text-sm leading-snug shadow-none placeholder:text-muted-foreground/40 focus-visible:ring-0 focus-visible:ring-offset-0"
          autoComplete="off"
        />
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              type="submit"
              size="icon"
              disabled={loading || !message.trim() || !target.trim()}
              className="size-9 shrink-0 rounded-lg bg-foreground/[0.06] text-foreground hover:bg-foreground/[0.1] disabled:opacity-30 transition-colors duration-200"
              aria-label="Send"
            >
              {loading ? (
                <span className="size-3.5 animate-spin rounded-full border border-white/10 border-t-foreground/40" aria-hidden />
              ) : (
                <SendHorizontal className="size-3.5 stroke-[1.5]" aria-hidden />
              )}
            </Button>
          </TooltipTrigger>
          <TooltipContent side="left" className="text-[11px]">Send — Enter · New line — Shift+Enter</TooltipContent>
        </Tooltip>
      </div>

      {variant === "footer" && footerSources > 0 && (
        <p className="px-1 text-[10px] uppercase tracking-wider text-muted-foreground/40">
          {footerSources} source{footerSources === 1 ? "" : "s"} in latest
        </p>
      )}
    </form>
  );

  const renderEmptyState = () => (
    <div className="flex min-h-0 flex-1 flex-col items-center justify-center px-4">
      <div className="w-full max-w-2xl space-y-10 animate-fade-in-up">
        <div className="text-center space-y-4">
          <h1 className="text-[1.75rem] font-semibold tracking-[-0.02em] text-foreground">
            What are you investigating?
          </h1>
          <p className="mx-auto max-w-sm text-[13px] leading-relaxed text-muted-foreground/60">
            Enter a target and pose your question — Grond runs the OSINT pipeline and returns an evidence-backed intel report.
          </p>
        </div>
        {renderChatInput("hero")}
      </div>
    </div>
  );

  const renderThread = () => (
    <>
      <ScrollArea className="min-h-0 flex-1">
        <div className="mx-auto w-full max-w-2xl px-4 pb-6 pt-8 sm:px-6">
          <div className="space-y-8">
            {entries.map((entry, ei) => (
              <div key={entry.id} className={`space-y-4 animate-fade-in-up stagger-${Math.min(ei + 1, 8)}`}>
                <UserQueryBubble
                  target={entry.user.target}
                  message={entry.user.displayPrompt}
                  goal={entry.user.goal}
                />

                {entry.status === "error" && entry.error && (
                  <div
                    role="alert"
                    className="whitespace-pre-wrap rounded-lg border border-red-500/20 bg-red-500/[0.05] px-4 py-3 text-[13px] leading-relaxed text-red-400"
                  >
                    {entry.error}
                  </div>
                )}

                {(entry.status === "loading" || entry.assistant) && (
                  <div className="max-w-[min(100%,52rem)]">
                    {entry.status === "loading" && (
                      <div className="flex items-center gap-2 pb-1 text-[11px] text-muted-foreground/50">
                        <span className="inline-block size-1.5 animate-pulse rounded-full bg-emerald-500/70" aria-hidden />
                        <span className="uppercase tracking-wider">Analyzing sources</span>
                      </div>
                    )}
                    <IntelThreadAnswerPanel
                      report={entry.assistant?.report ?? emptyIntelReport()}
                      loading={entry.status === "loading"}
                      parseWarning={entry.assistant?.parseWarning ?? false}
                      rawForDeveloper={entry.assistant?.raw ?? {}}
                    />
                  </div>
                )}
              </div>
            ))}
            <div ref={threadEndRef} className="h-1 shrink-0" aria-hidden />
          </div>
        </div>
      </ScrollArea>

      <footer className="shrink-0 border-t border-white/[0.06] bg-background/95 py-3 backdrop-blur-lg supports-[backdrop-filter]:bg-background/80 animate-slide-down">
        {renderChatInput("footer")}
      </footer>
    </>
  );

  return (
    <div className="flex h-svh bg-background">
      <aside
        className="hidden h-svh max-h-svh w-60 shrink-0 overflow-hidden border-r border-white/[0.06] lg:flex lg:flex-col"
        aria-label="Workspace"
      >
        <AnalystSidebarNav
          recent={recent}
          onNew={handleNew}
          onSelectRecent={(item) => setTarget(item.target)}
        />
      </aside>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
        <header className="flex shrink-0 items-center justify-between gap-3 border-b border-white/[0.06] px-4 py-2.5 lg:hidden">
          {openMobileNav}
          <div className="flex flex-1 justify-center px-2">
            <GrondLogo className="max-w-[8.5rem] justify-center [&_img]:object-center" />
          </div>
          <ThemeToggle />
        </header>

        <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
          {hasThread ? renderThread() : renderEmptyState()}
        </div>
      </div>
    </div>
  );
}
