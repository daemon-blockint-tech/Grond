"use client";

import {
  ChevronDown,
  Menu,
  Paperclip,
  SendHorizontal,
} from "lucide-react";
import Link from "next/link";
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
import { formatGrondReachabilityError } from "@/lib/grond-api-base";
import { cn } from "@/lib/utils";
import {
  loadRecent,
  saveRecent,
  type RecentItem,
} from "@/lib/recent-investigations";

const ANALYST_KEY = "grond-analyst-id";

const CATEGORIES = [
  "Entity",
  "Web",
  "Regulatory",
  "Social",
  "Technical",
] as const;

type Category = (typeof CATEGORIES)[number];

type ThreadEntry = {
  id: string;
  user: {
    target: string;
    goal: string;
    displayPrompt: string;
    fileName?: string | null;
  };
  status: "loading" | "ok" | "error";
  assistant?: {
    report: IntelReport;
    raw: unknown;
    parseWarning: boolean;
  };
  error?: string;
};

function getApiBase(): string {
  return (
    process.env.NEXT_PUBLIC_GROND_API_URL?.replace(/\/$/, "") ||
    "http://127.0.0.1:8000"
  );
}

/** FastAPI may return `detail` as a string or structured object (e.g. 403 active-scan HITL). */
function formatScanApiError(data: unknown, fallback: string): string {
  if (typeof data !== "object" || data === null || !("detail" in data)) {
    return fallback;
  }
  const detail = (data as { detail: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (typeof detail === "object" && detail !== null) {
    const o = detail as {
      message?: unknown;
      hint?: unknown;
      actions?: unknown;
    };
    const parts: string[] = [];
    if (typeof o.message === "string" && o.message) parts.push(o.message);
    if (typeof o.hint === "string" && o.hint) parts.push(o.hint);
    if (Array.isArray(o.actions)) {
      const lines = o.actions.filter((a): a is string => typeof a === "string");
      if (lines.length) parts.push(lines.map((l) => `• ${l}`).join("\n"));
    }
    if (parts.length) return parts.join("\n\n");
  }
  try {
    return JSON.stringify(detail);
  } catch {
    return fallback;
  }
}

function ensureAnalystId(): string {
  if (typeof window === "undefined") return "analyst-local";
  let id = localStorage.getItem(ANALYST_KEY);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(ANALYST_KEY, id);
  }
  return id;
}

const CATEGORY_GOALS: Record<Category, string> = {
  Entity:
    "Summarize the subject’s public profile: leadership where relevant, related entities, major news, and official web presence.",
  Web: "Enumerate the target’s public web footprint: primary domains, notable subdomains, and indexed surface pages.",
  Regulatory:
    "Surface relevant regulatory and filing references (where publicly available) tied to the target.",
  Social:
    "Collect open-source social signals: official accounts, notable public mentions, and indexed discourse (no private data).",
  Technical:
    "Assess publicly observable technical exposure: known services, banners, and corroborated infra signals.",
};

export function GrondAnalystApp() {
  const [goal, setGoal] = useState("");
  const [followUp, setFollowUp] = useState("");
  const [target, setTarget] = useState("");
  const [runNmap, setRunNmap] = useState(false);
  const [investigationProfile, setInvestigationProfile] = useState<
    "general" | "company" | "social"
  >("general");
  const [tavilyTimeRange, setTavilyTimeRange] = useState<"" | "day" | "week" | "month" | "year">(
    "",
  );
  const [activeCategory, setActiveCategory] = useState<Category | null>(null);
  const [recent, setRecent] = useState<RecentItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sheetOpen, setSheetOpen] = useState(false);
  const [entries, setEntries] = useState<ThreadEntry[]>([]);
  const [attachedName, setAttachedName] = useState<string | null>(null);
  const [nmapPanelOpen, setNmapPanelOpen] = useState(false);

  const lastSubmittedGoalRef = useRef("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const followUpRef = useRef<HTMLTextAreaElement>(null);
  const threadEndRef = useRef<HTMLDivElement>(null);
  const nmapId = useId();

  useEffect(() => {
    setRecent(loadRecent());
  }, []);

  useEffect(() => {
    const t = window.setTimeout(() => {
      threadEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
    }, 60);
    return () => clearTimeout(t);
  }, [entries]);

  const applyCategory = useCallback((cat: Category) => {
    setActiveCategory(cat);
    const prof =
      cat === "Social" ? "social" : cat === "Entity" ? "company" : "general";
    setInvestigationProfile(prof);
    setGoal((g) =>
      g.trim() ? `${g.trim()}\n\n${CATEGORY_GOALS[cat]}` : CATEGORY_GOALS[cat],
    );
  }, []);

  const handleNew = useCallback(() => {
    setGoal("");
    setFollowUp("");
    setTarget("");
    setRunNmap(false);
    setNmapPanelOpen(false);
    setInvestigationProfile("general");
    setTavilyTimeRange("");
    setActiveCategory(null);
    setError(null);
    setEntries([]);
    setAttachedName(null);
    lastSubmittedGoalRef.current = "";
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, []);

  const pushRecent = useCallback((label: string, t: string) => {
    const item: RecentItem = {
      id: crypto.randomUUID(),
      label,
      target: t,
      ts: Date.now(),
    };
    const next = [item, ...loadRecent()].slice(0, 50);
    saveRecent(next);
    setRecent(next);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const trimmedTarget = target.trim();
    const trimmedGoal = goal.trim();
    const trimmedFollow = followUp.trim();

    const goalToSend =
      entries.length > 0 && trimmedFollow
        ? `${lastSubmittedGoalRef.current}\n\n---\nFollow-up: ${trimmedFollow}`
        : trimmedGoal;

    if (!trimmedTarget || !goalToSend.trim()) {
      setError(
        entries.length > 0
          ? "Add a follow-up in the chat box, or set a new goal under Target & scan options."
          : "Enter both a target and an investigation goal.",
      );
      return;
    }

    const displayPrompt =
      entries.length > 0 && trimmedFollow ? trimmedFollow : trimmedGoal;

    const entryId = crypto.randomUUID();
    const fileLabel = attachedName;
    setEntries((prev) => [
      ...prev,
      {
        id: entryId,
        user: {
          target: trimmedTarget,
          goal: goalToSend,
          displayPrompt,
          fileName: fileLabel,
        },
        status: "loading",
      },
    ]);

    const body: Record<string, unknown> = {
      target: trimmedTarget,
      goal: goalToSend,
      analyst_id: ensureAnalystId(),
      run_nmap: runNmap,
      investigation_profile: investigationProfile,
    };
    if (tavilyTimeRange) {
      body["tavily_time_range"] = tavilyTimeRange;
    }

    setLoading(true);
    try {
      const res = await fetch(`${getApiBase()}/api/v1/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      const text = await res.text();
      let data: unknown;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        data = { raw: text };
      }

      if (!res.ok) {
        const detail = formatScanApiError(data, res.statusText);
        const msg = `Request failed (${res.status}): ${detail}`;
        setEntries((prev) =>
          prev.map((en) =>
            en.id === entryId ? { ...en, status: "error", error: msg } : en,
          ),
        );
        setError(msg);
        return;
      }

      const parsed = parseIntelReport(data);
      lastSubmittedGoalRef.current = goalToSend;
      setGoal("");
      setFollowUp("");
      setAttachedName(null);
      if (fileInputRef.current) fileInputRef.current.value = "";

      setEntries((prev) =>
        prev.map((en) =>
          en.id === entryId
            ? {
                ...en,
                status: "ok",
                assistant: {
                  report: parsed.data,
                  raw: data,
                  parseWarning: !parsed.ok,
                },
              }
            : en,
        ),
      );

      const title =
        trimmedTarget.length > 48
          ? `${trimmedTarget.slice(0, 45)}…`
          : trimmedTarget;
      pushRecent(title, trimmedTarget);
      queueMicrotask(() => followUpRef.current?.focus());
    } catch (err) {
      const friendly = formatGrondReachabilityError(err, getApiBase());
      setError(friendly);
      setEntries((prev) =>
        prev.map((en) =>
          en.id === entryId ? { ...en, status: "error", error: friendly } : en,
        ),
      );
    } finally {
      setLoading(false);
    }
  };

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
            handleNew();
            setSheetOpen(false);
          }}
          onSelectRecent={(item) => {
            setTarget(item.target);
            setSheetOpen(false);
          }}
        />
      </SheetContent>
    </Sheet>
  );

  const lastAssistant =
    [...entries].reverse().find((e) => e.assistant)?.assistant ?? null;
  const footerSources =
    lastAssistant ? sourceCount(lastAssistant.report) : 0;
  const hasThread = entries.length > 0;

  function renderComposer() {
    const renderNmapDisclosure = (nmapInputId: string) => (
      <details
        open={nmapPanelOpen}
        onToggle={(e) => {
          const next = e.currentTarget.open;
          setNmapPanelOpen(next);
          if (!next) setRunNmap(false);
        }}
        className="group rounded-xl border border-amber-500/45 bg-amber-50/40 dark:border-amber-500/35 dark:bg-amber-950/30"
      >
        <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2.5 text-xs font-semibold text-amber-950 dark:text-amber-100 [&::-webkit-details-marker]:hidden">
          <ChevronDown
            className="size-4 shrink-0 opacity-80 transition group-open:rotate-180"
            aria-hidden
          />
          <span>Active network scan (Nmap)</span>
          <span className="rounded-full bg-amber-600/20 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-amber-950 dark:text-amber-100">
            High risk
          </span>
        </summary>
        <div className="space-y-3 border-t border-amber-500/25 px-3 pb-3 pt-3 dark:border-amber-500/20">
          <p
            className="rounded-lg border border-amber-500/35 bg-amber-500/10 px-3 py-2 text-[11px] leading-snug text-amber-950 dark:text-amber-100/95"
            role="note"
          >
            <strong className="font-semibold">Authorized use only.</strong> Nmap probes live
            systems. Targets must be pre-authorized in Grond (same policy as the{" "}
            <Link
              href="/recon"
              className="font-medium underline underline-offset-2 hover:text-amber-900 dark:hover:text-amber-50"
            >
              Recon
            </Link>{" "}
            tools). This dashboard issues a single{" "}
            <code className="rounded bg-black/10 px-1 dark:bg-black/35">POST /api/v1/scan</code> —
            LangGraph human-in-the-loop for Nmap is not completed here, so expect{" "}
            <strong className="font-medium">403</strong> unless your environment allows a dev bypass.
          </p>
          <label className="flex cursor-pointer items-start gap-3 text-xs text-muted-foreground">
            <input
              id={nmapInputId}
              type="checkbox"
              checked={runNmap}
              onChange={(e) => {
                const on = e.target.checked;
                setRunNmap(on);
                if (on) setNmapPanelOpen(true);
              }}
              className="mt-1 size-4 rounded border-border bg-background accent-foreground"
            />
            <span>
              Include Nmap in this request (I confirm authorization is on record for this{" "}
              target).
            </span>
          </label>
          {runNmap ? (
            <p className="text-[11px] leading-snug text-muted-foreground">
              For dedicated Nmap controls use{" "}
              <Link
                href="/recon"
                className="font-medium text-foreground underline underline-offset-2"
              >
                Recon
              </Link>
              . Leave unchecked for normal passive OSINT.
            </p>
          ) : null}
        </div>
      </details>
    );

    const scanOptionsFields = (nmapInputId: string) => (
      <>
        <div>
          <label htmlFor="target" className="mb-1.5 block text-xs font-medium text-muted-foreground">
            Target
          </label>
          <Input
            id="target"
            name="target"
            placeholder="URL, domain, host, or entity label"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            autoComplete="off"
            className="rounded-xl bg-background dark:bg-zinc-950/80"
          />
        </div>
        <div>
          <label htmlFor="goal-thread" className="mb-1.5 block text-xs font-medium text-muted-foreground">
            Replace base goal (optional)
          </label>
          <Textarea
            id="goal-thread"
            name="goal-thread"
            placeholder="Override the investigation goal for the next run only…"
            value={goal}
            onChange={(e) => setGoal(e.target.value)}
            className="min-h-[4rem] rounded-xl bg-background dark:bg-zinc-950/80"
          />
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label
              htmlFor="investigation-profile"
              className="mb-1.5 block text-xs font-medium text-muted-foreground"
            >
              Investigation profile
            </label>
            <select
              id="investigation-profile"
              value={investigationProfile}
              onChange={(e) =>
                setInvestigationProfile(e.target.value as typeof investigationProfile)
              }
              aria-label="Investigation profile"
              className="flex h-10 w-full rounded-xl border border-input bg-background px-3 text-sm text-foreground ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring dark:bg-zinc-950/80"
            >
              <option value="general">General OSINT</option>
              <option value="company">Organization / intel focus</option>
              <option value="social">Social & indexed discourse</option>
            </select>
          </div>
          <div>
            <label
              htmlFor="tavily-time-range"
              className="mb-1.5 block text-xs font-medium text-muted-foreground"
            >
              Tavily recency (optional)
            </label>
            <select
              id="tavily-time-range"
              value={tavilyTimeRange}
              onChange={(e) =>
                setTavilyTimeRange(e.target.value as typeof tavilyTimeRange)
              }
              aria-label="Tavily search time range"
              className="flex h-10 w-full rounded-xl border border-input bg-background px-3 text-sm text-foreground ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring dark:bg-zinc-950/80"
            >
              <option value="">Any</option>
              <option value="day">Past day</option>
              <option value="week">Past week</option>
              <option value="month">Past month</option>
              <option value="year">Past year</option>
            </select>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={(e) =>
              setAttachedName(e.target.files?.[0]?.name ?? null)
            }
          />
          <Button
            type="button"
            variant="secondary"
            size="sm"
            className="rounded-full gap-1.5"
            onClick={() => fileInputRef.current?.click()}
          >
            <Paperclip className="size-4" aria-hidden />
            Attach
          </Button>
          {attachedName ? (
            <span className="inline-flex items-center rounded-full border border-border bg-muted/80 px-3 py-1 text-xs font-medium">
              {attachedName}
            </span>
          ) : (
            <span className="text-[11px] text-muted-foreground">
              Optional context file (not sent in API v1 body by default).
            </span>
          )}
        </div>

        {renderNmapDisclosure(nmapInputId)}
      </>
    );

    if (hasThread) {
      return (
        <footer
          className={cn(
            "shrink-0 border-t border-border bg-background/95 py-3 backdrop-blur-md supports-[backdrop-filter]:bg-background/80 dark:border-white/10 dark:bg-zinc-950/90",
          )}
        >
          <div className="px-4 sm:px-6">
            {error && (
              <div
                role="alert"
                className="mx-auto mb-3 max-w-3xl whitespace-pre-wrap rounded-xl border border-red-500/30 bg-red-50 px-4 py-2.5 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
              >
                {error}
              </div>
            )}
            <form onSubmit={handleSubmit} className="mx-auto max-w-3xl space-y-3">
              <div className="rounded-xl border border-border/70 bg-muted/20 px-3 py-2.5 dark:bg-zinc-900/50">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                  Refocus template
                </p>
                <p className="mb-2 text-[11px] leading-snug text-muted-foreground">
                  Same as Scope on a new run: updates profile and merges a goal template into your
                  base goal (see &quot;Target &amp; scan options&quot;).
                </p>
                <div
                  className="flex flex-wrap gap-1.5"
                  role="group"
                  aria-label="Investigation focus templates"
                >
                  {CATEGORIES.map((cat) => (
                    <Button
                      key={cat}
                      type="button"
                      variant={activeCategory === cat ? "default" : "secondary"}
                      size="sm"
                      className="h-8 rounded-full border border-border px-3 text-xs"
                      onClick={() => applyCategory(cat)}
                    >
                      {cat}
                    </Button>
                  ))}
                </div>
              </div>
              <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                <span className="font-semibold text-foreground">Chat session</span>
                <span aria-hidden>·</span>
                <span className="max-w-[min(100%,28rem)] truncate font-medium text-foreground" title={target}>
                  {target}
                </span>
                {investigationProfile !== "general" && (
                  <>
                    <span aria-hidden>·</span>
                    <span className="capitalize">{investigationProfile}</span>
                  </>
                )}
                {tavilyTimeRange ? (
                  <>
                    <span aria-hidden>·</span>
                    <span>Tavily: {tavilyTimeRange}</span>
                  </>
                ) : null}
              </p>

              <div className="flex gap-2 rounded-2xl border border-border bg-card p-2 shadow-lg dark:border-white/10 dark:bg-zinc-900/80">
                <label htmlFor="follow-up" className="sr-only">
                  Follow-up prompt
                </label>
                <Textarea
                  ref={followUpRef}
                  id="follow-up"
                  name="follow-up"
                  rows={1}
                  placeholder="Ask anything else — same target, new angle…"
                  value={followUp}
                  onChange={(e) => setFollowUp(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      const form = e.currentTarget.form;
                      if (!loading && form) {
                        form.requestSubmit();
                      }
                    }
                  }}
                  className="max-h-[220px] min-h-[52px] flex-1 resize-none rounded-xl border-0 bg-transparent px-3 py-3 text-[15px] leading-snug shadow-none placeholder:text-muted-foreground focus-visible:ring-0 focus-visible:ring-offset-0"
                  autoComplete="off"
                />
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      type="submit"
                      size="icon"
                      disabled={loading || !followUp.trim()}
                      className="mt-0.5 size-11 shrink-0 rounded-xl"
                      aria-label="Send"
                    >
                      {loading ? (
                        <span className="size-5 animate-pulse rounded-full bg-muted-foreground/50" aria-hidden />
                      ) : (
                        <SendHorizontal className="size-5" aria-hidden />
                      )}
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="left" className="max-w-[200px]">
                    Send — Enter (Shift+Enter for new line)
                  </TooltipContent>
                </Tooltip>
              </div>

              <p className="text-xs text-muted-foreground">
                {footerSources > 0
                  ? `${footerSources} source${footerSources === 1 ? "" : "s"} in latest answer · each send runs the pipeline again on this target`
                  : "Each prompt runs another evidence pass on the same target."}
              </p>

              <details className="group rounded-xl border border-border/70 bg-muted/25 dark:bg-zinc-900/50">
                <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2.5 text-xs font-medium text-muted-foreground [&::-webkit-details-marker]:hidden">
                  <ChevronDown
                    className="size-4 shrink-0 opacity-70 transition group-open:rotate-180"
                    aria-hidden
                  />
                  Target &amp; scan options
                </summary>
                <div className="space-y-3 border-t border-border/50 px-3 pb-3 pt-3">
                  {scanOptionsFields(nmapId)}
                </div>
              </details>
            </form>
          </div>
        </footer>
      );
    }

    return (
      <footer
        className={cn(
          "mt-auto flex min-h-0 min-w-0 flex-1 flex-col border-t border-border bg-background/95 backdrop-blur-md supports-[backdrop-filter]:bg-background/80 dark:border-white/10 dark:bg-zinc-950/90",
        )}
      >
        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 py-3 sm:px-6">
          {error && (
            <div
              role="alert"
              className="mx-auto mb-3 max-w-3xl whitespace-pre-wrap rounded-xl border border-red-500/30 bg-red-50 px-4 py-2.5 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
            >
              {error}
            </div>
          )}
          <form
            onSubmit={handleSubmit}
            className="mx-auto max-w-3xl space-y-3 pb-[max(1rem,env(safe-area-inset-bottom,0px))]"
          >
            <div className="rounded-2xl border border-border bg-card p-3 shadow-lg sm:p-5 dark:border-white/10 dark:bg-zinc-900/70">
              <div className="space-y-6 sm:space-y-7">
                <section className="space-y-3" aria-labelledby="scope-heading">
                  <h2
                    id="scope-heading"
                    className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground"
                  >
                    Scope
                  </h2>
                  <p className="text-[11px] leading-relaxed text-muted-foreground">
                    Pick a <strong className="font-medium text-foreground">focus</strong> to set the
                    investigation profile and add a <strong className="font-medium text-foreground">goal template</strong>{" "}
                    under Objective (appended if you already typed there).
                  </p>
                  <div
                    className="flex flex-wrap gap-1.5"
                    role="group"
                    aria-label="Investigation focus templates"
                  >
                    {CATEGORIES.map((cat) => (
                      <Button
                        key={cat}
                        type="button"
                        variant={activeCategory === cat ? "default" : "secondary"}
                        size="sm"
                        className="h-8 rounded-full border border-border px-3 text-xs sm:h-9 sm:text-sm"
                        onClick={() => applyCategory(cat)}
                      >
                        {cat}
                      </Button>
                    ))}
                  </div>
                  <div>
                    <label
                      htmlFor="target"
                      className="mb-1 block text-xs font-medium text-foreground"
                    >
                      Target
                    </label>
                    <Input
                      id="target"
                      name="target"
                      placeholder="URL, domain, host, or entity label"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      autoComplete="off"
                      className="h-10 rounded-xl bg-background dark:bg-zinc-950/80"
                    />
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <label
                        htmlFor="investigation-profile-init"
                        className="mb-1.5 block text-xs font-medium text-muted-foreground"
                      >
                        Investigation profile
                      </label>
                      <select
                        id="investigation-profile-init"
                        value={investigationProfile}
                        onChange={(e) =>
                          setInvestigationProfile(e.target.value as typeof investigationProfile)
                        }
                        aria-label="Investigation profile"
                        className="flex h-10 w-full rounded-xl border border-input bg-background px-3 text-sm text-foreground ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring dark:bg-zinc-950/80"
                      >
                        <option value="general">General OSINT</option>
                        <option value="company">Organization / intel focus</option>
                        <option value="social">Social & indexed discourse</option>
                      </select>
                    </div>
                    <div>
                      <label
                        htmlFor="tavily-time-range-init"
                        className="mb-1.5 block text-xs font-medium text-muted-foreground"
                      >
                        Tavily recency (optional)
                      </label>
                      <select
                        id="tavily-time-range-init"
                        value={tavilyTimeRange}
                        onChange={(e) =>
                          setTavilyTimeRange(e.target.value as typeof tavilyTimeRange)
                        }
                        aria-label="Tavily search time range"
                        className="flex h-10 w-full rounded-xl border border-input bg-background px-3 text-sm text-foreground ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring dark:bg-zinc-950/80"
                      >
                        <option value="">Any</option>
                        <option value="day">Past day</option>
                        <option value="week">Past week</option>
                        <option value="month">Past month</option>
                        <option value="year">Past year</option>
                      </select>
                    </div>
                  </div>
                </section>

                <section className="space-y-2" aria-labelledby="objective-heading">
                  <h2
                    id="objective-heading"
                    className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground"
                  >
                    Objective
                  </h2>
                  <label htmlFor="goal" className="sr-only">
                    Investigation goal
                  </label>
                  <Textarea
                    id="goal"
                    name="goal"
                    placeholder="What should this investigation establish? State claims you want supported by evidence (not speculation)."
                    value={goal}
                    onChange={(e) => setGoal(e.target.value)}
                    className="min-h-[6.5rem] rounded-xl bg-background text-[15px] leading-snug dark:bg-zinc-950/80 sm:min-h-[7.5rem]"
                    aria-describedby="objective-hint"
                  />
                  <p id="objective-hint" className="text-[11px] text-muted-foreground">
                    This is the main question the pipeline answers; keep it specific enough to grade
                    sources against.
                  </p>
                </section>

                <section className="space-y-3" aria-labelledby="options-heading">
                  <h2
                    id="options-heading"
                    className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground"
                  >
                    Options
                  </h2>
                  <div className="flex flex-wrap items-center gap-2">
                    <input
                      ref={fileInputRef}
                      type="file"
                      className="hidden"
                      onChange={(e) =>
                        setAttachedName(e.target.files?.[0]?.name ?? null)
                      }
                    />
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      className="rounded-full gap-1.5"
                      onClick={() => fileInputRef.current?.click()}
                    >
                      <Paperclip className="size-4" aria-hidden />
                      Attach file
                    </Button>
                    {attachedName ? (
                      <span className="inline-flex items-center rounded-full border border-border bg-muted/80 px-3 py-1 text-xs font-medium">
                        {attachedName}
                      </span>
                    ) : (
                      <span className="text-[11px] text-muted-foreground">
                        Optional — for your notes; not sent in the scan request body by default.
                      </span>
                    )}
                  </div>
                  {renderNmapDisclosure(nmapId)}
                </section>

                <div className="space-y-3 border-t border-border pt-4 dark:border-white/10">
                  <p className="max-w-xl text-xs leading-relaxed text-muted-foreground">
                    <strong className="font-medium text-foreground">Run investigation</strong> starts
                    one full pass. Once results land, the thread opens above; use the follow-up field
                    there for more questions on the same target without leaving this workspace.
                  </p>
                  <div className="flex justify-end">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          type="submit"
                          disabled={loading}
                          className="min-h-11 min-w-[11rem] rounded-xl"
                        >
                          {loading ? "Running…" : "Run investigation"}
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent side="top" className="max-w-[220px]">
                        POST /api/v1/scan — target, goal, analyst_id, run_nmap,
                        investigation_profile, optional tavily_time_range
                      </TooltipContent>
                    </Tooltip>
                  </div>
                </div>
              </div>
            </div>
          </form>
        </div>
      </footer>
    );
  }

  function renderScroll() {
    return (
      <ScrollArea className="min-h-0 flex-1">
        <div
          id="main-content"
          className="mx-auto w-full max-w-3xl px-4 pb-10 pt-4 sm:px-6"
          aria-label="Investigation workspace"
        >
          <div className="space-y-8">
            {entries.map((entry) => (
              <div key={entry.id} className="space-y-4">
                <UserQueryBubble
                  target={entry.user.target}
                  message={entry.user.displayPrompt}
                  goal={entry.user.goal}
                  fileName={entry.user.fileName}
                />

                {entry.status === "error" && entry.error && (
                  <div
                    role="alert"
                    className="whitespace-pre-wrap rounded-2xl border border-red-500/30 bg-red-50 px-4 py-3 text-sm text-red-900 dark:bg-red-950/40 dark:text-red-200"
                  >
                    {entry.error}
                  </div>
                )}

                {(entry.status === "loading" || entry.assistant) && (
                  <div className="flex justify-start">
                    <div className="w-full min-w-0 max-w-[min(100%,48rem)] space-y-2">
                      {entry.status === "loading" && (
                        <p className="flex items-center gap-2 text-xs text-muted-foreground">
                          <span
                            className="inline-block size-1.5 animate-pulse rounded-full bg-emerald-500"
                            aria-hidden
                          />
                          Reviewing sources · correlating evidence · drafting narrative…
                        </p>
                      )}
                      <IntelThreadAnswerPanel
                        report={
                          entry.assistant?.report ?? emptyIntelReport()
                        }
                        loading={entry.status === "loading"}
                        parseWarning={
                          entry.assistant?.parseWarning ?? false
                        }
                        rawForDeveloper={entry.assistant?.raw ?? {}}
                      />
                    </div>
                  </div>
                )}
              </div>
            ))}
            <div ref={threadEndRef} className="h-1 shrink-0" aria-hidden />
          </div>
        </div>
      </ScrollArea>
    );
  }

  return (
    <div className="flex min-h-screen bg-background">
      <aside
        className="hidden h-svh max-h-svh w-72 shrink-0 overflow-hidden border-r border-zinc-200 bg-white lg:flex lg:flex-col dark:border-white/10 dark:bg-zinc-950"
        aria-label="Workspace"
      >
        <AnalystSidebarNav
          recent={recent}
          onNew={handleNew}
          onSelectRecent={(item) => setTarget(item.target)}
        />
      </aside>

      <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden h-svh max-h-svh">
        <header className="flex shrink-0 items-center justify-between gap-3 border-b border-border bg-background px-4 py-3 lg:hidden">
          {openMobileNav}
          <div className="flex flex-1 justify-center px-2">
            <GrondLogo className="max-w-[8.5rem] justify-center [&_img]:object-center" />
          </div>
          <ThemeToggle />
        </header>

        <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
          {hasThread ? (
            <>
              {renderScroll()}
              {renderComposer()}
            </>
          ) : (
            <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
              {renderComposer()}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
