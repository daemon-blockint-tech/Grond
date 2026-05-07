"use client";

import * as React from "react";
import { ChevronDown, ExternalLink, Paperclip } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import type { IntelReport } from "@/lib/intel-report";
import {
  collectUniqueUrls,
  countFindings,
  filterImageUrls,
  sourceCount,
} from "@/lib/intel-report";

type ThreadTab = "answer" | "links" | "images";

function Chip({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center rounded-full border border-border bg-muted/80 px-2.5 py-0.5 text-xs font-medium text-muted-foreground ${className}`}
    >
      {children}
    </span>
  );
}

function InlineSourceLink({
  href,
  children,
}: {
  href?: string;
  children?: React.ReactNode;
}) {
  if (!href || !/^https?:\/\//i.test(href)) {
    return (
      <a href={href} className="text-primary underline underline-offset-2">
        {children}
      </a>
    );
  }
  const label =
    typeof children === "string" && children.length > 32
      ? `${children.slice(0, 28)}…`
      : children;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="mx-0.5 inline-flex max-w-[14rem] items-center gap-1 rounded-full border border-white/15 bg-white/10 px-2 py-0.5 text-xs font-medium text-zinc-100 transition hover:bg-white/15 dark:border-white/10 dark:bg-zinc-800/90"
    >
      <span className="truncate">{label || "Source"}</span>
      <ExternalLink className="size-3 shrink-0 opacity-70" aria-hidden />
    </a>
  );
}

const markdownComponents = {
  a: InlineSourceLink,
  p: ({ children }: { children?: React.ReactNode }) => (
    <p className="mb-3 text-[15px] leading-relaxed text-zinc-200 last:mb-0 dark:text-zinc-200">
      {children}
    </p>
  ),
  ul: ({ children }: { children?: React.ReactNode }) => (
    <ul className="mb-3 list-disc space-y-1.5 pl-5 text-[15px] text-zinc-200 dark:text-zinc-200">
      {children}
    </ul>
  ),
  ol: ({ children }: { children?: React.ReactNode }) => (
    <ol className="mb-3 list-decimal space-y-1.5 pl-5 text-[15px] text-zinc-200 dark:text-zinc-200">
      {children}
    </ol>
  ),
  li: ({ children }: { children?: React.ReactNode }) => (
    <li className="leading-relaxed">{children}</li>
  ),
  h1: ({ children }: { children?: React.ReactNode }) => (
    <h3 className="mb-2 mt-4 text-lg font-semibold text-zinc-50 first:mt-0">{children}</h3>
  ),
  h2: ({ children }: { children?: React.ReactNode }) => (
    <h3 className="mb-2 mt-4 text-base font-semibold text-zinc-50 first:mt-0">{children}</h3>
  ),
  h3: ({ children }: { children?: React.ReactNode }) => (
    <h4 className="mb-2 mt-3 text-sm font-semibold text-zinc-100">{children}</h4>
  ),
  code: ({ children, className }: { children?: React.ReactNode; className?: string }) => {
    const inline = !className;
    if (inline) {
      return (
        <code className="rounded-md bg-white/10 px-1.5 py-0.5 font-mono text-[13px] text-zinc-100">
          {children}
        </code>
      );
    }
    return (
      <code className="block overflow-x-auto rounded-lg bg-black/40 p-3 font-mono text-[13px] text-zinc-200">
        {children}
      </code>
    );
  },
  pre: ({ children }: { children?: React.ReactNode }) => (
    <pre className="mb-3 overflow-x-auto rounded-lg border border-white/10 bg-black/30 p-3 text-[13px]">
      {children}
    </pre>
  ),
  blockquote: ({ children }: { children?: React.ReactNode }) => (
    <blockquote className="mb-3 border-l-2 border-zinc-500 pl-4 text-zinc-400 italic">
      {children}
    </blockquote>
  ),
  strong: ({ children }: { children?: React.ReactNode }) => (
    <strong className="font-semibold text-zinc-50">{children}</strong>
  ),
  img: (props: React.ImgHTMLAttributes<HTMLImageElement>) => {
    const { src, alt, title, width, height, className } = props;
    if (typeof src !== "string" || !src.trim()) return null;
    return (
      // eslint-disable-next-line @next/next/no-img-element -- markdown evidence URLs are external/dynamic
      <img
        src={src.trim()}
        alt={alt ?? ""}
        title={title}
        width={width}
        height={height}
        className={
          className
            ? `my-2 max-h-64 max-w-full rounded-lg border border-white/10 object-contain ${className}`
            : "my-2 max-h-64 max-w-full rounded-lg border border-white/10 object-contain"
        }
        loading="lazy"
      />
    );
  },
};

function Markdown({ text }: { text: string }) {
  if (!text.trim()) return null;
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
      {text}
    </ReactMarkdown>
  );
}

export function IntelThreadAnswerPanel({
  report,
  loading,
  parseWarning,
  rawForDeveloper,
}: {
  report: IntelReport;
  loading: boolean;
  parseWarning: boolean;
  rawForDeveloper: unknown;
}) {
  const [tab, setTab] = React.useState<ThreadTab>("answer");

  const urls = collectUniqueUrls(report);
  const images = filterImageUrls(urls);
  const findingsN = countFindings(report);
  const sourcesN = sourceCount(report);

  const tabs: { id: ThreadTab; label: string }[] = [
    { id: "answer", label: "Answer" },
    { id: "links", label: "Links" },
    { id: "images", label: images.length === 0 ? "Images" : `Images (${images.length})` },
  ];

  return (
    <div className="rounded-2xl border border-white/10 bg-card/40 shadow-lg backdrop-blur-md dark:bg-zinc-900/50">
      <div className="flex flex-wrap items-center gap-2 border-b border-white/10 px-3 py-2">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`rounded-full px-3 py-1.5 text-sm font-medium transition ${
              tab === t.id
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:bg-muted/80 hover:text-foreground"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="min-h-[12rem] px-4 py-4 sm:px-5 sm:py-5">
        {loading && (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <span
              className="inline-block size-3.5 animate-spin rounded-full border-2 border-muted border-t-foreground"
              aria-hidden
            />
            Reviewing sources and synthesizing…
          </p>
        )}

        {!loading && parseWarning && (
          <p className="mb-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
            Some fields did not match the expected schema; showing best-effort structured view.
          </p>
        )}

        {!loading && tab === "answer" && (
          <div className="space-y-6">
            <div className="flex flex-wrap gap-2">
              {report.overall_risk && (
                <Chip>
                  Risk:{" "}
                  <span className="capitalize text-foreground">{report.overall_risk}</span>
                </Chip>
              )}
              {typeof report.avg_confidence === "number" && (
                <Chip>Avg confidence: {(report.avg_confidence * 100).toFixed(0)}%</Chip>
              )}
              {typeof report.pending_review_count === "number" && (
                <Chip>Pending review: {report.pending_review_count}</Chip>
              )}
              {typeof report.conflict_count === "number" && report.conflict_count > 0 && (
                <Chip>Conflicts: {report.conflict_count}</Chip>
              )}
            </div>

            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Executive summary
              </h3>
              <div className="text-foreground">
                <Markdown text={report.executive_summary || ""} />
              </div>
              {!report.executive_summary?.trim() && (
                <p className="text-sm text-muted-foreground">No executive summary in this response.</p>
              )}
            </div>

            {(report.key_takeaways?.length ?? 0) > 0 && (
              <div>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Key takeaways
                </h3>
                <ul className="list-disc space-y-1.5 pl-5 text-[15px] text-zinc-200 dark:text-zinc-200">
                  {report.key_takeaways!.map((item, i) => (
                    <li key={i} className="leading-relaxed">
                      <Markdown text={item} />
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {(report.sections ?? []).map((section, si) => (
              <div key={si}>
                <h3 className="mb-1 text-base font-semibold text-zinc-50">{section.heading}</h3>
                {section.summary?.trim() ? (
                  <div className="mb-3 text-muted-foreground">
                    <Markdown text={section.summary} />
                  </div>
                ) : null}
                <div className="space-y-4">
                  {(section.findings ?? []).map((f, fi) => (
                    <div
                      key={f.id ?? fi}
                      className="rounded-xl border border-white/10 bg-black/20 px-3 py-3 dark:bg-black/25"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium text-zinc-100">{f.title}</span>
                        {f.risk_level && <Chip className="capitalize">{f.risk_level}</Chip>}
                        {typeof f.confidence === "number" && (
                          <Chip>{(f.confidence * 100).toFixed(0)}% confidence</Chip>
                        )}
                        {f.requires_review && <Chip className="border-amber-500/40">Review</Chip>}
                        {f.conflict_flag && <Chip className="border-red-500/40">Conflict</Chip>}
                      </div>
                      <div className="mt-2 text-[15px] leading-relaxed text-zinc-300">
                        <Markdown text={f.description || ""} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}

            {report.disclaimer?.trim() ? (
              <p className="text-xs leading-relaxed text-muted-foreground">{report.disclaimer}</p>
            ) : null}
          </div>
        )}

        {!loading && tab === "links" && (
          <div>
            {urls.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No URLs were extracted from evidence. Links appear when provenance includes{" "}
                <code className="rounded bg-muted px-1">source_url</code> or value fields like{" "}
                <code className="rounded bg-muted px-1">url</code>.
              </p>
            ) : (
              <ul className="space-y-2">
                {urls.map((u) => (
                  <li key={u}>
                    <a
                      href={u}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 break-all text-sm text-primary hover:underline"
                    >
                      {u}
                      <ExternalLink className="size-3.5 shrink-0" aria-hidden />
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {!loading && tab === "images" && (
          <div>
            {images.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No image URLs in evidence for this run. This tab fills when links point to common
                image formats or known media hosts.
              </p>
            ) : (
              <div className="grid gap-3 sm:grid-cols-2">
                {images
                  .filter((s) => s.trim().length > 0)
                  .map((src) => (
                  <a
                    key={src}
                    href={src}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="overflow-hidden rounded-xl border border-white/10 bg-muted/30"
                  >
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img src={src} alt="Evidence preview" className="max-h-48 w-full object-cover" loading="lazy" />
                  </a>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-white/10 px-4 py-3 text-xs text-muted-foreground">
        {loading ? (
          <span>Preparing source summary…</span>
        ) : (
          <>
            <span>
              {sourcesN} source{sourcesN === 1 ? "" : "s"} · {findingsN} finding
              {findingsN === 1 ? "" : "s"}
            </span>
            <span className="font-mono text-[10px] opacity-70">
              {report.session_id ? `Session ${report.session_id.slice(0, 8)}…` : ""}
            </span>
          </>
        )}
      </div>

      <details className="group border-t border-white/10 bg-muted/20 dark:bg-black/20">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-4 py-3 text-xs font-medium text-muted-foreground [&::-webkit-details-marker]:hidden">
          Developer
          <ChevronDown className="size-4 shrink-0 transition group-open:rotate-180" aria-hidden />
        </summary>
        <pre className="max-h-64 overflow-auto border-t border-white/10 p-3 font-mono text-[11px] leading-relaxed text-muted-foreground">
          {JSON.stringify(rawForDeveloper, null, 2)}
        </pre>
      </details>
    </div>
  );
}

export function UserQueryBubble({
  target,
  goal,
  message,
  fileName,
}: {
  target: string;
  /** Full goal sent to API (optional if `message` is used) */
  goal?: string;
  /** Short prompt shown in the bubble (Perplexity-style turn text) */
  message?: string;
  fileName?: string | null;
}) {
  const text = (message ?? goal ?? "").trim();
  return (
    <div className="flex justify-end">
      <div className="max-w-[min(100%,36rem)] rounded-[1.25rem] rounded-br-md border border-primary/25 bg-primary px-4 py-3 text-primary-foreground shadow-md">
        <p className="whitespace-pre-wrap text-[15px] leading-relaxed">{text}</p>
        <p className="mt-2 text-xs opacity-80">Target · {target}</p>
        {fileName ? (
          <div className="mt-3">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-primary-foreground/25 bg-primary-foreground/10 px-3 py-1 text-xs font-medium">
              <Paperclip className="size-3.5 opacity-80" aria-hidden />
              {fileName}
            </span>
          </div>
        ) : null}
      </div>
    </div>
  );
}
