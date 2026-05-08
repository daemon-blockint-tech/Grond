"use client";

import * as React from "react";
import { ChevronDown, ExternalLink } from "lucide-react";
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

function Chip({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={`inline-flex items-center rounded-md bg-foreground/[0.05] px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground/80 ${className}`}>
      {children}
    </span>
  );
}

function InlineSourceLink({ href, children }: { href?: string; children?: React.ReactNode }) {
  if (!href || !/^https?:\/\//i.test(href)) {
    return <a href={href} className="text-foreground/70 underline underline-offset-2 decoration-foreground/20 hover:decoration-foreground/40 transition-colors duration-200">{children}</a>;
  }
  const label = typeof children === "string" && children.length > 32 ? `${children.slice(0, 28)}…` : children;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="mx-0.5 inline-flex max-w-[14rem] items-center gap-1 rounded-md border border-white/[0.06] bg-white/[0.03] px-2 py-0.5 text-[11px] font-medium text-foreground/70 transition-colors duration-200 hover:bg-white/[0.06] hover:text-foreground/90"
    >
      <span className="truncate">{label || "Source"}</span>
      <ExternalLink className="size-2.5 stroke-[1.5] shrink-0 opacity-40" aria-hidden />
    </a>
  );
}

const markdownComponents = {
  a: InlineSourceLink,
  p: ({ children }: { children?: React.ReactNode }) => (
    <p className="mb-3 text-[13px] leading-[1.7] text-foreground/85 last:mb-0">{children}</p>
  ),
  ul: ({ children }: { children?: React.ReactNode }) => (
    <ul className="mb-3 list-disc space-y-1 pl-5 text-[13px] text-foreground/85">{children}</ul>
  ),
  ol: ({ children }: { children?: React.ReactNode }) => (
    <ol className="mb-3 list-decimal space-y-1 pl-5 text-[13px] text-foreground/85">{children}</ol>
  ),
  li: ({ children }: { children?: React.ReactNode }) => (
    <li className="leading-[1.7]">{children}</li>
  ),
  h1: ({ children }: { children?: React.ReactNode }) => (
    <h3 className="mb-2 mt-5 text-sm font-semibold tracking-[-0.01em] text-foreground first:mt-0">{children}</h3>
  ),
  h2: ({ children }: { children?: React.ReactNode }) => (
    <h3 className="mb-2 mt-5 text-[13px] font-semibold tracking-[-0.01em] text-foreground first:mt-0">{children}</h3>
  ),
  h3: ({ children }: { children?: React.ReactNode }) => (
    <h4 className="mb-2 mt-4 text-[13px] font-semibold tracking-[-0.01em] text-foreground">{children}</h4>
  ),
  code: ({ children, className }: { children?: React.ReactNode; className?: string }) => {
    const inline = !className;
    if (inline) {
      return <code className="rounded bg-white/[0.06] px-1.5 py-0.5 font-[family-name:var(--font-geist-mono)] text-[11px] text-foreground/80">{children}</code>;
    }
    return <code className="block overflow-x-auto rounded-lg bg-white/[0.03] p-3 font-[family-name:var(--font-geist-mono)] text-[11px] text-foreground/70">{children}</code>;
  },
  pre: ({ children }: { children?: React.ReactNode }) => (
    <pre className="mb-3 overflow-x-auto rounded-lg border border-white/[0.04] bg-white/[0.02] p-3 font-[family-name:var(--font-geist-mono)] text-[11px]">{children}</pre>
  ),
  blockquote: ({ children }: { children?: React.ReactNode }) => (
    <blockquote className="mb-3 border-l border-foreground/10 pl-4 text-foreground/50 italic">{children}</blockquote>
  ),
  strong: ({ children }: { children?: React.ReactNode }) => (
    <strong className="font-semibold text-foreground">{children}</strong>
  ),
  img: (props: React.ImgHTMLAttributes<HTMLImageElement>) => {
    const { src, alt, title, width, height, className } = props;
    if (typeof src !== "string" || !src.trim()) return null;
    return (
      // eslint-disable-next-line @next/next/no-img-element
      <img
        src={src.trim()}
        alt={alt ?? ""}
        title={title}
        width={width}
        height={height}
        className={
          className
            ? `my-2 max-h-64 max-w-full rounded-lg border border-white/[0.06] object-contain ${className}`
            : "my-2 max-h-64 max-w-full rounded-lg border border-white/[0.06] object-contain"
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
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden animate-scale-in">
      <div className="flex flex-wrap items-center gap-1 border-b border-white/[0.04] px-3 py-1.5">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`rounded-md px-2.5 py-1 text-[11px] font-medium tracking-wide uppercase transition-all duration-200 ${
              tab === t.id
                ? "bg-foreground/[0.08] text-foreground scale-[1.02]"
                : "text-muted-foreground/50 hover:text-foreground/70 hover:bg-white/[0.03]"
            }`}
          >
            {t.label}
          </button>
        ))}
        <span className="ml-auto text-[10px] uppercase tracking-wider text-muted-foreground/30">
          {sourcesN} src · {findingsN} finding{findingsN === 1 ? "" : "s"}
        </span>
      </div>

      <div className="min-h-[6rem] px-4 py-4 sm:px-5">
        {loading && (
          <div className="space-y-4">
            <div className="h-4 w-48 rounded bg-white/[0.03] shimmer-bg" />
            <div className="h-3 w-full rounded bg-white/[0.02] shimmer-bg" />
            <div className="h-3 w-3/4 rounded bg-white/[0.02] shimmer-bg" />
            <div className="h-3 w-5/6 rounded bg-white/[0.02] shimmer-bg" />
            <div className="flex items-center gap-2.5 pt-2 text-[11px] text-muted-foreground/40">
              <span className="inline-block size-3 animate-spin rounded-full border border-white/10 border-t-foreground/30" aria-hidden />
              <span className="uppercase tracking-wider">Synthesizing report</span>
            </div>
          </div>
        )}

        {!loading && parseWarning && (
          <p className="mb-3 animate-slide-down rounded-md border border-amber-500/15 bg-amber-500/[0.04] px-3 py-2 text-[11px] text-amber-500/80">
            Some fields did not match the expected schema — showing best-effort view.
          </p>
        )}

        {!loading && tab === "answer" && (
          <div className="space-y-6 animate-fade-in">
            <div className="flex flex-wrap gap-1.5">
              {report.overall_risk && (
                <Chip className="bg-foreground/[0.06] animate-fade-in stagger-1"><span className="capitalize text-foreground/70">{report.overall_risk}</span> risk</Chip>
              )}
              {typeof report.avg_confidence === "number" && (
                <Chip className="animate-fade-in stagger-2">{(report.avg_confidence * 100).toFixed(0)}% confidence</Chip>
              )}
              {typeof report.pending_review_count === "number" && report.pending_review_count > 0 && (
                <Chip className="animate-fade-in stagger-3">{report.pending_review_count} review</Chip>
              )}
              {typeof report.conflict_count === "number" && report.conflict_count > 0 && (
                <Chip className="text-red-400/80 animate-fade-in stagger-4">{report.conflict_count} conflict{report.conflict_count > 1 ? "s" : ""}</Chip>
              )}
            </div>

            {report.executive_summary?.trim() && (
              <div className="animate-fade-in stagger-2">
                <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground/50">
                  Summary
                </h3>
                <div><Markdown text={report.executive_summary} /></div>
              </div>
            )}

            {(report.key_takeaways?.length ?? 0) > 0 && (
              <div className="animate-fade-in stagger-3">
                <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground/50">
                  Key takeaways
                </h3>
                <ul className="list-none space-y-1.5">
                  {report.key_takeaways!.map((item, i) => (
                    <li key={i} className={`flex gap-2.5 text-[13px] leading-[1.7] text-foreground/85 animate-fade-in stagger-${Math.min(i + 1, 8)}`}>
                      <span className="mt-[7px] size-1 shrink-0 rounded-full bg-foreground/20" aria-hidden />
                      <span><Markdown text={item} /></span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {(report.sections ?? []).map((section, si) => (
              <div key={si} className={`animate-fade-in stagger-${Math.min(si + 3, 8)}`}>
                <h3 className="mb-2 text-[13px] font-semibold tracking-[-0.01em] text-foreground">{section.heading}</h3>
                {section.summary?.trim() && (
                  <div className="mb-4 text-foreground/50"><Markdown text={section.summary} /></div>
                )}
                <div className="space-y-2">
                  {(section.findings ?? []).map((f, fi) => (
                    <div
                      key={f.id ?? fi}
                      className={`rounded-lg border border-white/[0.04] bg-white/[0.02] px-3.5 py-3 transition-all duration-200 ease-out-expo hover:bg-white/[0.04] hover:border-white/[0.08] animate-fade-in-up stagger-${Math.min(fi + 1, 8)}`}
                    >
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-[13px] font-medium text-foreground/90">{f.title}</span>
                        {f.risk_level && <Chip className="capitalize">{f.risk_level}</Chip>}
                        {typeof f.confidence === "number" && <Chip>{(f.confidence * 100).toFixed(0)}%</Chip>}
                        {f.requires_review && <Chip className="text-amber-500/70">Review</Chip>}
                        {f.conflict_flag && <Chip className="text-red-400/70">Conflict</Chip>}
                      </div>
                      {f.description?.trim() && (
                        <div className="mt-2 text-[13px] leading-[1.7] text-foreground/50">
                          <Markdown text={f.description} />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}

            {report.disclaimer?.trim() && (
              <p className="text-[10px] leading-relaxed text-muted-foreground/30">{report.disclaimer}</p>
            )}
          </div>
        )}

        {!loading && tab === "links" && (
          <div className="animate-fade-in">
            {urls.length === 0 ? (
              <p className="text-[13px] text-muted-foreground/40">No URLs extracted from evidence.</p>
            ) : (
              <ul className="space-y-1.5">
                {urls.map((u, ui) => (
                  <li key={u} className={`animate-fade-in stagger-${Math.min(ui + 1, 8)}`}>
                    <a href={u} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 break-all text-[13px] text-foreground/60 underline underline-offset-2 decoration-foreground/15 hover:decoration-foreground/30 transition-colors duration-200 hover:text-foreground/80">
                      {u}
                      <ExternalLink className="size-2.5 stroke-[1.5] shrink-0 opacity-30" aria-hidden />
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {!loading && tab === "images" && (
          <div className="animate-fade-in">
            {images.length === 0 ? (
              <p className="text-[13px] text-muted-foreground/40">No image URLs in evidence for this run.</p>
            ) : (
              <div className="grid gap-2 sm:grid-cols-2">
                {images.filter((s) => s.trim().length > 0).map((src, ii) => (
                  <a key={src} href={src} target="_blank" rel="noopener noreferrer" className={`overflow-hidden rounded-lg border border-white/[0.04] bg-white/[0.02] transition-all duration-300 ease-out-expo hover:border-white/[0.1] hover:scale-[1.02] animate-scale-in stagger-${Math.min(ii + 1, 8)}`}>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img src={src} alt="Evidence preview" className="max-h-48 w-full object-cover" loading="lazy" />
                  </a>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <details className="group border-t border-white/[0.04]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3 py-2 text-[10px] font-medium uppercase tracking-wider text-muted-foreground/30 [&::-webkit-details-marker]:hidden hover:text-muted-foreground/50 transition-colors duration-200">
          <span>Developer JSON</span>
          <ChevronDown className="size-3 stroke-[1.5] shrink-0 transition-transform duration-300 spring-sm group-open:rotate-180" aria-hidden />
        </summary>
        <pre className="max-h-56 overflow-auto border-t border-white/[0.03] p-3 font-[family-name:var(--font-geist-mono)] text-[10px] leading-relaxed text-muted-foreground/40">
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
  goal?: string;
  message?: string;
  fileName?: string | null;
}) {
  const text = (message ?? goal ?? "").trim();
  return (
    <div className="flex justify-end animate-fade-in-up">
      <div className="max-w-[min(100%,34rem)] rounded-xl rounded-br-sm border border-white/[0.06] bg-foreground/[0.04] px-4 py-3 transition-all duration-200 hover:border-white/[0.1]">
        <p className="whitespace-pre-wrap text-[13px] leading-[1.7] text-foreground/90">{text}</p>
        <p className="mt-1.5 text-[10px] uppercase tracking-wider text-muted-foreground/30">Target: {target}</p>
        {fileName && (
          <p className="mt-0.5 text-[10px] text-muted-foreground/30">{fileName}</p>
        )}
      </div>
    </div>
  );
}
