"use client";

import { useCallback, useEffect, useRef, useState } from "react";

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

export function MetadataCard() {
  const [target, setTarget] = useState("");
  const [engine, setEngine] = useState<"auto" | "exiftool" | "exiv2">("auto");
  const [session, setSession] = useState("");
  const [loading, setLoading] = useState(false);
  const [output, setOutput] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { setSession(crypto.randomUUID()); }, []);

  const run = useCallback(async () => {
    const file = fileInputRef.current?.files?.[0];
    if (!file) {
      setError("Select a file to analyze.");
      return;
    }
    setLoading(true);
    setError(null);
    setOutput(null);
    const analyst = ensureAnalystId();
    const base = getGrondApiBase();
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("target", target.trim() || file.name);
      formData.append("analyst_id", analyst);
      formData.append("session_id", session);
      if (engine !== "auto") formData.append("engine", engine);
      const res = await fetch(`${base}/api/v1/tools/metadata`, {
        method: "POST",
        body: formData,
      });
      const data: unknown = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(formatApiDetail(data, `Request failed (${res.status})`));
        return;
      }
      setOutput(JSON.stringify(data, null, 2));
    } catch (e) {
      setError(formatGrondReachabilityError(e, base));
    } finally {
      setLoading(false);
    }
  }, [target, engine, session]);

  return (
    <section className="mt-10 space-y-4" aria-labelledby="metadata-tool-heading">
      <h2 id="metadata-tool-heading" className="text-lg font-semibold tracking-tight text-foreground">
        File Metadata
      </h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">ExifTool / Exiv2 extraction</CardTitle>
          <CardDescription className="text-pretty">
            Endpoint{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">POST /api/v1/tools/metadata</code>.
            File metadata via ExifTool (broad formats) and/or Exiv2 (image Exif/IPTC/XMP).{" "}
            <strong>Passive</strong> — analyst must only upload material they are authorized to hold.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-0 p-0">
          <div className="space-y-3 px-6 pb-4 pt-0">
            <div className="space-y-1.5">
              <label htmlFor="metadata-file" className="text-xs font-medium text-foreground">
                File
              </label>
              <input
                ref={fileInputRef}
                id="metadata-file"
                type="file"
                className="block w-full text-sm text-muted-foreground file:mr-3 file:rounded-lg file:border file:border-border file:bg-background file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-foreground hover:file:bg-muted dark:file:border-white/10"
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <label htmlFor="metadata-target" className="text-xs font-medium text-foreground">
                  Target label
                </label>
                <Input
                  id="metadata-target"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="Investigation context (defaults to filename)"
                  autoComplete="off"
                />
              </div>
              <div className="space-y-1.5">
                <label htmlFor="metadata-engine" className="text-xs font-medium text-foreground">
                  Engine
                </label>
                <select
                  id="metadata-engine"
                  value={engine}
                  onChange={(e) => setEngine(e.target.value as typeof engine)}
                  className="flex h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 py-1 text-sm shadow-sm dark:border-white/10 dark:bg-zinc-950"
                >
                  <option value="auto">auto</option>
                  <option value="exiftool">exiftool</option>
                  <option value="exiv2">exiv2</option>
                </select>
              </div>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
              <Button
                type="button"
                onClick={() => void run()}
                disabled={loading || !session}
                className="min-h-11 w-full sm:w-auto sm:min-w-[10rem]"
              >
                {loading ? "Extracting…" : "Extract metadata"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => setSession(crypto.randomUUID())}
                className="min-h-11 w-full sm:w-auto"
              >
                New session id
              </Button>
            </div>
          </div>

          <div className="border-t border-border px-6 pb-6 pt-4 dark:border-white/10">
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Result
            </h3>
            <div
              className={cn(
                "flex min-h-[14rem] flex-col overflow-hidden rounded-xl border border-border bg-zinc-50/80 dark:border-white/10 dark:bg-zinc-950/60",
                error && "border-red-500/40 bg-red-50/50 dark:bg-red-950/25",
              )}
            >
              {loading ? (
                <div className="flex flex-1 items-center justify-center gap-3 px-4 py-8 text-sm text-muted-foreground">
                  <span className="inline-block size-2 animate-pulse rounded-full bg-emerald-500" aria-hidden />
                  Extracting metadata…
                </div>
              ) : error ? (
                <p className="flex-1 whitespace-pre-wrap p-4 text-sm text-red-900 dark:text-red-100" role="alert">
                  {error}
                </p>
              ) : output ? (
                <pre className="max-h-[min(24rem,55vh)] flex-1 overflow-auto p-4 text-xs leading-relaxed text-zinc-900 dark:text-zinc-100">
                  <code>{output}</code>
                </pre>
              ) : (
                <p className="flex flex-1 items-center justify-center px-4 py-8 text-center text-xs text-muted-foreground">
                  File metadata appears here after a successful extraction.
                </p>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
