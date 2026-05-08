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

export function StegoCard() {
  const [target, setTarget] = useState("");
  const [engine, setEngine] = useState<"auto" | "stegoveritas" | "lsb">("auto");
  const [password, setPassword] = useState("");
  const [session, setSession] = useState("");
  const [loading, setLoading] = useState(false);
  const [output, setOutput] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setSession(crypto.randomUUID());
  }, []);

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
      if (password) formData.append("password", password);
      const res = await fetch(`${base}/api/v1/tools/stego`, {
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
  }, [target, engine, password, session]);

  return (
    <section className="mt-10 space-y-4" aria-labelledby="stego-tool-heading">
      <h2
        id="stego-tool-heading"
        className="text-lg font-semibold tracking-tight text-foreground"
      >
        Steganography Analysis
      </h2>
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">
            stegoVeritas / LSB detection
          </CardTitle>
          <CardDescription className="text-pretty">
            Endpoint{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">
              POST /api/v1/tools/stego
            </code>
            . Detect hidden data via stegoVeritas (multi-method: LSB, color map,
            StegHide, carving) or pure-Python LSB fallback.{" "}
            <strong>Passive</strong> — analyst must only upload material they
            are authorized to analyze. Extracted payloads require analyst review.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-0 p-0">
          <div className="space-y-3 px-6 pb-4 pt-0">
            <div className="space-y-1.5">
              <label
                htmlFor="stego-file"
                className="text-xs font-medium text-foreground"
              >
                File
              </label>
              <input
                ref={fileInputRef}
                id="stego-file"
                type="file"
                accept="image/*,.bmp,.tiff,.tif,.gif,.png,.jpg,.jpeg,.webp,.pdf"
                className="block w-full text-sm text-muted-foreground file:mr-3 file:rounded-lg file:border file:border-border file:bg-background file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-foreground hover:file:bg-muted dark:file:border-white/10"
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1.5">
                <label
                  htmlFor="stego-target"
                  className="text-xs font-medium text-foreground"
                >
                  Target label
                </label>
                <Input
                  id="stego-target"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="Investigation context"
                  autoComplete="off"
                />
              </div>
              <div className="space-y-1.5">
                <label
                  htmlFor="stego-engine"
                  className="text-xs font-medium text-foreground"
                >
                  Engine
                </label>
                <select
                  id="stego-engine"
                  value={engine}
                  onChange={(e) =>
                    setEngine(e.target.value as typeof engine)
                  }
                  className="flex h-9 w-full rounded-lg border border-zinc-200 bg-white px-3 py-1 text-sm shadow-sm dark:border-white/10 dark:bg-zinc-950"
                >
                  <option value="auto">auto</option>
                  <option value="stegoveritas">stegoVeritas</option>
                  <option value="lsb">LSB fallback</option>
                </select>
              </div>
              <div className="space-y-1.5">
                <label
                  htmlFor="stego-password"
                  className="text-xs font-medium text-foreground"
                >
                  Password{" "}
                  <span className="text-muted-foreground">(optional)</span>
                </label>
                <Input
                  id="stego-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="For encrypted stego"
                  autoComplete="off"
                />
              </div>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
              <Button
                type="button"
                onClick={() => void run()}
                disabled={loading || !session}
                className="min-h-11 w-full sm:w-auto sm:min-w-[10rem]"
              >
                {loading ? "Analyzing\u2026" : "Analyze for stego"}
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
                  <span
                    className="inline-block size-2 animate-pulse rounded-full bg-amber-500"
                    aria-hidden
                  />
                  Analyzing for steganography\u2026
                </div>
              ) : error ? (
                <p
                  className="flex-1 whitespace-pre-wrap p-4 text-sm text-red-900 dark:text-red-100"
                  role="alert"
                >
                  {error}
                </p>
              ) : output ? (
                <pre className="max-h-[min(24rem,55vh)] flex-1 overflow-auto p-4 text-xs leading-relaxed text-zinc-900 dark:text-zinc-100">
                  <code>{output}</code>
                </pre>
              ) : (
                <p className="flex flex-1 items-center justify-center px-4 py-8 text-center text-xs text-muted-foreground">
                  Steganography analysis results appear here after a successful
                  scan.
                </p>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
