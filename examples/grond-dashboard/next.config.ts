import type { NextConfig } from "next";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Absolute path to this package (`company-research-ui/`), not a parent `examples/` folder. */
const appDir = path.dirname(fileURLToPath(import.meta.url));

const nextConfig: NextConfig = {
  reactStrictMode: true,
  /**
   * When a second `package-lock.json` exists in `examples/`, Next can infer the wrong monorepo
   * root and emit or resolve `.next` inconsistently (missing `routes-manifest.json`, etc.).
   */
  outputFileTracingRoot: appDir,
  /** Avoid flaky ENOENTs on `.next/cache/webpack/*.pack.gz` when the folder is touched concurrently. */
  webpack: (config, { dev }) => {
    if (dev) {
      config.cache = false;
    }
    return config;
  },
};

export default nextConfig;
