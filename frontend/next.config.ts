import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  // Pin the root to frontend/ so stray lockfiles in parent folders are ignored.
  outputFileTracingRoot: path.join(__dirname),
  // Hide the floating Next.js dev-tools "N" button; it only appears in `next dev`.
  devIndicators: false,
};

export default nextConfig;
