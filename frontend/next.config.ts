import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  // Pin the root to frontend/ so stray lockfiles in parent folders are ignored.
  outputFileTracingRoot: path.join(__dirname),
};

export default nextConfig;
