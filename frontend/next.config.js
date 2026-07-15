/** @type {import('next').NextConfig} */
const API = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    // Proxy /api/* and /evidence-img/* to the FastAPI backend (one browser origin).
    // /evidence/* stays a Next page route (the Evidence section).
    return [
      { source: "/api/:path*", destination: `${API}/api/:path*` },
      { source: "/evidence-img/:path*", destination: `${API}/evidence-img/:path*` },
    ];
  },
};

module.exports = nextConfig;
