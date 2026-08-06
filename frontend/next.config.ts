import type { NextConfig } from "next";

// A reasonably strict baseline for a self-hosted app with no third-party embeds/analytics.
//
// `script-src` includes `'unsafe-inline'` rather than a per-request nonce. A nonce-based CSP
// was tried first and reverted: Next.js only stamps nonces onto pages that are *dynamically*
// rendered (confirmed against `node_modules/next/dist/docs/.../content-security-policy.md`,
// "Static vs Dynamic Rendering with CSP") — `/login` and `/signup` are statically prerendered
// here, so their hydration bootstrap scripts (`self.__next_f.push(...)`, verified in the built
// HTML) would be silently blocked by browsers under a strict nonce policy, breaking the app.
// Forcing every route into dynamic rendering just to support nonces trades away Next's static
// optimization for a benefit this app doesn't actually need: nothing here renders raw/untrusted
// HTML (no `dangerouslySetInnerHTML` anywhere in the app — verified) and there are no
// third-party scripts, so an inline-script CSP bypass has no attacker-controlled content to
// exploit. `default-src 'self'` plus the img/style/connect/frame/form restrictions below still
// block the things a same-origin app is actually exposed to (framing, exfil to other origins,
// arbitrary third-party script/object sources).
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join("; "),
  },
];

const nextConfig: NextConfig = {
  // Standalone output for a lean Docker image (see frontend/Dockerfile).
  output: "standalone",

  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
