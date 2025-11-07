import { NextRequest, NextResponse } from 'next/server';
import { env } from '@/src/lib/env';

/**
 * Comma-separated list in ORIGIN_ALLOWLIST (optional), plus FRONTEND_ORIGIN (required).
 * Supports wildcards like https://*.vercel.app and https://crytip-frontend2-*.vercel.app
 */
function getAllowlist(): string[] {
  const list = (env.ORIGIN_ALLOWLIST ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  if (env.FRONTEND_ORIGIN && !list.includes(env.FRONTEND_ORIGIN)) {
    list.push(env.FRONTEND_ORIGIN);
  }
  return list;
}

function originMatchesPattern(origin: string, pattern: string): boolean {
  try {
    const o = new URL(origin);
    const p = new URL(pattern.replace('*.', 'WILDCARD.'));
    if (o.protocol !== p.protocol) return false;

    // wildcard subdomain matching
    const ph = p.hostname;
    if (ph.startsWith('WILDCARD.')) {
      const bare = ph.replace('WILDCARD.', '');
      return o.hostname === bare || o.hostname.endsWith('.' + bare);
    }
    return o.hostname === p.hostname && (o.port || defaultPort(o)) === (p.port || defaultPort(p));
  } catch {
    return false;
  }
}

function defaultPort(u: URL) {
  return u.protocol === 'https:' ? '443' : u.protocol === 'http:' ? '80' : '';
}

function isAllowedOrigin(origin: string | null): boolean {
  if (!origin) return false;
  const allow = getAllowlist();
  return allow.some(p => p === origin || originMatchesPattern(origin, p));
}

function setCorsHeaders(res: NextResponse, origin: string) {
  res.headers.set('Access-Control-Allow-Origin', origin);
  res.headers.set('Access-Control-Allow-Credentials', 'true');
  res.headers.set('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.headers.set('Vary', 'Origin');
  return res;
}

/** Always handle OPTIONS; return 204 with headers if origin is allowed, else 403 (still with Vary header). */
export function handleCorsOptions(req: NextRequest) {
  const origin = req.headers.get('origin');
  if (isAllowedOrigin(origin)) {
    return setCorsHeaders(new NextResponse(null, { status: 204 }), origin!);
  }
  const res = new NextResponse(JSON.stringify({ error: 'origin_not_allowed', origin }), {
    status: 403,
    headers: { 'content-type': 'application/json' },
  });
  res.headers.set('Vary', 'Origin');
  return res;
}

/** Wrap any response with CORS headers when origin is allowed. */
export function withCORS(req: NextRequest, res: NextResponse) {
  const origin = req.headers.get('origin');
  if (isAllowedOrigin(origin)) {
    return setCorsHeaders(res, origin!);
  }
  // Return response as-is (browser will block if cross-site and not allowed).
  res.headers.set('Vary', 'Origin');
  return res;
}

/**
 * Validate request origin for non-OPTIONS methods. If not allowed, return a 403
 * that still includes Vary: Origin (avoids “missing allow origin” confusion).
 */
export function guardOrigin(req: NextRequest): { ok: true } | { ok: false; res: NextResponse } {
  const origin = req.headers.get('origin');
  if (req.method === 'OPTIONS') return { ok: true };
  if (isAllowedOrigin(origin)) return { ok: true };
  const res = new NextResponse(JSON.stringify({ error: 'origin_not_allowed', origin }), {
    status: 403,
    headers: { 'content-type': 'application/json' },
  });
  res.headers.set('Vary', 'Origin');
  return { ok: false, res };
}
