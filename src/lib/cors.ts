import { NextRequest, NextResponse } from 'next/server';
import { env } from '@/src/lib/env';

/** ---------- Allowlist + matching ---------- */

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

function defaultPort(u: URL) {
  return u.protocol === 'https:' ? '443' : u.protocol === 'http:' ? '80' : '';
}

function originMatchesPattern(origin: string, pattern: string): boolean {
  try {
    const o = new URL(origin);
    // Support wildcard subdomains like https://*.vercel.app
    const wildcard = pattern.startsWith('http://*.') || pattern.startsWith('https://*.');
    if (wildcard) {
      const scheme = pattern.split('://')[0] + '://';
      const host = pattern.replace(/^https?:\/\/\*\./, '');
      const p = new URL(scheme + host);
      if (o.protocol !== p.protocol) return false;
      return o.hostname === p.hostname || o.hostname.endsWith('.' + p.hostname);
    }
    const p = new URL(pattern);
    return (
      o.protocol === p.protocol &&
      o.hostname === p.hostname &&
      (o.port || defaultPort(o)) === (p.port || defaultPort(p))
    );
  } catch {
    return false;
  }
}

function isAllowedOrigin(origin: string | null): boolean {
  if (!origin) return false;
  const allow = getAllowlist();
  return allow.some(p => p === origin || originMatchesPattern(origin, p));
}

/** ---------- Header helpers ---------- */

function setCorsHeaders(res: NextResponse, origin: string) {
  res.headers.set('Access-Control-Allow-Origin', origin);
  res.headers.set('Access-Control-Allow-Credentials', 'true');
  res.headers.set('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.headers.set('Vary', 'Origin');
  res.headers.append('Vary', 'Access-Control-Request-Headers');
  return res;
}

/** ---------- Primary APIs (new) ---------- */

/** Always handle OPTIONS with a 204 if origin is allowed, else 403 with Vary: Origin. */
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

/**
 * Wrap a response with CORS headers for allowed origins.
 * Back-compat OVERLOAD: accepts either (req, res) or (res, req).
 */
export function withCORS(a: NextRequest | NextResponse, b?: NextResponse | NextRequest): NextResponse {
  const isReqFirst = typeof (a as any)?.nextUrl !== 'undefined'; // crude but effective
  const req = (isReqFirst ? a : b) as NextRequest | undefined;
  const res = (isReqFirst ? b : a) as NextResponse | undefined;

  if (!req || !res) throw new Error('withCORS requires a NextRequest and NextResponse');

  const origin = req.headers.get('origin');
  if (isAllowedOrigin(origin)) return setCorsHeaders(res, origin!);
  res.headers.set('Vary', 'Origin');
  return res;
}

/** Guard for non-OPTIONS methods: 200 if allowed; else 403 with Vary: Origin. */
export function guardOrigin(req: NextRequest): { ok: true } | { ok: false; res: NextResponse } {
  if (req.method === 'OPTIONS') return { ok: true };
  const origin = req.headers.get('origin');
  if (isAllowedOrigin(origin)) return { ok: true };
  const res = new NextResponse(JSON.stringify({ error: 'origin_not_allowed', origin }), {
    status: 403,
    headers: { 'content-type': 'application/json' },
  });
  res.headers.set('Vary', 'Origin');
  return { ok: false, res };
}

/** ---------- Back-compat shims (old API many files still import) ---------- */

/**
 * Old helper many routes import. Returns { ok, response?, evaluation }.
 * evaluation is kept only for callsites that log it; not strictly required.
 */
export function validateRequestOrigin(req: NextRequest): {
  ok: boolean;
  response?: NextResponse;
  evaluation: { origin: string | null; allowed: boolean };
} {
  const origin = req.headers.get('origin');
  const allowed = isAllowedOrigin(origin);
  if (req.method === 'OPTIONS') {
    // Callers should be using handleCorsOptions() for OPTIONS, but keep this permissive.
    return { ok: true, evaluation: { origin, allowed: true } };
  }
  if (allowed) return { ok: true, evaluation: { origin, allowed: true } };

  const response = new NextResponse(JSON.stringify({ error: 'origin_not_allowed', origin }), {
    status: 403,
    headers: { 'content-type': 'application/json' },
  });
  response.headers.set('Vary', 'Origin');
  return { ok: false, response, evaluation: { origin, allowed: false } };
}

/** Old helper: pick a domain to embed in SIWS messages based on request origin. */
export function resolveAllowedRequestDomain(req: NextRequest, ev?: { origin: string | null }) {
  const origin = ev?.origin ?? req.headers.get('origin');
  if (origin && isAllowedOrigin(origin)) {
    try {
      return new URL(origin).host;
    } catch {
      /* no-op */
    }
  }
  // Fallback to configured SIWS domain
  try {
    return new URL(env.FRONTEND_ORIGIN).host;
  } catch {
    return env.SIWS_DOMAIN;
  }
}
