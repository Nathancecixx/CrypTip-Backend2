// src/lib/cors.ts
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

/** Comma-separated list of origins or patterns like https://*.vercel.app */
function allowedOrigins(): string[] {
  const raw = (process.env.ALLOWED_ORIGINS || process.env.FRONTEND_ORIGIN || '').trim();
  return raw ? raw.split(',').map(s => s.trim()).filter(Boolean) : [];
}

function parseUrl(u: string) {
  try { return new URL(u); } catch { return null; }
}

function isWildcardHost(host: string) {
  return host.startsWith('*.') && host.length > 2;
}

function hostMatchesWildcard(host: string, patternHost: string) {
  // patternHost like "*.vercel.app" => match "foo.vercel.app", not "vercel.app"
  const suffix = patternHost.slice(1); // ".vercel.app"
  return host.endsWith(suffix) && host.split('.').length > suffix.split('.').length;
}

function originAllowed(origin: string): boolean {
  if (!origin) return true; // allow server-to-server/no-origin
  const rules = allowedOrigins();
  if (rules.length === 0) return true; // open if not configured
  const o = parseUrl(origin);
  if (!o) return false;

  for (const rule of rules) {
    const r = parseUrl(rule);
    if (r) {
      // Exact or wildcard host match, and protocol must match if provided
      if (r.protocol && r.protocol !== o.protocol) continue;
      if (isWildcardHost(r.hostname)) {
        if (hostMatchesWildcard(o.hostname, r.hostname)) return true;
      } else if (o.hostname === r.hostname) {
        // If rule supplied a port or full origin, also check port/path authority
        if (!r.port || r.port === o.port) return true;
      }
    } else {
      // Support bare hosts like "cryptip.org"
      if (origin.includes(rule)) return true;
    }
  }
  return false;
}

function applyCORS(req: NextRequest, res: NextResponse): NextResponse {
  const origin = req.headers.get('origin') || '';
  res.headers.set('Vary', ['Origin', 'Access-Control-Request-Headers'].join(', '));

  if (origin && originAllowed(origin)) {
    res.headers.set('Access-Control-Allow-Origin', origin);
    res.headers.set('Access-Control-Allow-Credentials', 'true');
  }
  return res;
}

export function withCORS(req: NextRequest, res: NextResponse): NextResponse {
  return applyCORS(req, res);
}

export function handleCorsOptions(req: NextRequest): NextResponse {
  const res = new NextResponse(null, { status: 204 });
  const reqHeaders = req.headers.get('access-control-request-headers');
  res.headers.set('Access-Control-Max-Age', '86400');
  res.headers.set('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.headers.set('Access-Control-Allow-Headers', reqHeaders || 'content-type, authorization, x-requested-with');
  return applyCORS(req, res);
}

/** Derive the domain to embed inside SIWS message when SIWS_DOMAIN is not pinned. */
export function resolveAllowedRequestDomain(req: NextRequest): string {
  const origin = req.headers.get('origin');
  if (origin) {
    const u = parseUrl(origin);
    if (u?.hostname) return u.hostname;
  }
  const host = req.headers.get('host') || '';
  return host.split(':')[0] || 'cryptip.org';
}

/** Validate browser Origin and (if not allowed) pre-build a 400 JSON response. */
export function validateRequestOrigin(req: NextRequest): {
  ok: boolean;
  response?: NextResponse;
  evaluation: { origin: string };
} {
  const origin = req.headers.get('origin') || '';
  if (!origin) return { ok: true, evaluation: { origin } }; // server-to-server/no-origin
  if (originAllowed(origin)) return { ok: true, evaluation: { origin } };

  const res = new NextResponse(
    JSON.stringify({ error: 'cors_origin_not_allowed', origin }),
    { status: 400, headers: { 'Content-Type': 'application/json' } },
  );
  return { ok: false, response: applyCORS(req, res), evaluation: { origin } };
}
