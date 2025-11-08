// src/lib/cors.ts
import { NextRequest, NextResponse } from 'next/server';
import { env } from './env';

// Support comma-separated allowlist with wildcard subdomains (*.vercel.app)
function allowedOrigins(): string[] {
  if (env.ALLOWED_ORIGINS) return env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean);
  return env.FRONTEND_ORIGIN ? [env.FRONTEND_ORIGIN.trim()] : [];
}

function matchHost(host: string, patternHost: string): boolean {
  if (patternHost === host) return true;
  if (patternHost.startsWith('*.')) {
    const suffix = patternHost.slice(1); // ".example.com"
    return host === patternHost.slice(2) || host.endsWith(suffix);
  }
  return false;
}

function isAllowed(origin: string | null): boolean {
  if (!origin) return false;
  const list = allowedOrigins();
  if (list.length === 0) return false;
  let url: URL;
  try { url = new URL(origin); } catch { return false; }
  return list.some(entry => {
    try {
      const pat = new URL(entry);
      if (pat.protocol !== url.protocol) return false;
      return matchHost(url.hostname, pat.hostname);
    } catch { return false; }
  });
}

export function resolveAllowedRequestDomain(req: NextRequest): string {
  const origin = req.headers.get('origin');
  try { return origin ? new URL(origin).hostname : (env.SIWS_DOMAIN ?? 'cryptip.org'); }
  catch { return env.SIWS_DOMAIN ?? 'cryptip.org'; }
}

export function validateRequestOrigin(req: NextRequest): { ok: boolean; response?: NextResponse } {
  const origin = req.headers.get('origin');
  const ok = isAllowed(origin);
  if (!ok) {
    const res = NextResponse.json({ error: 'cors_origin_not_allowed' }, { status: 400 });
    res.headers.set('Vary', 'Origin');
    res.headers.set('Access-Control-Allow-Credentials', 'true');
    return { ok, response: res };
  }
  return { ok };
}

function applyCors(req: NextRequest, res: NextResponse) {
  const origin = req.headers.get('origin');
  if (isAllowed(origin)) {
    res.headers.set('Access-Control-Allow-Origin', origin!);
    res.headers.set('Access-Control-Allow-Credentials', 'true');
  }
  res.headers.set('Vary', 'Origin');
  return res;
}

export function withCORS(req: NextRequest, res: NextResponse) {
  return applyCors(req, res);
}

export function handleCorsOptions(req: NextRequest) {
  const res = new NextResponse(null, { status: 204 });
  const origin = req.headers.get('origin');
  if (isAllowed(origin)) {
    res.headers.set('Access-Control-Allow-Origin', origin!);
    res.headers.set('Access-Control-Allow-Credentials', 'true');
  }
  res.headers.set('Vary', 'Origin');
  res.headers.set('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.headers.set('Access-Control-Allow-Headers', 'content-type, authorization');
  res.headers.set('Access-Control-Max-Age', '86400');
  return res;
}
