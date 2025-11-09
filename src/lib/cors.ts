// src/lib/cors.ts
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

function allowedOrigins(): string[] {
  const multi = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  if (multi.length > 0) return multi;
  const single = (process.env.FRONTEND_ORIGIN || '').trim();
  return single ? [single] : [];
}

function isAllowed(origin: string): boolean {
  const list = allowedOrigins();
  if (!origin) return true; // same-origin/no CORS
  if (list.length === 0) return true; // wide-open (dev)
  return list.includes(origin);
}

export function resolveAllowedRequestDomain(req: NextRequest): string {
  // Derive a sensible domain from Origin or Host for inclusion in SIWS message.
  const origin = req.headers.get('origin') ?? '';
  try {
    if (origin) return new URL(origin).host;
  } catch {}
  const host = req.headers.get('host') ?? '';
  return host || 'localhost';
}

export function validateRequestOrigin(req: NextRequest) {
  const origin = req.headers.get('origin') || '';
  const ok = isAllowed(origin);
  if (!ok) {
    const res = NextResponse.json({ error: 'cors_origin_not_allowed' }, { status: 400 });
    res.headers.set('Vary', 'Origin');
    return { ok, response: res, evaluation: { origin } };
  }
  return { ok, evaluation: { origin } };
}

export function withCORS(req: NextRequest, res: NextResponse) {
  const origin = req.headers.get('origin') || '';
  const headers = res.headers;

  // Only echo back an allowed origin; do not use "*"
  if (isAllowed(origin)) {
    headers.set('Access-Control-Allow-Origin', origin);
  }

  headers.set('Access-Control-Allow-Credentials', 'true');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  headers.set('Access-Control-Max-Age', '600');
  headers.set('Vary', 'Origin');
  return res;
}

export function handleCorsOptions(req: NextRequest) {
  const res = new NextResponse(null, { status: 204 });
  return withCORS(req, res);
}
