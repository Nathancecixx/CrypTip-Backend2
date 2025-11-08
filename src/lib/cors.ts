// src/lib/cors.ts
import { NextRequest, NextResponse } from 'next/server';
import { env } from './env';

// Comma-separated allowlist, or single FRONTEND_ORIGIN fallback
function allowedOrigins(): string[] {
  if (env.ALLOWED_ORIGINS) {
    return env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean);
  }
  return env.FRONTEND_ORIGIN ? [env.FRONTEND_ORIGIN.trim()] : [];
}

function isAllowed(origin: string | null): boolean {
  const list = allowedOrigins();
  if (!origin || list.length === 0) return false;
  try {
    const host = new URL(origin).origin;
    return list.some(o => {
      try { return new URL(o).origin === host; } catch { return false; }
    });
  } catch {
    return false;
  }
}

export function resolveAllowedRequestDomain(req: NextRequest): string {
  // Map to a canonical hostname for SIWS message if needed
  const origin = req.headers.get('origin');
  if (origin) {
    try { return new URL(origin).hostname; } catch {}
  }
  // final fallback to configured domain
  return (env.SIWS_DOMAIN ?? '').trim() || 'cryptip.org';
}

export function validateRequestOrigin(req: NextRequest): { ok: boolean; response?: NextResponse } {
  const origin = req.headers.get('origin');
  const ok = isAllowed(origin);
  if (!ok) {
    const res = NextResponse.json({ error: 'cors_origin_not_allowed' }, { status: 400 });
    // Attach CORS meta anyway (don’t echo a disallowed origin)
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
