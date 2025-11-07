// src/lib/cors.ts
import { NextRequest, NextResponse } from 'next/server';
import { env } from './env';

function allowedOrigins(): string[] {
  const allowlist = env.ORIGIN_ALLOWLIST || env.ALLOWED_ORIGINS;
  if (allowlist) {
    return allowlist
      .split(',')
      .map((s: string) => s.trim())
      .filter(Boolean);
  }
  return env.FRONTEND_ORIGIN ? [env.FRONTEND_ORIGIN] : [];
}

export function validateRequestOrigin(req: NextRequest) {
  const origin = req.headers.get('origin') || '';
  const list = allowedOrigins();
  const ok = !origin || list.length === 0 || list.includes(origin);
  if (!ok) {
    const res = NextResponse.json({ error: 'cors_origin_not_allowed' }, { status: 400 });
    res.headers.set('Vary', 'Origin');
    return { ok, response: res, res, evaluation: { origin } };
  }
  return { ok, evaluation: { origin } };
}

/**
 * guardOrigin — alias kept for compatibility with existing routes
 * Same behavior/return shape as validateRequestOrigin.
 */
export const guardOrigin = validateRequestOrigin;

export function withCORS(req: NextRequest, res: NextResponse) {
  const nr = res;
  const origin = req.headers.get('origin') || '';
  const list = allowedOrigins();
  const allow = origin && (list.length === 0 || list.includes(origin)) ? origin : '';
  if (allow) {
    nr.headers.set('Access-Control-Allow-Origin', allow);
    nr.headers.set('Access-Control-Allow-Credentials', 'true');
  } else {
    nr.headers.delete('Access-Control-Allow-Origin');
    nr.headers.delete('Access-Control-Allow-Credentials');
  }
  nr.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  nr.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  const varyValues = new Set(
    (nr.headers.get('Vary') || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean),
  );
  varyValues.add('Origin');
  varyValues.add('Access-Control-Request-Headers');
  nr.headers.set('Vary', Array.from(varyValues).join(', '));
  return nr;
}

export async function handleCorsOptions(req: NextRequest) {
  const res = new NextResponse(null, { status: 204 });
  return withCORS(req, res);
}

export function resolveAllowedRequestDomain(req: NextRequest): string {
  const host = new URL(req.url).host;
  return env.SIWS_DOMAIN ?? host;
}
