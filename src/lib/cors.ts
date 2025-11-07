// src/lib/cors.ts
import { NextRequest, NextResponse } from 'next/server';
import { env } from './env';

function allowedOrigins(): string[] {
  if (env.ALLOWED_ORIGINS) {
    return env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean);
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
    return { ok, response: res, evaluation: { origin } };
  }
  return { ok, evaluation: { origin } };
}

/**
 * guardOrigin — alias kept for compatibility with existing routes
 * Same behavior/return shape as validateRequestOrigin.
 */
export const guardOrigin = validateRequestOrigin;

export function withCORS(req: NextRequest, res: Response | NextResponse) {
  const nr = 'cookies' in res ? (res as NextResponse) : NextResponse.from(res as Response);
  const origin = req.headers.get('origin') || '';
  const list = allowedOrigins();
  const allow = origin && (list.length === 0 || list.includes(origin)) ? origin : '';
  if (allow) nr.headers.set('Access-Control-Allow-Origin', allow);
  nr.headers.set('Access-Control-Allow-Credentials', 'true');
  nr.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  nr.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  nr.headers.append('Vary', 'Origin');
  nr.headers.append('Vary', 'Access-Control-Request-Headers');
  return nr;
}

export async function handleCorsOptions(req: NextRequest) {
  const res = new Response(null, { status: 204 });
  return withCORS(req, res);
}

export function resolveAllowedRequestDomain(req: NextRequest): string {
  const host = new URL(req.url).host;
  return env.SIWS_DOMAIN ?? host;
}
