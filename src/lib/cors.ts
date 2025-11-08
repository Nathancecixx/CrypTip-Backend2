// src/lib/cors.ts
import { NextRequest, NextResponse } from 'next/server';
import { env } from './env';

function extractHostname(input?: string | null): string | null {
  if (!input) return null;
  try {
    return new URL(input).hostname;
  } catch {
    try {
      return new URL(`https://${input}`).hostname;
    } catch {
      const withoutProtocol = input.replace(/^[^:\/]+:\/\//, '');
      const hostOnly = withoutProtocol.split('/')[0] ?? '';
      if (!hostOnly) return null;
      return hostOnly.split(':')[0] || null;
    }
  }
}

const ALLOW_METHODS = 'GET,POST,OPTIONS';
const ALLOW_HEADERS = 'content-type, authorization';

function parseOrigins(value?: string | null): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);
}

const DEFAULT_ALLOWED_ORIGINS = [
  'https://cryptip.org',
  'https://staging.cryptip.org',
];

function allowedOrigins(): string[] {
  const results: string[] = [];
  const seen = new Set<string>();
  const push = (value: string) => {
    if (!seen.has(value)) {
      seen.add(value);
      results.push(value);
    }
  };

  for (const origin of parseOrigins(env.ORIGIN_ALLOWLIST)) push(origin);
  for (const origin of env.ALLOWED_ORIGINS_LIST ?? []) push(origin);

  if (results.length === 0) {
    for (const origin of DEFAULT_ALLOWED_ORIGINS) push(origin);
  }

  return results;
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
  const varyValues = new Set(
    (nr.headers.get('Vary') || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean),
  );
  varyValues.add('Origin');
  if (req.method === 'OPTIONS') {
    nr.headers.set('Access-Control-Allow-Methods', ALLOW_METHODS);
    nr.headers.set('Access-Control-Allow-Headers', ALLOW_HEADERS);
  }
  nr.headers.set('Vary', Array.from(varyValues).join(', '));
  return nr;
}

export async function handleCorsOptions(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) {
    return withCORS(req, validation.response);
  }

  const res = new NextResponse(null, { status: 204 });
  return withCORS(req, res);
}

export function resolveAllowedRequestDomain(req: NextRequest): string {
  const originHost = extractHostname(req.headers.get('origin'));
  if (originHost) return originHost;

  const frontendHost = extractHostname(env.FRONTEND_ORIGIN);
  if (frontendHost) return frontendHost;

  const siwsHost = extractHostname(env.SIWS_DOMAIN);
  if (siwsHost) return siwsHost;

  return new URL(req.url).hostname;
}
