import type { NextRequest } from 'next/server';

import { env } from '@/src/lib/env';

const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'https://cryptip.org',
  'https://www.cryptip.org',
  'https://cryptip-frontend.vercel.app',
  'https://cryptip-frontend2.vercel.app',
];

const ALLOW_METHODS = 'GET,POST,PUT,PATCH,DELETE,OPTIONS';
const ALLOW_HEADERS =
  'Authorization, Content-Type, X-Requested-With, X-CSRF-Token, X-402-Signature, X-Idempotency-Key, Accept';

type RequestLike = Request | NextRequest;

type CorsEvaluation = {
  origin: string | null;
  originUrl: URL | null;
  allowed: boolean;
};

type OriginMatcher = (originUrl: URL) => boolean;

const allowedOriginMatchers = buildAllowedOriginMatchers();

export function withCORS<T extends Response>(
  response: T,
  requestOrEvaluation?: RequestLike | CorsEvaluation | null,
): T {
  const evaluation = resolveEvaluation(requestOrEvaluation);

  appendVaryHeader(response.headers, 'Origin');

  if (evaluation.allowed) {
    if (evaluation.origin) {
      response.headers.set('Access-Control-Allow-Origin', evaluation.origin);
    }
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    response.headers.set('Access-Control-Allow-Methods', ALLOW_METHODS);
    response.headers.set('Access-Control-Allow-Headers', ALLOW_HEADERS);
  }

  return response;
}

export function handleCorsOptions(request: RequestLike): Response {
  const validation = validateRequestOrigin(request);
  if (!validation.ok) {
    return validation.response;
  }

  const preflight = new Response(null, { status: 204 });
  return withCORS(preflight, validation.evaluation);
}

export function validateRequestOrigin(request: RequestLike):
  | { ok: true; evaluation: CorsEvaluation }
  | { ok: false; response: Response } {
  const evaluation = evaluateRequest(request);

  if (!evaluation.allowed) {
    const rejection = Response.json({ error: 'origin_not_allowed' }, { status: 400 });
    return { ok: false, response: withCORS(rejection, evaluation) };
  }

  return { ok: true, evaluation };
}

function resolveEvaluation(requestOrEvaluation?: RequestLike | CorsEvaluation | null): CorsEvaluation {
  if (isCorsEvaluation(requestOrEvaluation)) {
    return requestOrEvaluation;
  }

  return evaluateRequest(requestOrEvaluation ?? null);
}

function evaluateRequest(request?: RequestLike | null): CorsEvaluation {
  if (!request) {
    return { origin: null, originUrl: null, allowed: true };
  }

  const originHeader = request.headers.get('origin');
  if (!originHeader) {
    return { origin: null, originUrl: null, allowed: true };
  }

  let originUrl: URL;
  try {
    originUrl = new URL(originHeader);
  } catch {
    return { origin: originHeader, originUrl: null, allowed: false };
  }

  if (allowedOriginMatchers.some((matcher) => matcher(originUrl))) {
    return { origin: originHeader, originUrl, allowed: true };
  }

  return { origin: originHeader, originUrl, allowed: false };
}

function buildAllowedOriginMatchers(): OriginMatcher[] {
  const allowlist = new Set(
    [
      ...DEFAULT_ALLOWED_ORIGINS,
      env.FRONTEND_ORIGIN,
      ...parseAllowlist(env.ORIGIN_ALLOWLIST),
    ]
      .map((value) => value?.trim())
      .filter((value): value is string => Boolean(value)),
  );

  const matchers: OriginMatcher[] = [];
  for (const entry of allowlist) {
    const matcher = createOriginMatcher(entry);
    if (matcher) {
      matchers.push(matcher);
    }
  }
  return matchers;
}

function createOriginMatcher(entry: string): OriginMatcher | null {
  let scheme: string | null = null;
  let hostPattern = entry;

  if (entry.includes('://')) {
    try {
      const url = new URL(entry);
      scheme = url.protocol;
      hostPattern = url.host;
    } catch {
      return null;
    }
  }

  const hostRegex = wildcardToRegExp(hostPattern.toLowerCase());

  return (originUrl: URL) => {
    if (scheme && originUrl.protocol !== scheme) {
      return false;
    }
    return hostRegex.test(originUrl.host.toLowerCase());
  };
}

function wildcardToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[-/\\^$+?.()|[\]{}]/g, '\\$&');
  const regex = `^${escaped.replace(/\\\*/g, '.*')}$`;
  return new RegExp(regex);
}

function parseAllowlist(raw?: string): string[] {
  if (!raw) return [];
  return raw
    .split(/[,\s]+/)
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
}

function isCorsEvaluation(value: unknown): value is CorsEvaluation {
  return (
    typeof value === 'object' &&
    value !== null &&
    'allowed' in value &&
    'origin' in value &&
    'originUrl' in value
  );
}

function appendVaryHeader(headers: Headers, value: string) {
  const existing = headers.get('Vary');
  if (!existing) {
    headers.set('Vary', value);
    return;
  }

  const parts = existing.split(',').map((part) => part.trim().toLowerCase());
  if (parts.includes(value.toLowerCase())) {
    return;
  }

  headers.set('Vary', `${existing}, ${value}`);
}
