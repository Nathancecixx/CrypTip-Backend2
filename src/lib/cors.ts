import type { NextRequest } from 'next/server';

import { env } from '@/src/lib/env';

const DEFAULT_ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'https://cryptip.org',
  'https://www.cryptip.org',
  'https://cryptip-frontend.vercel.app',
  'https://cryptip-frontend2.vercel.app',
  'https://crytip-frontend2.vercel.app',
];

const ALLOW_METHODS = 'GET, POST, OPTIONS';
const ALLOW_HEADERS = 'Content-Type, Authorization, X-Requested-With';

type RequestLike = Request | NextRequest;

export type CorsEvaluation = {
  origin: string | null;
  originUrl: URL | null;
  allowed: boolean;
};

type OriginMatcher = (originUrl: URL) => boolean;
type HostMatcher = (host: string) => boolean;

const allowedOriginMatchers = buildAllowedOriginMatchers();
const allowedHostMatchers = buildAllowedHostMatchers();

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

function buildAllowedHostMatchers(): HostMatcher[] {
  const allowlist = new Set(
    [
      ...DEFAULT_ALLOWED_ORIGINS,
      env.FRONTEND_ORIGIN,
      env.SIWS_DOMAIN,
      ...parseAllowlist(env.ORIGIN_ALLOWLIST),
    ]
      .map((value) => value?.trim())
      .filter((value): value is string => Boolean(value)),
  );

  const matchers: HostMatcher[] = [];
  for (const entry of allowlist) {
    const matcher = createHostMatcher(entry);
    if (matcher) {
      matchers.push(matcher);
    }
  }
  return matchers;
}

function createHostMatcher(entry: string): HostMatcher | null {
  let hostPattern = entry;

  if (entry.includes('://')) {
    try {
      const url = new URL(entry);
      hostPattern = url.host;
    } catch {
      return null;
    }
  }

  const hostRegex = wildcardToRegExp(hostPattern.toLowerCase());

  return (host: string) => hostRegex.test(host.toLowerCase());
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

export function resolveAllowedRequestDomain(
  request: RequestLike,
  evaluation?: CorsEvaluation,
): string | null {
  const resolved = evaluation ?? evaluateRequest(request);
  if (resolved.allowed && resolved.originUrl) {
    return resolved.originUrl.host;
  }

  const forwardedHost = request.headers.get('x-forwarded-host');
  const hostHeader = forwardedHost ?? request.headers.get('host');
  if (!hostHeader) {
    return null;
  }

  const host = hostHeader.split(',')[0]?.trim();
  if (!host) {
    return null;
  }

  if (allowedHostMatchers.some((matcher) => matcher(host))) {
    return host;
  }

  return null;
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
