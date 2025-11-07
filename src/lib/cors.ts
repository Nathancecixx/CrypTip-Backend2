import type { NextRequest } from 'next/server';

import { env } from '@/src/lib/env';

const DEFAULT_ALLOWED_ORIGINS = ['http://localhost:3000'];

const allowedOrigins = new Set(
  [env.FRONTEND_ORIGIN, ...DEFAULT_ALLOWED_ORIGINS]
    .filter(Boolean)
    .map(normalizeOrigin)
    .filter((origin): origin is string => Boolean(origin)),
);

const ALLOW_METHODS = 'GET,POST,PUT,PATCH,DELETE,OPTIONS';
const ALLOW_HEADERS =
  'Authorization, Content-Type, X-Requested-With, X-CSRF-Token, X-402-Signature, X-Idempotency-Key, Accept';

type RequestLike = Request | NextRequest;

type CorsEvaluation = {
  origin: string | null;
  allowed: boolean;
};

export function withCORS<T extends Response>(response: T, request?: RequestLike | null): T {
  const evaluation = evaluateRequest(request);

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
  const evaluation = evaluateRequest(request);

  if (!evaluation.allowed) {
    const forbidden = new Response(null, { status: 403 });
    return withCORS(forbidden, request);
  }

  const preflight = new Response(null, { status: 204 });
  return withCORS(preflight, request);
}

function evaluateRequest(request?: RequestLike | null): CorsEvaluation {
  if (!request) {
    return { origin: null, allowed: true };
  }

  const originHeader = request.headers.get('origin');
  if (!originHeader) {
    return { origin: null, allowed: true };
  }

  const normalized = normalizeOrigin(originHeader);
  if (!normalized) {
    return { origin: null, allowed: false };
  }

  if (allowedOrigins.has(normalized)) {
    return { origin: normalized, allowed: true };
  }

  return { origin: normalized, allowed: false };
}

function normalizeOrigin(origin: string | undefined | null): string | null {
  if (!origin) return null;

  try {
    const url = new URL(origin);
    return url.origin;
  } catch {
    return null;
  }
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
