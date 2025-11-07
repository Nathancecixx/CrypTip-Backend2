import type { NextRequest } from 'next/server';

import { env } from '@/src/lib/env';

type RequestLike = Pick<Request, 'headers' | 'url'> | NextRequest;

type Handler<Req extends RequestLike = Request, Ctx = unknown> = (
  req: Req,
  ctx: Ctx,
) => Response | Promise<Response>;

type CorsEvaluation = {
  allowed: boolean;
  originHeader: string | null;
};

const DEFAULT_ALLOWED_ORIGINS = ['http://localhost:3000'];

const allowedOrigins = new Set(
  [env.FRONTEND_ORIGIN, ...DEFAULT_ALLOWED_ORIGINS]
    .filter(Boolean)
    .map((origin) => normalizeOrigin(origin))
    .filter((origin): origin is string => Boolean(origin)),
);

const ALLOW_METHODS = 'GET,POST,PUT,PATCH,DELETE,OPTIONS';
const ALLOW_HEADERS =
  'Authorization, Content-Type, X-Requested-With, X-CSRF-Token, X-402-Signature, X-Idempotency-Key, Accept';

export function withCors<Req extends RequestLike = Request, Ctx = unknown>(handler: Handler<Req, Ctx>): Handler<Req, Ctx> {
  return async (req, ctx) => {
    const evaluation = evaluateRequest(req);

    if (!evaluation.allowed) {
      const forbidden = Response.json({ error: 'Origin not allowed' }, { status: 403 });
      return applyCorsHeaders(forbidden, evaluation);
    }

    const response = await handler(req, ctx);
    return applyCorsHeaders(response, evaluation);
  };
}

export function handleCorsOptions<Req extends RequestLike = Request>(req: Req): Response {
  const evaluation = evaluateRequest(req);

  if (!evaluation.allowed) {
    const forbidden = Response.json({ error: 'Origin not allowed' }, { status: 403 });
    return applyCorsHeaders(forbidden, evaluation);
  }

  const preflight = new Response(null, { status: 200 });
  return applyCorsHeaders(preflight, evaluation);
}

function evaluateRequest(req: RequestLike): CorsEvaluation {
  const originHeader = req.headers.get('origin');
  if (!originHeader) {
    return { allowed: true, originHeader: null };
  }

  const normalized = normalizeOrigin(originHeader);
  if (!normalized) {
    return { allowed: false, originHeader };
  }

  if (allowedOrigins.has(normalized)) {
    return { allowed: true, originHeader };
  }

  return { allowed: false, originHeader };
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

function applyCorsHeaders(response: Response, evaluation: CorsEvaluation): Response {
  appendVaryHeader(response.headers, 'Origin');

  if (evaluation.allowed && evaluation.originHeader) {
    response.headers.set('Access-Control-Allow-Origin', evaluation.originHeader);
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    response.headers.set('Access-Control-Allow-Methods', ALLOW_METHODS);
    response.headers.set('Access-Control-Allow-Headers', ALLOW_HEADERS);
  }

  return response;
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

