// src/lib/auth.ts
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import type { JwtPayload } from 'jsonwebtoken';
import { serialize } from 'cookie';
import { env } from './env';
import { log } from './logger';

type SessionClaims = JwtPayload & { sub: string };

function assertClaims(payload: string | JwtPayload): asserts payload is SessionClaims {
  if (!payload || typeof payload !== 'object') {
    throw new UnauthorizedError('invalid_token', 'Session token payload must be an object');
  }

  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new UnauthorizedError('invalid_token', 'Session token missing subject');
  }
}

function readSessionCookie(req: NextRequest) {
  return req.cookies.get(env.SESSION_COOKIE_NAME)?.value;
}

function decodeSessionToken(token: string): SessionClaims {
  try {
    const payload = jwt.verify(token, env.SESSION_SECRET, { audience: 'cryptip', issuer: 'cryptip' });
    assertClaims(payload);
    return payload;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new UnauthorizedError('token_expired', 'Session token expired', { cause: error });
    }

    if (error instanceof jwt.JsonWebTokenError) {
      throw new UnauthorizedError('invalid_token', 'Invalid session token', { cause: error });
    }

    throw error;
  }
}

export type Session = {
  userId: string;
  token: string;
  claims: SessionClaims;
};

type CookieOptions = {
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'lax' | 'strict' | 'none';
  path: string;
  maxAge?: number;
  domain?: string;
  partitioned?: boolean;
};

function buildSessionCookieOptions(): CookieOptions {
  const base: CookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/',
  };

  if (env.SESSION_COOKIE_DOMAIN) {
    base.domain = env.SESSION_COOKIE_DOMAIN;
  }

  if (env.EXPERIMENTAL_PARTITIONED_COOKIES || process.env.EXPERIMENTAL_PARTITIONED_COOKIES === '1') {
    base.partitioned = true;
  }

  return base;
}

function setCookie(res: NextResponse, name: string, value: string, options: CookieOptions) {
  const maybeCookies = (res as unknown as { cookies?: { set?: Function } }).cookies;
  if (maybeCookies && typeof maybeCookies.set === 'function') {
    maybeCookies.set(name, value, options);
    return;
  }

  const headerValue = serialize(name, value, options);
  res.headers.append('set-cookie', headerValue);
}

export type RequireSessionMiddlewareResult =
  | { ok: true; session: Session }
  | { ok: false; response: NextResponse };

export type UnauthorizedReason =
  | 'missing_session_cookie'
  | 'invalid_token'
  | 'token_expired';

export class UnauthorizedError extends Error {
  reason: UnauthorizedReason;

  constructor(reason: UnauthorizedReason, message?: string, options?: ErrorOptions) {
    super(message ?? reason, options);
    this.name = 'UnauthorizedError';
    this.reason = reason;
  }
}

export function buildSiwsMessage(domain: string, address: string, nonce: string, createdAtISO: string) {
  return [
    `Sign-In With Solana`,
    `Domain: ${domain}`,
    `Address: ${address}`,
    `Nonce: ${nonce}`,
    `Issued At: ${createdAtISO}`,
  ].join('\n');
}

export function issueSessionJWT(userId: string) {
  if (!env.SESSION_SECRET) throw new Error('missing_session_secret');
  return jwt.sign({ sub: userId }, env.SESSION_SECRET, { expiresIn: '7d', audience: 'cryptip', issuer: 'cryptip' });
}

export function setSessionCookie(res: NextResponse, token: string) {
  const options = buildSessionCookieOptions();
  options.maxAge = env.SESSION_MAX_AGE;
  setCookie(res, env.SESSION_COOKIE_NAME, token, options);
}

export function clearSessionCookie(res: NextResponse) {
  const options = buildSessionCookieOptions();
  options.maxAge = 0;
  setCookie(res, env.SESSION_COOKIE_NAME, '', options);
}

export function requireSession(req: NextRequest): Session {
  const token = readSessionCookie(req);
  if (!token) {
    throw new UnauthorizedError('missing_session_cookie', 'Session cookie not found');
  }

  const claims = decodeSessionToken(token);

  return {
    userId: claims.sub,
    token,
    claims,
  };
}

export function requireSessionMiddleware(req: NextRequest): RequireSessionMiddlewareResult {
  try {
    const session = requireSession(req);
    return { ok: true, session };
  } catch (error) {
    if (error instanceof UnauthorizedError) {
      logUnauthorizedAccess(req, error);
      return {
        ok: false,
        response: NextResponse.json({ error: 'unauthorized' }, { status: 401 }),
      };
    }

    throw error;
  }
}

export function logUnauthorizedAccess(req: NextRequest, error: unknown) {
  const unauthorizedError = error instanceof UnauthorizedError ? error : undefined;
  const ipHeader = req.headers.get('x-forwarded-for') ?? undefined;
  const ip = ipHeader?.split(',')[0]?.trim() || req.ip || undefined;
  const path = req.nextUrl?.pathname ?? req.url;

  log('auth.unauthorized', {
    reason: unauthorizedError?.reason ?? 'unknown',
    message:
      unauthorizedError?.message ?? (error instanceof Error ? error.message : typeof error === 'string' ? error : 'unknown'),
    method: req.method,
    path,
    ip,
  });
}
