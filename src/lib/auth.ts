// src/lib/auth.ts
import { createHmac, randomBytes } from 'crypto';
import { cookies as nextCookies } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';
import { serialize, type CookieSerializeOptions } from 'cookie';
import { env } from './env';

// ---------- base64url helpers ----------
const b64urlEncode = (buf: Buffer) =>
  buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

const b64urlDecode = (txt: string) => {
  const pad = 4 - (txt.length % 4 || 4);
  const base64 = txt.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad === 4 ? 0 : pad);
  return Buffer.from(base64, 'base64');
};

function hmacSha256(data: string, key: string) {
  return createHmac('sha256', key).update(data).digest();
}

// ---------- Errors ----------
export class UnauthorizedError extends Error {
  code = 'unauthorized';
  constructor(message = 'Unauthorized') {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

// ---------- SIWS helpers your routes import ----------
export function makeNonce(bytes = 16): string {
  return b64urlEncode(randomBytes(bytes));
}

export function buildSiwsMessage(
  domain: string,
  address: string,
  nonce: string,
  issuedAt: string = new Date().toISOString()
): string {
  const issuedAtIso = (() => {
    try {
      const parsed = new Date(issuedAt);
      if (!Number.isNaN(parsed.getTime())) {
        return parsed.toISOString();
      }
    } catch {
      // fall through to new Date() below
    }
    return new Date().toISOString();
  })();

  return (
    'Sign-In With Solana\n\n' +
    `Domain: ${domain}\n` +
    `Address: ${address}\n` +
    `Nonce: ${nonce}\n` +
    `Issued At: ${issuedAtIso}\n\n` +
    'By signing this message you prove you control the wallet above.'
  );
}

// ---------- Session (JWT HS256 minimal) ----------
type JwtPayload = {
  sub: string;   // userId
  iat: number;   // issued at (sec)
  exp: number;   // expiry (sec)
  iss: string;   // issuer
};

export function issueSessionJWT(userId: string): string {
  const header = b64urlEncode(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const now = Math.floor(Date.now() / 1000);
  const sessionMaxAge = env.SESSION_MAX_AGE ?? 60 * 15;
  const payload: JwtPayload = {
    sub: userId,
    iat: now,
    exp: now + sessionMaxAge,
    iss: 'cryptip-backend',
  };
  const payloadB64 = b64urlEncode(Buffer.from(JSON.stringify(payload)));
  const data = `${header}.${payloadB64}`;
  const sig = b64urlEncode(hmacSha256(data, env.SESSION_SECRET));
  return `${data}.${sig}`;
}

function verifySessionJWT(token: string): JwtPayload {
  const parts = token.split('.');
  if (parts.length !== 3) throw new UnauthorizedError('token_malformed');
  const [h, p, s] = parts;
  const expect = b64urlEncode(hmacSha256(`${h}.${p}`, env.SESSION_SECRET));
  if (s !== expect) throw new UnauthorizedError('token_bad_signature');
  const payloadJson = b64urlDecode(p).toString('utf8');
  const payload = JSON.parse(payloadJson) as JwtPayload;
  if (typeof payload.exp !== 'number' || Date.now() / 1000 > payload.exp) {
    throw new UnauthorizedError('token_expired');
  }
  if (!payload.sub) throw new UnauthorizedError('token_no_sub');
  return payload;
}

/**
 * requireSession — matches your existing route imports
 * Throws UnauthorizedError if the cookie is missing/invalid.
 * Returns { userId } on success.
 */
export function requireSession(req?: NextRequest): { userId: string } {
  // Prefer NextRequest cookies if provided; otherwise read from process (not typical)
  const name = env.SESSION_COOKIE_NAME || 'ctj_sess';
  let token: string | undefined;

  if (req) {
    token = req.cookies.get(name)?.value;
  }

  if (!token) {
    try {
      token = nextCookies().get(name)?.value;
    } catch {
      // no-op: accessing nextCookies outside request context can throw
    }
  }

  if (!token) throw new UnauthorizedError('no_session');
  const payload = verifySessionJWT(token);
  return { userId: payload.sub };
}

export function setSessionCookie(res: NextResponse, token: string) {
  const name = env.SESSION_COOKIE_NAME || 'ctj_sess';
  const maxAge = env.SESSION_MAX_AGE ?? 60 * 15;

  const options: CookieSerializeOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/',
    maxAge,
  };

  let cookieValue = serialize(name, token, options);

  if (process.env.EXPERIMENTAL_PARTITIONED_COOKIES === '1') {
    cookieValue += '; Partitioned';
  }

  // Replace any existing Set-Cookie header to guarantee the browser receives exactly
  // one session cookie (required for the BFF to mirror it as a first-party cookie).
  res.headers.set('Set-Cookie', cookieValue);
}

export function logUnauthorizedAccess(req: NextRequest, error: unknown) {
  try {
    const url = new URL(req.url);
    const origin = req.headers.get('origin') ?? undefined;
    const reason =
      error instanceof UnauthorizedError
        ? error.code
        : typeof (error as any)?.code === 'string'
        ? (error as any).code
        : error instanceof Error
        ? error.message
        : undefined;

    console.warn('auth.unauthorized', {
      path: url.pathname,
      origin,
      reason,
    });
  } catch {
    // logging is best-effort
  }
}
