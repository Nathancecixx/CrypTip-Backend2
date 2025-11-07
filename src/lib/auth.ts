// src/lib/auth.ts
import { createHmac, randomBytes } from 'crypto';
import { NextResponse } from 'next/server';
import { env } from './env';

// Base64url helper
const b64url = (buf: Buffer) =>
  buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

/**
 * Minimal HS256 JWT (server-side only).
 * Payload: { sub, iat, exp, iss }
 */
export function issueSessionJWT(userId: string): string {
  const header = b64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const now = Math.floor(Date.now() / 1000);
  const payloadObj = {
    sub: userId,
    iat: now,
    exp: now + env.SESSION_MAX_AGE, // seconds
    iss: 'cryptip-backend',
  };
  const payload = b64url(Buffer.from(JSON.stringify(payloadObj)));
  const data = `${header}.${payload}`;
  const sig = createHmac('sha256', env.SESSION_SECRET).update(data).digest();
  return `${data}.${b64url(sig)}`;
}

/**
 * Sets cross-site session cookie.
 * - SameSite=None + Secure enables FE<->BE across different origins.
 * - Domain is optional; OMIT on vercel.app previews.
 */
export function setSessionCookie(res: NextResponse, token: string) {
  const domain = env.SESSION_COOKIE_DOMAIN || undefined;
  res.cookies.set({
    name: env.SESSION_COOKIE_NAME,
    value: token,
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/',
    maxAge: env.SESSION_MAX_AGE, // seconds
    ...(domain ? { domain } : {}),
  });
}

/** Cryptographically strong random nonce for SIWS message */
export function generateNonce(bytes = 16): string {
  return b64url(randomBytes(bytes));
}
