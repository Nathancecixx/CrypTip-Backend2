// src/lib/auth.ts
import { createHmac, randomBytes } from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
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

type BuildSiwsMessageOptions = {
  domain: string;
  issuedAt?: string;
  statement?: string;
  resources?: string[];
};

export function buildSiwsMessage(
  address: string,
  nonce: string,
  { domain, issuedAt, statement, resources }: BuildSiwsMessageOptions
): { message: string; issuedAt: string } {
  const issued = issuedAt ?? new Date().toISOString();
  const summary =
    statement ?? 'By signing this message you prove you control the wallet above.';
  const resourcesBlock = resources && resources.length
    ? `\nResources:\n${resources.map(r => `- ${r}`).join('\n')}`
    : '';

  const message = `Sign-In With Solana

Domain: ${domain}
Address: ${address}
Nonce: ${nonce}
Issued At: ${issued}${resourcesBlock}

${summary}`;

  return { message, issuedAt: issued };
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
  const payload: JwtPayload = {
    sub: userId,
    iat: now,
    exp: now + Number(env.SESSION_MAX_AGE ?? 60 * 60 * 24 * 14), // default 14d
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

  if (!token) throw new UnauthorizedError('no_session');
  const payload = verifySessionJWT(token);
  return { userId: payload.sub };
}

/**
 * Sets cross-site session cookie (SameSite=None; Secure).
 * Keep domain undefined on Vercel preview subdomains.
 */
export function setSessionCookie(res: NextResponse, token: string) {
  const domain = env.SESSION_COOKIE_DOMAIN || undefined;
  res.cookies.set({
    name: env.SESSION_COOKIE_NAME || 'ctj_sess',
    value: token,
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/',
    maxAge: Number(env.SESSION_MAX_AGE ?? 60 * 60 * 24 * 14),
    ...(domain ? { domain } : {}),
  });
}
