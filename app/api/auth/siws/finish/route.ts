import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { env } from '@/src/lib/env';
import { upsertUserByWallet } from '@/src/lib/db';
import { handleCorsOptions, withCORS, validateRequestOrigin } from '@/src/lib/cors';
import { issueSessionJWT, setSessionCookie } from '@/src/lib/auth';

import { PublicKey } from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

export const runtime = 'nodejs';
const LOGIN_TTL_MS = 10 * 60 * 1000; // 10 min

// ---------- helpers ----------
function verifySignature(message: string, signatureB58: string, address: string): boolean {
  try {
    const pub = new PublicKey(address).toBytes();
    const sig = bs58.decode(signatureB58);
    const msg = new TextEncoder().encode(message.replace(/\r\n/g, '\n'));
    return nacl.sign.detached.verify(msg, sig, pub);
  } catch {
    return false;
  }
}

// tolerant SIWS parsing
function findHeader(message: string, labels: string[]): string | null {
  for (const label of labels) {
    const re = new RegExp(`(?:^|\\n)${label}\\s*:\\s*([^\\n]+)`, 'i');
    const m = message.match(re);
    if (m) return m[1].trim();
  }
  return null;
}
function parseDomain(message: string): string | null {
  const hdr = findHeader(message, ['Domain']);
  if (hdr) return hdr;
  const first = message.split('\n', 1)[0] ?? '';
  const m = first.match(/^([^\s]+)\s+wants you to sign in/i);
  if (m) return m[1].trim();
  const uri = findHeader(message, ['URI', 'Uri']);
  if (uri) { try { return new URL(uri).host; } catch {} }
  return null;
}
function parseIssuedAt(message: string): number | null {
  const s = findHeader(message, ['Issued At', 'IssuedAt', 'Issued at', 'Issued']);
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

// small helper to standardize error responses + CORS
function fail(req: NextRequest, status: number, code: string, extra: Record<string, unknown> = {}) {
  return withCORS(req, NextResponse.json({ error: code, ...extra }, { status }));
}

// ---------- handlers ----------
export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  try {
    const originCheck = validateRequestOrigin(req);
    if (!originCheck.ok && originCheck.response) return originCheck.response;

    let body: any;
    try {
      body = await req.json();
    } catch {
      return fail(req, 400, 'bad_request', { fields: { json: 'invalid' } });
    }

    const { address, signature, message } = body ?? {};
    if (!address || !signature || !message || typeof message !== 'string') {
      return fail(req, 400, 'bad_request', { fields: { address: 'required', signature: 'required', message: 'required' } });
    }

    // parse relaxed fields
    const domain = parseDomain(message);               // optional
    const issuedAt = parseIssuedAt(message);           // optional
    const allowedHost = (() => {
      try { return new URL(env.FRONTEND_ORIGIN).host; } catch { return env.SIWS_DOMAIN; }
    })();
    const expectedDomain = env.SIWS_DOMAIN || allowedHost;

    if (domain && domain !== expectedDomain && domain !== allowedHost) {
      return fail(req, 400, 'domain_mismatch', { expected: [expectedDomain, allowedHost], got: domain });
    }
    if (issuedAt !== null && (Date.now() - issuedAt) > LOGIN_TTL_MS) {
      return fail(req, 400, 'nonce_expired');
    }

    if (!verifySignature(message, signature, address)) {
      return fail(req, 401, 'bad_signature');
    }

    // db upsert
    let userId: string;
    try {
      const user = await upsertUserByWallet(address);
      userId = user.id;
    } catch (e: any) {
      // sanitize but keep a breadcrumb
      return fail(req, 500, 'db_error', { code: e?.code ?? 'unknown', hint: 'upsertUserByWallet' });
    }

    // issue session
    if (!env.SESSION_SECRET) {
      return fail(req, 500, 'missing_session_secret');
    }

    const token = issueSessionJWT(userId);
    const res = NextResponse.json({ ok: true, userId }, { status: 200 });
    setSessionCookie(res, token);

    return withCORS(req, res);
  } catch {
    return fail(req, 500, 'internal_error');
  }
}
