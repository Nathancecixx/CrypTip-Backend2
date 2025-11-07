import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { env } from '@/src/lib/env';
import { upsertUserByWallet } from '@/src/lib/db';
import { handleCorsOptions, withCORS, validateRequestOrigin } from '@/src/lib/cors';

// ---- minimal, robust signature verify (phantom signMessage) ---------------
import { PublicKey } from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

// verify signature of raw message bytes using address (base58 pubkey)
function verifySignature(message: string, signatureB58: string, address: string): boolean {
  try {
    const pub = new PublicKey(address).toBytes();
    const sig = bs58.decode(signatureB58);
    // normalize EOLs: signers sometimes use \r\n, sometimes \n
    const msg = new TextEncoder().encode(message.replace(/\r\n/g, '\n'));
    return nacl.sign.detached.verify(msg, sig, pub);
  } catch {
    return false;
  }
}

// ---- tolerant SIWS parsing -------------------------------------------------
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
  if (uri) {
    try { return new URL(uri).host; } catch { /* ignore */ }
  }
  return null;
}

function parseIssuedAt(message: string): number | null {
  const s = findHeader(message, ['Issued At', 'IssuedAt', 'Issued at', 'Issued']);
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

// ---- tiny JWT (HS256) without deps ----------------------------------------
import { createHmac } from 'node:crypto';

function b64url(input: string | Buffer) {
  return Buffer.from(input).toString('base64').replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
}
function signHS256(payload: object, secret: string, header: object = { alg: 'HS256', typ: 'JWT' }) {
  const enc = (o: object) => b64url(JSON.stringify(o));
  const body = `${enc(header)}.${enc(payload)}`;
  const sig = b64url(createHmac('sha256', secret).update(body).digest());
  return `${body}.${sig}`;
}

function issueSessionJWT(userId: string) {
  const now = Math.floor(Date.now() / 1000);
  const ttl = Number(process.env.SESSION_MAX_AGE ?? 60 * 60 * 24 * 14); // 14d default
  const payload = { sub: userId, iat: now, exp: now + ttl, iss: 'cryptip-backend' };
  const secret = env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET missing');
  return { token: signHS256(payload, secret), maxAge: ttl };
}

export const runtime = 'nodejs';
const TTL_MS = 10 * 60 * 1000; // accept messages within 10 minutes

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  try {
    const originCheck = validateRequestOrigin(req);
    if (!originCheck.ok && originCheck.response) return originCheck.response;

    const body = await req.json().catch(() => ({} as any));
    const { address, signature, message } = body ?? {};
    if (!address || !signature || !message || typeof message !== 'string') {
      return withCORS(req, NextResponse.json(
        { error: 'bad_request', fields: { address: 'required', signature: 'required', message: 'required' } },
        { status: 400 }
      ));
    }

    // Parse permissively
    const domain   = parseDomain(message);                    // optional
    const issuedAt = parseIssuedAt(message);                  // optional
    const allowedHost = (() => {
      try { return new URL(env.FRONTEND_ORIGIN).host; } catch { return env.SIWS_DOMAIN; }
    })();
    const expectedDomain = env.SIWS_DOMAIN || allowedHost;

    // If message declares a domain, require it to be one of ours
    if (domain && domain !== expectedDomain && domain !== allowedHost) {
      return withCORS(req, NextResponse.json({ error: 'domain_mismatch' }, { status: 400 }));
    }

    // If Issued At exists, enforce a TTL window
    if (issuedAt !== null && (Date.now() - issuedAt) > TTL_MS) {
      return withCORS(req, NextResponse.json({ error: 'nonce_expired' }, { status: 400 }));
    }

    // Verify Phantom signature over exact message bytes
    if (!verifySignature(message, signature, address)) {
      return withCORS(req, NextResponse.json({ error: 'bad_signature' }, { status: 401 }));
    }

    // Upsert user & issue session cookie
    const user = await upsertUserByWallet(address);
    const { token, maxAge } = issueSessionJWT(user.id);

    const res = NextResponse.json({ ok: true, userId: user.id }, { status: 200 });
    res.cookies.set({
      name: env.SESSION_COOKIE_NAME ?? 'cryptip.sid',
      value: token,
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge,
    });

    return withCORS(req, res);
  } catch {
    // Always return CORS on error paths
    const res = NextResponse.json({ error: 'internal_error' }, { status: 500 });
    return withCORS(req, res);
  }
}
