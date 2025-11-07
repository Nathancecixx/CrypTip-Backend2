import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { env } from '@/src/lib/env';
import { upsertUserByWallet } from '@/src/lib/db';
import { handleCorsOptions, withCORS, validateRequestOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { issueSessionJWT, setSessionCookie } from '@/src/lib/auth';
import { consumeSiwsNonce, extractNonceFromMessage, loadSiwsNonce } from '@/src/lib/nonce-store';

import { PublicKey } from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

export const runtime = 'nodejs';
const LOGIN_TTL_MS = 15 * 60 * 1000; // 15 min

// ---------- helpers ----------
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
    try {
      return new URL(uri).host;
    } catch {}
  }
  return null;
}

function parseIssuedAt(message: string): number | null {
  const s = findHeader(message, ['Issued At', 'IssuedAt', 'Issued at', 'Issued']);
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

function coerceBytes(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) return value;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) return new Uint8Array(value);
  if (Array.isArray(value) && value.every(v => Number.isInteger(v) && v >= 0 && v <= 255)) {
    return Uint8Array.from(value as number[]);
  }
  return null;
}

function normalizeSignatureInput(signature: unknown, signatureBytes: unknown) {
  if (typeof signature === 'string') {
    try {
      const bytes = bs58.decode(signature);
      return { base58: signature, bytes } as const;
    } catch {
      return { error: 'signature_malformed' } as const;
    }
  }

  const rawBytes = coerceBytes(signatureBytes);
  if (!rawBytes) {
    return { error: 'signature_malformed' } as const;
  }

  const base58 = bs58.encode(rawBytes);
  try {
    const bytes = bs58.decode(base58);
    return { base58, bytes } as const;
  } catch {
    return { error: 'signature_malformed' } as const;
  }
}

function verifySignatureBytes(message: string, signature: Uint8Array, publicKeyBytes: Uint8Array): boolean {
  try {
    const msg = new TextEncoder().encode(message);
    return nacl.sign.detached.verify(msg, signature, publicKeyBytes);
  } catch {
    return false;
  }
}

function logReject(
  reason: string,
  context: { address?: string; hasNonce: boolean; domainSeen: string | null; domainExpected: string }
) {
  try {
    console.warn('siws.finish.reject', {
      reason,
      address: context.address,
      hasNonce: context.hasNonce,
      domainSeen: context.domainSeen,
      domainExpected: context.domainExpected,
    });
  } catch {
    // logging best-effort only
  }
}

function fail(
  req: NextRequest,
  status: number,
  code: 'nonce_invalid' | 'message_expired' | 'signature_malformed' | 'bad_signature',
  context: { address?: string; hasNonce: boolean; domainSeen: string | null; domainExpected: string },
  extra: Record<string, unknown> = {}
) {
  logReject(code, context);
  return withCORS(req, NextResponse.json({ error: code, ...extra }, { status }));
}

// ---------- handlers ----------
export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  try {
    const originCheck = validateRequestOrigin(req);
    if (!originCheck.ok && originCheck.response) return withCORS(req, originCheck.response);

    let body: any;
    try {
      body = await req.json();
    } catch {
      return withCORS(req, NextResponse.json({ error: 'bad_request', fields: { json: 'invalid' } }, { status: 400 }));
    }

    const { address, signature, signatureBytes, nonce, message } = body ?? {};
    const expectedDomain = resolveAllowedRequestDomain(req);
    const domainSeen = typeof message === 'string' ? parseDomain(message) : null;

    if (typeof address !== 'string' || !address.trim()) {
      return fail(req, 400, 'nonce_invalid', {
        address: undefined,
        hasNonce: false,
        domainSeen,
        domainExpected: expectedDomain,
      });
    }

    const normalizedAddress = address.trim();

    if (typeof nonce !== 'string' || !nonce.trim()) {
      return fail(req, 400, 'nonce_invalid', {
        address: normalizedAddress,
        hasNonce: false,
        domainSeen,
        domainExpected: expectedDomain,
      });
    }

    if (typeof message !== 'string' || !message) {
      return fail(req, 400, 'nonce_invalid', {
        address: normalizedAddress,
        hasNonce: false,
        domainSeen,
        domainExpected: expectedDomain,
      });
    }

    const normalizedNonce = nonce.trim();
    const context = {
      address: normalizedAddress,
      hasNonce: false,
      domainSeen,
      domainExpected: expectedDomain,
    };

    if (!context.domainSeen || context.domainSeen !== expectedDomain) {
      return fail(req, 400, 'nonce_invalid', context);
    }

    const messageNonce = extractNonceFromMessage(message);
    if (!messageNonce || messageNonce !== normalizedNonce) {
      return fail(req, 400, 'nonce_invalid', context);
    }

    const storedNonce = loadSiwsNonce(normalizedAddress);
    context.hasNonce = Boolean(storedNonce);
    if (!storedNonce) {
      return fail(req, 400, 'nonce_invalid', context);
    }

    if (storedNonce.nonce !== normalizedNonce || storedNonce.message !== message) {
      return fail(req, 400, 'nonce_invalid', context);
    }

    const issuedAtFromMessage = parseIssuedAt(message);
    const issuedAtStored = Date.parse(storedNonce.issuedAt);
    if (
      !Number.isFinite(issuedAtStored) ||
      issuedAtFromMessage === null ||
      Math.abs(issuedAtStored - issuedAtFromMessage) > 1000
    ) {
      consumeSiwsNonce(normalizedAddress);
      return fail(req, 400, 'nonce_invalid', context);
    }

    if (Date.now() - issuedAtStored > LOGIN_TTL_MS) {
      consumeSiwsNonce(normalizedAddress);
      return fail(req, 400, 'message_expired', context);
    }

    const parsedSignature = normalizeSignatureInput(signature, signatureBytes);
    if ('error' in parsedSignature) {
      return fail(req, 400, 'signature_malformed', context);
    }

    if (parsedSignature.bytes.length !== 64) {
      return fail(req, 400, 'signature_malformed', context);
    }

    let publicKeyBytes: Uint8Array;
    try {
      publicKeyBytes = new PublicKey(normalizedAddress).toBytes();
    } catch {
      consumeSiwsNonce(normalizedAddress);
      return fail(req, 400, 'signature_malformed', context);
    }

    if (!verifySignatureBytes(message, parsedSignature.bytes, publicKeyBytes)) {
      return fail(req, 400, 'bad_signature', context);
    }

    // db upsert
    let userId: string;
    try {
      const user = await upsertUserByWallet(normalizedAddress);
      userId = user.id;
    } catch (e: any) {
      logReject('db_error', { ...context, hasNonce: false });
      return withCORS(
        req,
        NextResponse.json({ error: 'db_error', code: e?.code ?? 'unknown', hint: 'upsertUserByWallet' }, { status: 500 })
      );
    }

    if (!env.SESSION_SECRET) {
      logReject('missing_session_secret', { ...context, hasNonce: false });
      return withCORS(req, NextResponse.json({ error: 'missing_session_secret' }, { status: 500 }));
    }

    consumeSiwsNonce(normalizedAddress);

    const token = issueSessionJWT(userId);
    const res = NextResponse.json({ ok: true, userId }, { status: 200 });
    setSessionCookie(res, token);

    return withCORS(req, res);
  } catch (error) {
    console.error('siws.finish.error', error);
    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
