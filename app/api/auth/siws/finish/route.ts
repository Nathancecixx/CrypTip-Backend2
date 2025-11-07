import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { env } from '@/src/lib/env';
import { upsertUserByWallet } from '@/src/lib/db';
import { handleCorsOptions, withCORS, validateRequestOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { issueSessionJWT, setSessionCookie } from '@/src/lib/auth';
import { consumeIfValid, extractNonceFromMessage } from '@/src/lib/nonce-store';

import { PublicKey } from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

export const runtime = 'nodejs';
const LOGIN_TTL_MS = env.SIWS_NONCE_TTL_SECONDS * 1000; // 10 min TTL

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

function decodeBase64Bytes(value: string): Uint8Array | null {
  try {
    return new Uint8Array(Buffer.from(value, 'base64'));
  } catch {
    return null;
  }
}

function normalizeSignatureInput(signature: unknown, signatureBytes: unknown, signatureBase64: unknown) {
  if (typeof signature === 'string') {
    try {
      const bytes = bs58.decode(signature);
      return { base58: signature, bytes } as const;
    } catch {
      return { error: 'signature_malformed' } as const;
    }
  }

  if (typeof signatureBase64 === 'string') {
    const bytes = decodeBase64Bytes(signatureBase64);
    if (!bytes) {
      return { error: 'signature_malformed' } as const;
    }
    return { base64: signatureBase64, bytes } as const;
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

function verifySignature(message: Uint8Array, signature: Uint8Array, publicKeyBytes: Uint8Array): boolean {
  try {
    return nacl.sign.detached.verify(message, signature, publicKeyBytes);
  } catch {
    return false;
  }
}

function logReject(
  reason: string,
  context: { address?: string; nonce?: string; hasNonce: boolean; domainSeen: string | null; domainExpected: string }
) {
  try {
    const logger = reason === 'nonce_invalid' || reason === 'message_expired' ? console.info : console.warn;
    logger('siws.finish.reject', {
      reason,
      address: context.address,
      nonce: context.nonce,
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
  context: { address?: string; nonce?: string; hasNonce: boolean; domainSeen: string | null; domainExpected: string },
  extra: Record<string, unknown> = {}
) {
  logReject(code, context);
  return withCORS(req, NextResponse.json({ error: code, ...extra }, { status }));
}

function normalizeMessageInput(body: any) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  if (typeof body?.message === 'string') {
    return { text: body.message, bytes: encoder.encode(body.message) } as const;
  }

  const base64Candidate =
    (typeof body?.messageBase64 === 'string' && body.messageBase64) ||
    (typeof body?.messageBytesBase64 === 'string' && body.messageBytesBase64) ||
    (typeof body?.message_base64 === 'string' && body.message_base64) ||
    (typeof body?.message_bytes_base64 === 'string' && body.message_bytes_base64);
  if (base64Candidate) {
    const bytes = decodeBase64Bytes(base64Candidate);
    if (!bytes) return { error: 'message_malformed' } as const;
    try {
      const text = decoder.decode(bytes);
      return { text, bytes } as const;
    } catch {
      return { error: 'message_malformed' } as const;
    }
  }

  const messageBytes = coerceBytes(body?.messageBytes);
  if (messageBytes) {
    try {
      const text = decoder.decode(messageBytes);
      return { text, bytes: messageBytes } as const;
    } catch {
      return { error: 'message_malformed' } as const;
    }
  }

  return { error: 'message_malformed' } as const;
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

    const { address, signature, signatureBytes, signatureBase64, nonce } = body ?? {};
    const providedNonce = typeof nonce === 'string' ? nonce.trim() : undefined;
    const signatureBase64Input =
      typeof signatureBase64 === 'string'
        ? signatureBase64
        : typeof body?.signatureBytesBase64 === 'string'
        ? body.signatureBytesBase64
        : typeof body?.signature_base64 === 'string'
        ? body.signature_base64
        : typeof body?.signature_bytes_base64 === 'string'
        ? body.signature_bytes_base64
        : undefined;
    const expectedDomain = resolveAllowedRequestDomain(req);
    const normalizedMessage = normalizeMessageInput(body);
    if ('error' in normalizedMessage) {
      return fail(req, 400, 'nonce_invalid', {
        address: typeof address === 'string' ? address.trim() || undefined : undefined,
        nonce: providedNonce,
        hasNonce: false,
        domainSeen: null,
        domainExpected: expectedDomain,
      });
    }

    const { text: message, bytes: messageBytes } = normalizedMessage;
    const domainSeen = parseDomain(message);

    if (typeof address !== 'string' || !address.trim()) {
      return fail(req, 400, 'nonce_invalid', {
        address: undefined,
        nonce: providedNonce,
        hasNonce: false,
        domainSeen,
        domainExpected: expectedDomain,
      });
    }

    const normalizedAddress = address.trim();

    if (!providedNonce) {
      return fail(req, 400, 'nonce_invalid', {
        address: normalizedAddress,
        nonce: providedNonce,
        hasNonce: false,
        domainSeen,
        domainExpected: expectedDomain,
      });
    }

    if (!message) {
      return fail(req, 400, 'nonce_invalid', {
        address: normalizedAddress,
        nonce: providedNonce,
        hasNonce: false,
        domainSeen,
        domainExpected: expectedDomain,
      });
    }

    const normalizedNonce = providedNonce;
    const context = {
      address: normalizedAddress,
      nonce: normalizedNonce,
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

    const issuedAtFromMessage = parseIssuedAt(message);
    if (issuedAtFromMessage === null) {
      return fail(req, 400, 'nonce_invalid', context);
    }

    if (Date.now() - issuedAtFromMessage > LOGIN_TTL_MS) {
      return fail(req, 400, 'message_expired', context);
    }

    console.info('siws.finish.attempt', {
      address: normalizedAddress,
      nonce: normalizedNonce,
      origin: req.headers.get('origin') ?? undefined,
    });

    const consumed = await consumeIfValid({
      address: normalizedAddress,
      nonce: normalizedNonce,
      domain: expectedDomain,
    });

    if (!consumed) {
      return fail(req, 400, 'nonce_invalid', context);
    }

    context.hasNonce = true;

    const parsedSignature = normalizeSignatureInput(signature, signatureBytes, signatureBase64Input);
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
      return fail(req, 400, 'signature_malformed', context);
    }

    if (!verifySignature(messageBytes, parsedSignature.bytes, publicKeyBytes)) {
      return fail(req, 400, 'bad_signature', context);
    }

    const issuedAtStored = Date.parse(consumed.issued_at);
    if (!Number.isFinite(issuedAtStored) || Math.abs(issuedAtStored - issuedAtFromMessage) > 1000) {
      return fail(req, 400, 'nonce_invalid', context);
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

    const token = issueSessionJWT(userId);
    const res = NextResponse.json({ ok: true }, { status: 200 });
    setSessionCookie(res, token);

    console.info('siws.finish.success', {
      address: normalizedAddress,
      nonce: normalizedNonce,
      userId,
      origin: req.headers.get('origin') ?? undefined,
    });

    return withCORS(req, res);
  } catch (error) {
    console.error('siws.finish.error', error);
    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
