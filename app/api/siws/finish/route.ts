import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import { env } from '@/src/lib/env';
import { upsertUserByWallet } from '@/src/lib/db';
import {
  handleCorsOptions,
  withCORS,
  validateRequestOrigin,
  resolveAllowedRequestDomain,
} from '@/src/lib/cors';
import { buildSiwsMessage, issueSessionJWT, setSessionCookie } from '@/src/lib/auth';
import { getNonce, consumeNonce } from '@/src/lib/nonce-store';

import { PublicKey } from '@solana/web3.js';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

export const runtime = 'nodejs';

/** Clamp TTL: default 10m, min 10s, max 10m unless your store already enforces expires_at. */
const DEFAULT_NONCE_TTL_MS = 10 * 60 * 1000;
const MIN_NONCE_TTL_MS = 10 * 1000;
const MAX_NONCE_TTL_MS = 10 * 60 * 1000;

const encoder = new TextEncoder();

type FailureCode =
  | 'bad_request'
  | 'address_invalid'
  | 'nonce_invalid'
  | 'signature_malformed'
  | 'bad_signature'
  | 'db_error'
  | 'missing_session_secret'
  | 'internal_error';

type FailureContext = {
  domain: string;
  address?: string;
  nonce?: string;
};

function ttlMs(): number {
  const raw = Number(env.SIWS_NONCE_TTL_SECONDS ?? 0) * 1000;
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_NONCE_TTL_MS;
  return Math.min(MAX_NONCE_TTL_MS, Math.max(MIN_NONCE_TTL_MS, raw));
}

function deriveExpectedDomain(req: NextRequest): string {
  const pinned = (env.SIWS_DOMAIN ?? '').trim();
  return pinned || resolveAllowedRequestDomain(req);
}

function logReject(code: FailureCode, ctx: FailureContext, extra?: Record<string, unknown>) {
  try {
    const logger = code === 'nonce_invalid' || code === 'address_invalid' || code === 'bad_request'
      ? console.info
      : console.warn;
    logger('siws.finish.reject', { code, ...ctx, ...(extra ?? {}) });
  } catch {
    /* best-effort logging */
  }
}

function fail(
  req: NextRequest,
  status: number,
  code: FailureCode,
  ctx: FailureContext,
  extra?: Record<string, unknown>,
) {
  logReject(code, ctx, extra);
  return withCORS(req, NextResponse.json({ error: code, ...(extra ?? {}) }, { status }));
}

function coerceBytes(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) return value;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) return new Uint8Array(value);
  if (Array.isArray(value) && value.every(v => Number.isInteger(v) && v >= 0 && v <= 255)) {
    return Uint8Array.from(value as number[]);
  }
  return null;
}

function decodeBase64Bytes(value: string | undefined): Uint8Array | null {
  if (!value || typeof value !== 'string') return null;
  try {
    return new Uint8Array(Buffer.from(value, 'base64'));
  } catch {
    return null;
  }
}

function normalizeSignatureInput(body: any) {
  const sigB58 = typeof body?.signature === 'string' ? body.signature : undefined;

  const sigB64 =
    typeof body?.signatureBase64 === 'string' ? body.signatureBase64
    : typeof body?.signatureBytesBase64 === 'string' ? body.signatureBytesBase64
    : typeof body?.signature_base64 === 'string' ? body.signature_base64
    : typeof body?.signature_bytes_base64 === 'string' ? body.signature_bytes_base64
    : undefined;

  const bytesFromArray = coerceBytes(body?.signatureBytes);

  if (sigB58) {
    try {
      const bytes = bs58.decode(sigB58);
      return { format: 'base58' as const, value: sigB58, bytes };
    } catch {
      return { error: 'signature_malformed' as const };
    }
  }

  if (sigB64) {
    const bytes = decodeBase64Bytes(sigB64);
    if (!bytes) return { error: 'signature_malformed' as const };
    return { format: 'base64' as const, value: sigB64, bytes };
  }

  if (bytesFromArray) {
    // Normalize via base58 round-trip to ensure valid length/shape
    try {
      const as58 = bs58.encode(bytesFromArray);
      const bytes = bs58.decode(as58);
      return { format: 'bytes' as const, value: as58, bytes };
    } catch {
      return { error: 'signature_malformed' as const };
    }
  }

  return { error: 'signature_malformed' as const };
}

function verifySignature(message: Uint8Array, signature: Uint8Array, publicKeyBytes: Uint8Array): boolean {
  try {
    return nacl.sign.detached.verify(message, signature, publicKeyBytes);
  } catch {
    return false;
  }
}

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  try {
    // 1) Origin guard (CORS) – always return with CORS attached.
    const originCheck = validateRequestOrigin(req);
    if (!originCheck.ok && originCheck.response) return withCORS(req, originCheck.response);

    // 2) Parse body
    let body: any;
    try {
      body = await req.json();
    } catch {
      return fail(req, 400, 'bad_request', { domain: deriveExpectedDomain(req) }, { fields: { json: 'invalid' } });
    }

    const expectedDomain = deriveExpectedDomain(req);
    const providedAddress = typeof body?.address === 'string' ? body.address.trim() : '';
    const providedNonce = typeof body?.nonce === 'string' ? body.nonce.trim() : '';

    const ctx: FailureContext = {
      domain: expectedDomain,
      address: providedAddress || undefined,
      nonce: providedNonce || undefined,
    };

    if (!providedAddress) return fail(req, 400, 'address_invalid', ctx);
    if (!providedNonce) return fail(req, 400, 'nonce_invalid', ctx);

    // 3) Normalize signature input (base58/base64/raw bytes)
    const parsedSig = normalizeSignatureInput(body);
    if ('error' in parsedSig) return fail(req, 400, 'signature_malformed', ctx);
    if (parsedSig.bytes.length !== 64) return fail(req, 400, 'signature_malformed', ctx, { reason: 'bad_length' });

    // 4) Validate address format
    let publicKeyBytes: Uint8Array;
    try {
      publicKeyBytes = new PublicKey(providedAddress).toBytes();
    } catch {
      return fail(req, 400, 'address_invalid', ctx);
    }

    // 5) Load nonce
    const nonceRow = await getNonce(providedNonce);
    if (!nonceRow) {
      return fail(req, 400, 'nonce_invalid', ctx, { reason: 'not_found' });
    }

    // Support different shapes from store: created_at/createdAt, expires_at/expiresAt, domain
    const createdAtRaw = (nonceRow as any).created_at ?? (nonceRow as any).createdAt ?? null;
    const expiresAtRaw = (nonceRow as any).expires_at ?? (nonceRow as any).expiresAt ?? null;
    const nonceDomain = (nonceRow as any).domain ?? undefined;

    // 6) Enforce TTL if store didn’t already expire, and optionally domain binding
    const now = Date.now();
    let createdMs = Number.isFinite(Date.parse(createdAtRaw)) ? Date.parse(createdAtRaw) : NaN;
    if (!Number.isFinite(createdMs)) {
      // Fall back to "now - ttl" so we still allow current attempt if store didn’t provide a timestamp
      createdMs = now - ttlMs() / 2;
    }

    const expiresMs = Number.isFinite(Date.parse(expiresAtRaw)) ? Date.parse(expiresAtRaw) : createdMs + ttlMs();
    if (now > expiresMs) {
      await consumeNonce((nonceRow as any).id).catch(() => void 0); // burn on expiry
      return fail(req, 400, 'nonce_invalid', ctx, { reason: 'expired' });
    }

    if (nonceDomain && nonceDomain !== expectedDomain) {
      await consumeNonce((nonceRow as any).id).catch(() => void 0);
      return fail(req, 400, 'nonce_invalid', ctx, { reason: 'domain_mismatch' });
    }

    // 7) Rebuild canonical message (must byte-match what the wallet signed)
    const canonicalMessage = buildSiwsMessage(
      expectedDomain,
      providedAddress,
      providedNonce,
      createdAtRaw ?? new Date(createdMs).toISOString(),
    );
    const messageBytes = encoder.encode(canonicalMessage);

    // 8) Verify signature
    if (!verifySignature(messageBytes, parsedSig.bytes, publicKeyBytes)) {
      return fail(req, 400, 'bad_signature', ctx);
    }

    // 9) One-time consumption
    const consumed = await consumeNonce((nonceRow as any).id).catch(() => false);
    if (!consumed) {
      return fail(req, 400, 'nonce_invalid', ctx, { reason: 'consumed' });
    }

    console.info('siws.finish.attempt', {
      address: providedAddress,
      nonce: providedNonce,
      origin: req.headers.get('origin') ?? undefined,
    });

    // 10) Upsert user by wallet
    let userId: string;
    try {
      const user = await upsertUserByWallet(providedAddress);
      userId = user.id;
    } catch (e: any) {
      return fail(req, 500, 'db_error', ctx, { code: e?.code ?? 'unknown', hint: 'upsertUserByWallet' });
    }

    // 11) Issue session and set cookie
    if (!env.SESSION_SECRET) {
      return fail(req, 500, 'missing_session_secret', ctx);
    }

    const token = issueSessionJWT(userId);
    const res = NextResponse.json({ ok: true }, { status: 200 });
    // Ensure your cookie helper sets: HttpOnly, Secure, SameSite=None (cross-site), and optionally Partitioned.
    setSessionCookie(res, token);

    console.info('siws.finish.success', {
      address: providedAddress,
      userId,
      origin: req.headers.get('origin') ?? undefined,
    });

    return withCORS(req, res);
  } catch (error) {
    console.error('siws.finish.error', error);
    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
