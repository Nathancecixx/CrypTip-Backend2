import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

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

const encoder = new TextEncoder();
const DEFAULT_NONCE_TTL_MS = 10 * 60 * 1000;
const MIN_NONCE_TTL_MS = 10 * 1000;
const MAX_NONCE_TTL_MS = 10 * 60 * 1000;

type FailureCode =
  | 'bad_request'
  | 'address_invalid'
  | 'nonce_invalid'
  | 'signature_malformed'
  | 'bad_signature'
  | 'db_error'
  | 'missing_session_secret'
  | 'internal_error';

type FailureContext = { domain: string; address?: string; nonce?: string };

function ttlMs(): number {
  const raw = Number((process.env.SIWS_NONCE_TTL_SECONDS || '0').trim()) * 1000;
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_NONCE_TTL_MS;
  return Math.min(MAX_NONCE_TTL_MS, Math.max(MIN_NONCE_TTL_MS, raw));
}

function deriveExpectedDomain(req: NextRequest): string {
  const pinned = (process.env.SIWS_DOMAIN || '').trim();
  return pinned || resolveAllowedRequestDomain(req);
}

function fail(req: NextRequest, status: number, code: FailureCode, ctx: FailureContext, extra?: Record<string, unknown>) {
  try {
    const logger = code === 'nonce_invalid' || code === 'address_invalid' || code === 'bad_request'
      ? console.info : console.warn;
    logger('siws.finish.reject', { code, ...ctx, ...(extra ?? {}) });
  } catch {}
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
  try { return new Uint8Array(Buffer.from(value, 'base64')); }
  catch { return null; }
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
  try { return nacl.sign.detached.verify(message, signature, publicKeyBytes); }
  catch { return false; }
}

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
      return fail(req, 400, 'bad_request', { domain: deriveExpectedDomain(req) }, { fields: { json: 'invalid' } });
    }

    const expectedDomain = deriveExpectedDomain(req);
    const providedAddress = typeof body?.address === 'string' ? body.address.trim() : '';
    const providedNonce = typeof body?.nonce === 'string' ? body.nonce.trim() : '';

    const ctx: FailureContext = { domain: expectedDomain, address: providedAddress || undefined, nonce: providedNonce || undefined };

    if (!providedAddress) return fail(req, 400, 'address_invalid', ctx);
    if (!providedNonce) return fail(req, 400, 'nonce_invalid', ctx);

    const parsedSig = normalizeSignatureInput(body);
    if ('error' in parsedSig) return fail(req, 400, 'signature_malformed', ctx);
    if (parsedSig.bytes.length !== 64) return fail(req, 400, 'signature_malformed', ctx, { reason: 'bad_length' });

    // Validate address format
    let publicKeyBytes: Uint8Array;
    try { publicKeyBytes = new PublicKey(providedAddress).toBytes(); }
    catch { return fail(req, 400, 'address_invalid', ctx); }

    // Load nonce
    const nonceRow = await getNonce(providedNonce);
    if (!nonceRow) return fail(req, 400, 'nonce_invalid', ctx, { reason: 'not_found' });

    const createdAtRaw = (nonceRow as any).created_at ?? (nonceRow as any).createdAt ?? null;
    const expiresAtRaw = (nonceRow as any).expires_at ?? (nonceRow as any).expiresAt ?? null;
    const nonceDomain = (nonceRow as any).domain ?? undefined;

    const now = Date.now();
    let createdMs = Number.isFinite(Date.parse(createdAtRaw)) ? Date.parse(createdAtRaw) : NaN;
    if (!Number.isFinite(createdMs)) createdMs = now - ttlMs() / 2;
    const expiresMs = Number.isFinite(Date.parse(expiresAtRaw)) ? Date.parse(expiresAtRaw) : createdMs + ttlMs();

    if (now > expiresMs) {
      await consumeNonce((nonceRow as any).id).catch(() => void 0);
      return fail(req, 400, 'nonce_invalid', ctx, { reason: 'expired' });
    }

    if (nonceDomain && nonceDomain !== expectedDomain) {
      await consumeNonce((nonceRow as any).id).catch(() => void 0);
      return fail(req, 400, 'nonce_invalid', ctx, { reason: 'domain_mismatch' });
    }

    const canonicalMessage = buildSiwsMessage(
      expectedDomain,
      providedAddress,
      providedNonce,
      createdAtRaw ?? new Date(createdMs).toISOString(),
    );
    const messageBytes = encoder.encode(canonicalMessage);

    if (!verifySignature(messageBytes, parsedSig.bytes, publicKeyBytes)) {
      return fail(req, 400, 'bad_signature', ctx);
    }

    const consumed = await consumeNonce((nonceRow as any).id).catch(() => false);
    if (!consumed) return fail(req, 400, 'nonce_invalid', ctx, { reason: 'consumed' });

    console.info('siws.finish.attempt', {
      address: providedAddress,
      nonce: providedNonce,
      origin: req.headers.get('origin') ?? undefined,
    });

    let userId: string;
    try {
      const user = await upsertUserByWallet(providedAddress);
      userId = user.id;
    } catch (e: any) {
      return fail(req, 500, 'db_error', ctx, { code: e?.code ?? 'unknown', hint: 'upsertUserByWallet' });
    }

    // Keep the explicit check to return a good error instead of 500
    if (!((process.env.SESSION_SECRET || '').trim())) {
      return fail(req, 500, 'missing_session_secret', ctx);
    }

    const token = issueSessionJWT(userId);
    const res = NextResponse.json({ ok: true }, { status: 200 });
    setSessionCookie(res, token); // HttpOnly; Secure; SameSite=None

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
