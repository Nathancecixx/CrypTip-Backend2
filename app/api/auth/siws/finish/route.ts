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

const encoder = new TextEncoder();
const NONCE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function deriveExpectedDomain(req: NextRequest): string {
  if (env.SIWS_DOMAIN && env.SIWS_DOMAIN.trim()) return env.SIWS_DOMAIN.trim();
  return resolveAllowedRequestDomain(req);
}

type FailureCode =
  | 'address_invalid'
  | 'nonce_invalid'
  | 'signature_malformed'
  | 'bad_signature'
  | 'db_error'
  | 'missing_session_secret'
  | 'bad_request';

type FailureContext = {
  address?: string;
  nonce?: string;
  domain: string;
};

function logReject(reason: FailureCode, context: FailureContext, extra: Record<string, unknown> = {}) {
  try {
    const logger = reason === 'nonce_invalid' || reason === 'address_invalid' ? console.info : console.warn;
    logger('siws.finish.reject', { reason, ...context, ...extra });
  } catch {
    /* no-op */
  }
}

function fail(
  req: NextRequest,
  status: number,
  code: FailureCode,
  context: FailureContext,
  extra: Record<string, unknown> = {},
) {
  logReject(code, context, extra);
  return withCORS(req, NextResponse.json({ error: code, ...extra }, { status }));
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
  // Prefer base58 string `signature`, then base64, then raw byte array forms.
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
    if (!bytes) return { error: 'signature_malformed' } as const;
    return { base64: signatureBase64, bytes } as const;
  }

  const rawBytes = coerceBytes(signatureBytes);
  if (!rawBytes) return { error: 'signature_malformed' } as const;

  // Normalize: encode to base58, then decode again to ensure validity
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
      return fail(
        req,
        400,
        'bad_request',
        { domain: deriveExpectedDomain(req) },
        { fields: { json: 'invalid' } },
      );
    }

    const {
      address,
      signature,
      signatureBytes,
      signatureBase64,
      nonce,
      // Accept common aliases for base64 so clients are forgiving:
      signatureBytesBase64,
      signature_base64,
      signature_bytes_base64,
    } = body ?? {};

    const expectedDomain = deriveExpectedDomain(req);
    const providedAddress = typeof address === 'string' ? address.trim() : '';
    const providedNonce = typeof nonce === 'string' ? nonce.trim() : '';

    const context: FailureContext = {
      address: providedAddress || undefined,
      nonce: providedNonce || undefined,
      domain: expectedDomain,
    };

    if (!providedAddress) {
      return fail(req, 400, 'address_invalid', context);
    }
    if (!providedNonce) {
      return fail(req, 400, 'nonce_invalid', context);
    }

    // Collect the various base64 aliases
    const signatureBase64Input: string | undefined =
      typeof signatureBase64 === 'string'
        ? signatureBase64
        : typeof signatureBytesBase64 === 'string'
        ? signatureBytesBase64
        : typeof signature_base64 === 'string'
        ? signature_base64
        : typeof signature_bytes_base64 === 'string'
        ? signature_bytes_base64
        : undefined;

    const parsedSignature = normalizeSignatureInput(signature, signatureBytes, signatureBase64Input);
    if ('error' in parsedSignature) {
      return fail(req, 400, 'signature_malformed', context);
    }
    if (parsedSignature.bytes.length !== 64) {
      return fail(req, 400, 'signature_malformed', context, { reason: 'bad_length' });
    }

    let publicKeyBytes: Uint8Array;
    try {
      publicKeyBytes = new PublicKey(providedAddress).toBytes();
    } catch {
      return fail(req, 400, 'address_invalid', context);
    }

    // Load nonce and enforce TTL
    const nonceRow = await getNonce(providedNonce);
    if (!nonceRow) {
      return fail(req, 400, 'nonce_invalid', context, { reason: 'not_found' });
    }

    const createdMs = new Date(nonceRow.created_at).getTime();
    if (!Number.isFinite(createdMs) || Date.now() - createdMs > NONCE_TTL_MS) {
      // Burn on expiry to prevent reuse if a clock skew occurs later
      await consumeNonce(nonceRow.id).catch(() => void 0);
      return fail(req, 400, 'nonce_invalid', context, { reason: 'expired' });
    }

    // If you persist domain with nonceRow, also check:
    // if (nonceRow.domain && nonceRow.domain !== expectedDomain) {
    //   await consumeNonce(nonceRow.id).catch(() => void 0);
    //   return fail(req, 400, 'nonce_invalid', context, { reason: 'domain_mismatch' });
    // }

    // Rebuild the exact message bytes that were signed
    const message = buildSiwsMessage(expectedDomain, providedAddress, providedNonce, nonceRow.created_at);
    const messageBytes = encoder.encode(message);

    // Verify
    if (!verifySignature(messageBytes, parsedSignature.bytes, publicKeyBytes)) {
      return fail(req, 400, 'bad_signature', context);
    }

    // Consume the nonce (one-time)
    const consumed = await consumeNonce(nonceRow.id).catch(() => false);
    if (!consumed) {
      // Already used or race condition
      return fail(req, 400, 'nonce_invalid', context, { reason: 'consumed' });
    }

    console.info('siws.finish.attempt', {
      address: providedAddress,
      nonce: providedNonce,
      origin: req.headers.get('origin') ?? undefined,
    });

    // Create / fetch user by wallet
    let userId: string;
    try {
      const user = await upsertUserByWallet(providedAddress);
      userId = user.id;
    } catch (e: any) {
      return fail(req, 500, 'db_error', context, { code: e?.code ?? 'unknown', hint: 'upsertUserByWallet' });
    }

    if (!env.SESSION_SECRET) {
      return fail(req, 500, 'missing_session_secret', context);
    }

    // Short-lived session; refresh via your own refresh endpoint if desired.
    const token = issueSessionJWT(userId);

    const res = NextResponse.json({ ok: true }, { status: 200 });
    // Ensure setSessionCookie sets: httpOnly, secure, sameSite (None if cross-site), and optionally `partitioned`.
    setSessionCookie(res, token);

    console.info('siws.finish.success', {
      address: providedAddress,
      nonce: providedNonce,
      userId,
      origin: req.headers.get('origin') ?? undefined,
    });

    return withCORS(req, res);
  } catch (error) {
    console.error('siws.finish.error', error);
    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
