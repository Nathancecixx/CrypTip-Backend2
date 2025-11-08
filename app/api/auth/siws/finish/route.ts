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

function deriveExpectedDomain(req: NextRequest): string {
  const origin = req.headers.get('origin');
  if (origin) {
    try {
      return new URL(origin).hostname;
    } catch {
      // fall through to resolver below
    }
  }
  return resolveAllowedRequestDomain(req);
}

type FailureCode = 'nonce_invalid' | 'signature_malformed' | 'bad_signature';

type FailureContext = {
  address?: string;
  nonce?: string;
  domain: string;
};

function logReject(reason: string, context: FailureContext, extra: Record<string, unknown> = {}) {
  try {
    const logger = reason === 'nonce_invalid' ? console.info : console.warn;
    logger('siws.finish.reject', { reason, ...context, ...extra });
  } catch {
    // logging best-effort
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
    const providedNonce = typeof nonce === 'string' ? nonce.trim() : '';
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
    const expectedDomain = deriveExpectedDomain(req);

    if (typeof address !== 'string' || !address.trim()) {
      return fail(
        req,
        400,
        'nonce_invalid',
        {
          address: undefined,
          nonce: providedNonce || undefined,
          domain: expectedDomain,
        },
      );
    }

    const normalizedAddress = address.trim();
    const context: FailureContext = {
      address: normalizedAddress,
      nonce: providedNonce || undefined,
      domain: expectedDomain,
    };

    if (!providedNonce) {
      return fail(req, 400, 'nonce_invalid', context);
    }

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

    const nonceRow = await getNonce(providedNonce);
    if (!nonceRow) {
      return fail(req, 400, 'nonce_invalid', context);
    }

    const message = buildSiwsMessage(expectedDomain, normalizedAddress, providedNonce, nonceRow.created_at);
    const messageBytes = encoder.encode(message);

    if (!verifySignature(messageBytes, parsedSignature.bytes, publicKeyBytes)) {
      return fail(req, 400, 'bad_signature', context);
    }

    const consumed = await consumeNonce(nonceRow.id);
    if (!consumed) {
      return fail(req, 400, 'nonce_invalid', context);
    }

    console.info('siws.finish.attempt', {
      address: normalizedAddress,
      nonce: providedNonce,
      origin: req.headers.get('origin') ?? undefined,
    });

    let userId: string;
    try {
      const user = await upsertUserByWallet(normalizedAddress);
      userId = user.id;
    } catch (e: any) {
      logReject('db_error', context, { code: e?.code ?? 'unknown' });
      return withCORS(
        req,
        NextResponse.json({ error: 'db_error', code: e?.code ?? 'unknown', hint: 'upsertUserByWallet' }, { status: 500 }),
      );
    }

    if (!env.SESSION_SECRET) {
      logReject('missing_session_secret', context);
      return withCORS(req, NextResponse.json({ error: 'missing_session_secret' }, { status: 500 }));
    }

    const token = issueSessionJWT(userId);
    const res = NextResponse.json({ ok: true }, { status: 200 });
    setSessionCookie(res, token);

    console.info('siws.finish.success', {
      address: normalizedAddress,
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
