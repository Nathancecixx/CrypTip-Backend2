import bs58 from 'bs58';
import nacl from 'tweetnacl';
import { NextRequest, NextResponse } from 'next/server';

import { issueSessionJWT, setSessionCookie } from '@/src/lib/auth';
import { handleCorsOptions, validateRequestOrigin, withCORS } from '@/src/lib/cors';
import { upsertUserByWallet } from '@/src/lib/db';
import { consumeSiwsNonce } from '@/src/lib/nonce-store';

export const runtime = 'nodejs';
export const OPTIONS = handleCorsOptions;

type ParsedMessage = {
  domain?: string;
  address?: string;
  nonce?: string;
  issuedAt?: string;
};

function parseMessage(msg: string): ParsedMessage {
  const lines = msg.split('\n').map(line => line.trim());
  const extract = (key: string) =>
    (lines.find(line => line.startsWith(`${key}:`)) || '')
      .split(':')
      .slice(1)
      .join(':')
      .trim();

  return {
    domain: extract('Domain'),
    address: extract('Address'),
    nonce: extract('Nonce'),
    issuedAt: extract('Issued At'),
  };
}

export async function POST(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) {
    return validation.response;
  }

  const body = await req.json().catch(() => null);
  const address = typeof body?.address === 'string' ? body.address.trim() : '';
  const signatureB58 = typeof body?.signature === 'string' ? body.signature.trim() : '';
  const message = typeof body?.message === 'string' ? body.message : '';

  if (!address || !signatureB58 || !message) {
    return withCORS(
      req,
      NextResponse.json(
        {
          error: 'bad_request',
          fields: {
            address: Boolean(address),
            signature: Boolean(signatureB58),
            message: Boolean(message),
          },
        },
        { status: 400 }
      )
    );
  }

  const fields = parseMessage(message);
  if (!fields.nonce) {
    return withCORS(
      req,
      NextResponse.json({ error: 'nonce_missing' }, { status: 400 })
    );
  }

  const stored = consumeSiwsNonce(fields.nonce);
  if (!stored) {
    return withCORS(
      req,
      NextResponse.json({ error: 'nonce_invalid' }, { status: 400 })
    );
  }

  if (stored.address !== address) {
    return withCORS(
      req,
      NextResponse.json({ error: 'message_address_mismatch' }, { status: 400 })
    );
  }

  if (stored.message !== message) {
    return withCORS(
      req,
      NextResponse.json({ error: 'message_mismatch' }, { status: 400 })
    );
  }

  if (!fields.domain || fields.domain !== stored.domain) {
    return withCORS(
      req,
      NextResponse.json({ error: 'domain_mismatch' }, { status: 400 })
    );
  }

  if (stored.issuedAt) {
    const age = Date.now() - Date.parse(stored.issuedAt);
    if (Number.isFinite(age) && age > 10 * 60 * 1000) {
      return withCORS(
        req,
        NextResponse.json({ error: 'message_expired' }, { status: 400 })
      );
    }
  }

  try {
    const signature = bs58.decode(signatureB58);
    const publicKey = bs58.decode(address);
    const encodedMessage = new TextEncoder().encode(message);

    const ok = nacl.sign.detached.verify(encodedMessage, signature, publicKey);
    if (!ok) {
      return withCORS(
        req,
        NextResponse.json({ error: 'bad_signature' }, { status: 400 })
      );
    }
  } catch {
    return withCORS(
      req,
      NextResponse.json({ error: 'signature_malformed' }, { status: 400 })
    );
  }

  try {
    const user = await upsertUserByWallet(address);
    const token = issueSessionJWT(user.id);
    const response = NextResponse.json({ ok: true, userId: user.id }, { status: 200 });
    setSessionCookie(response, token);
    return withCORS(req, response);
  } catch (error: any) {
    return withCORS(
      req,
      NextResponse.json(
        {
          error: 'db_error',
          code: error?.code ?? 'unknown',
          hint: error?.hint ?? 'upsertUserByWallet',
        },
        { status: 500 }
      )
    );
  }
}
