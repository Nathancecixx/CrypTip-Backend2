import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { handleCorsOptions, withCORS, validateRequestOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { buildSiwsMessage } from '@/src/lib/auth';
import { issueNonce } from '@/src/lib/nonce-store';
import { env } from '@/src/lib/env';

export const runtime = 'nodejs';

const ADDRESS_PLACEHOLDER = '<WALLET_ADDRESS>';
const NONCE_TTL_MS = 10 * 60 * 1000;

function deriveExpectedDomain(req: NextRequest): string {
  if (env.SIWS_DOMAIN && env.SIWS_DOMAIN.trim()) return env.SIWS_DOMAIN.trim();
  return resolveAllowedRequestDomain(req);
}

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  try {
    const originCheck = validateRequestOrigin(req);
    if (!originCheck.ok && originCheck.response) return withCORS(req, originCheck.response);

    const expectedDomain = deriveExpectedDomain(req);

    // If your nonce-store supports metadata, pass { domain: expectedDomain }
    const { nonce, createdAt } = await issueNonce();

    const message = buildSiwsMessage(expectedDomain, ADDRESS_PLACEHOLDER, nonce, createdAt);
    const res = NextResponse.json(
      { nonce, message, expiresAt: new Date(new Date(createdAt).getTime() + NONCE_TTL_MS).toISOString() },
      { status: 200 },
    );
    return withCORS(req, res);
  } catch (err) {
    console.error('siws.start.error', err);
    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
