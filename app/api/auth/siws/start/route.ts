import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import {
  handleCorsOptions,
  withCORS,
  validateRequestOrigin,
  resolveAllowedRequestDomain,
} from '@/src/lib/cors';
import { buildSiwsMessage } from '@/src/lib/auth';
import { issueNonce } from '@/src/lib/nonce-store';
import { env } from '@/src/lib/env';

export const runtime = 'nodejs';

const ADDRESS_PLACEHOLDER = '<WALLET_ADDRESS>';
const NONCE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function deriveExpectedDomain(req: NextRequest): string {
  // Prefer a canonical domain from env; fall back to allowed resolver.
  if (env.SIWS_DOMAIN && env.SIWS_DOMAIN.trim()) return env.SIWS_DOMAIN.trim();
  return resolveAllowedRequestDomain(req);
}

export async function OPTIONS(req: NextRequest) {
  // Must reply with proper CORS headers on preflight
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  // Strict origin validation and consistent CORS response
  const originCheck = validateRequestOrigin(req);
  if (!originCheck.ok && originCheck.response) return withCORS(req, originCheck.response);

  const expectedDomain = deriveExpectedDomain(req);

  // Create a one-time nonce. (If your nonce store supports metadata, also persist { domain: expectedDomain }.)
  const { nonce, createdAt } = await issueNonce();

  // Build the canonical message the wallet should sign (address is filled on client)
  const message = buildSiwsMessage(expectedDomain, ADDRESS_PLACEHOLDER, nonce, createdAt);

  const res = new NextResponse(
    JSON.stringify({
      nonce,
      message,
      expiresAt: new Date(new Date(createdAt).getTime() + NONCE_TTL_MS).toISOString(),
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );

  return withCORS(req, res);
}
