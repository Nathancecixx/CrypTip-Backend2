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

export const runtime = 'nodejs';

const ADDRESS_PLACEHOLDER = '<WALLET_ADDRESS>';

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

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) {
    return withCORS(req, validation.response);
  }

  const expectedDomain = deriveExpectedDomain(req);
  const { nonce, createdAt } = await issueNonce();

  const message = buildSiwsMessage(expectedDomain, ADDRESS_PLACEHOLDER, nonce, createdAt);

  return withCORS(
    req,
    NextResponse.json(
      { nonce, message },
      {
        status: 200,
        headers: { 'Cache-Control': 'no-store' },
      },
    ),
  );
}
