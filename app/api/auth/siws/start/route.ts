import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { handleCorsOptions, withCORS, guardOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { buildSiwsMessage } from '@/src/lib/auth';
import { issueNonce } from '@/src/lib/nonce-store';

const ADDRESS_PLACEHOLDER = '<WALLET_ADDRESS>';

function deriveExpectedDomain(req: NextRequest): string {
  const origin = req.headers.get('origin');
  if (origin) {
    try {
      return new URL(origin).hostname;
    } catch {
      // fall through to fallback below
    }
  }
  return resolveAllowedRequestDomain(req);
}

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  const guard = guardOrigin(req);
  if (!guard.ok) return withCORS(req, guard.res);

  const expectedDomain = deriveExpectedDomain(req);
  const { nonce, createdAt } = await issueNonce();

  const message = buildSiwsMessage(expectedDomain, ADDRESS_PLACEHOLDER, nonce, createdAt);

  return withCORS(
    req,
    new NextResponse(JSON.stringify({ nonce, message }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  );
}
