import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { handleCorsOptions, withCORS, guardOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { buildSiwsMessage } from '@/src/lib/auth';
import { issueNonce } from '@/src/lib/nonce-store';

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

  const { address } = await req.json().catch(() => ({} as any));
  if (!address || typeof address !== 'string') {
    return withCORS(
      req,
      new NextResponse(JSON.stringify({ error: 'bad_request', fields: { address: 'required' } }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }),
    );
  }

  const expectedDomain = deriveExpectedDomain(req);

  const normalizedAddress = address.trim();
  if (!normalizedAddress) {
    return withCORS(
      req,
      new NextResponse(JSON.stringify({ error: 'bad_request', fields: { address: 'required' } }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }),
    );
  }

  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  const userAgent = req.headers.get('user-agent') ?? undefined;

  const { nonce, issuedAt } = await issueNonce({
    address: normalizedAddress,
    domain: expectedDomain,
    ip: ip || undefined,
    userAgent,
  });

  const message = buildSiwsMessage(expectedDomain, normalizedAddress, nonce, issuedAt);

  return withCORS(
    req,
    new NextResponse(JSON.stringify({ nonce, message }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  );
}
