import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { handleCorsOptions, withCORS, guardOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { makeNonce, buildSiwsMessage } from '@/src/lib/auth';
import { saveSiwsNonce } from '@/src/lib/nonce-store';

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

  const domain = resolveAllowedRequestDomain(req);

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

  const nonce = makeNonce();
  const issuedAt = new Date().toISOString();
  const message = buildSiwsMessage(domain, normalizedAddress, nonce, issuedAt);

  saveSiwsNonce({ address: normalizedAddress, nonce, issuedAt, message });

  return withCORS(
    req,
    new NextResponse(JSON.stringify({ nonce, message }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  );
}
