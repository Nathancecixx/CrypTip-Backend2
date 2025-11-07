import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { env } from '@/src/lib/env';
import { handleCorsOptions, withCORS, validateRequestOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { buildSiwsMessage, makeNonce } from '@/src/lib/auth';
import { saveSiwsNonce } from '@/src/lib/nonce-store';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) return validation.response;

  const { address } = await req.json().catch(() => ({} as any));
  if (!address || typeof address !== 'string') {
    return withCORS(
      req,
      NextResponse.json({ error: 'bad_request', fields: { address: 'required' } }, { status: 400 })
    );
  }

  const domain = resolveAllowedRequestDomain(req);

  const nonce = makeNonce();
  const message = buildSiwsMessage(domain, address, nonce);

  saveSiwsNonce({
    address,
    nonce,
    issuedAt: new Date().toISOString(),
    message,
  });

  return withCORS(req, NextResponse.json({ nonce, message }, { status: 200 }));
}
