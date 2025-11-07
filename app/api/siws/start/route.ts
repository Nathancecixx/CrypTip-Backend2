import type { NextRequest } from 'next/server';
import { env } from '@/src/lib/env';
import { withCORS, handleCorsOptions, validateRequestOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { buildSiwsMessage, makeNonce } from '@/src/lib/auth';
import { saveSiwsNonce } from '@/src/lib/nonce-store';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok) return validation.response;

  const { address } = await req.json().catch(() => ({}));
  if (!address || typeof address !== 'string') {
    const bad = new Response(JSON.stringify({ error: 'address required' }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    });
    return withCORS(bad, validation.evaluation);
  }

  const domain = resolveAllowedRequestDomain(req, validation.evaluation) ?? env.SIWS_DOMAIN;
  const nonce = makeNonce();

  const { message } = buildSiwsMessage(address, nonce, {
    domain,
    resources: [env.FRONTEND_ORIGIN],
  });

  saveSiwsNonce({
    address,
    nonce,
    issuedAt: new Date().toISOString(),
    message,
  });

  const res = new Response(JSON.stringify({ nonce, message }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
  return withCORS(res, validation.evaluation);
}
