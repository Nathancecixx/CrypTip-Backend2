import { NextRequest, NextResponse } from 'next/server';

import { makeNonce, buildSiwsMessage } from '@/src/lib/auth';
import { handleCorsOptions, resolveAllowedRequestDomain, validateRequestOrigin, withCORS } from '@/src/lib/cors';
import { env } from '@/src/lib/env';
import { saveSiwsNonce } from '@/src/lib/nonce-store';

export const runtime = 'nodejs';
export const OPTIONS = handleCorsOptions;

export async function POST(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) {
    return validation.response;
  }

  const body = await req.json().catch(() => ({} as Record<string, unknown>));
  const address = typeof body.address === 'string' ? body.address.trim() : '';
  if (!address) {
    return withCORS(
      req,
      NextResponse.json(
        { error: 'bad_request', fields: { address: 'required' } },
        { status: 400 }
      )
    );
  }

  const domain = resolveAllowedRequestDomain(req, validation.evaluation);
  const nonce = makeNonce();
  const { message, issuedAt } = buildSiwsMessage(address, nonce, {
    domain,
    resources: env.FRONTEND_ORIGIN ? [env.FRONTEND_ORIGIN] : undefined,
  });

  saveSiwsNonce({ address, domain, nonce, issuedAt, message });

  return withCORS(req, NextResponse.json({ domain, nonce, message }, { status: 200 }));
}
