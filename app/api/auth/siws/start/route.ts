import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { handleCorsOptions, withCORS, guardOrigin } from '@/src/lib/cors';
import { env } from '@/src/lib/env';
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

  const origin = req.headers.get('origin') ?? env.FRONTEND_ORIGIN;
  const domain = new URL(origin).host;

  const nonce = makeNonce();
  const { message } = buildSiwsMessage(address, nonce, {
    domain,
    resources: [env.FRONTEND_ORIGIN],
  });

  saveSiwsNonce({ address, nonce, message, issuedAt: new Date().toISOString() });

  return withCORS(
    req,
    new NextResponse(JSON.stringify({ nonce, message }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  );
}
