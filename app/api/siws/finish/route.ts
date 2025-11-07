import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { handleCorsOptions, withCORS, guardOrigin } from '@/src/lib/cors';
import { verifySignature, setSessionCookie } from '@/src/lib/auth';
import { consumeSiwsNonce, extractNonceFromMessage } from '@/src/lib/nonce-store';
import { upsertUserByWallet } from '@/src/lib/db';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  const guard = guardOrigin(req);
  if (!guard.ok) return withCORS(req, guard.res);

  const { address, signature, message, nonce } = await req.json().catch(() => ({} as any));
  if (!address || !signature || !message) {
    return withCORS(
      req,
      new NextResponse(
        JSON.stringify({ error: 'bad_request', fields: { address: 'required', signature: 'required', message: 'required' } }),
        { status: 400, headers: { 'content-type': 'application/json' } }
      )
    );
  }

  const extracted = extractNonceFromMessage(message);
  if (!nonce || !extracted || extracted !== nonce) {
    return withCORS(
      req,
      new NextResponse(JSON.stringify({ error: 'bad_request', fields: { nonce: 'required' } }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      })
    );
  }

  const init = consumeSiwsNonce(nonce);
  if (!init || init.address !== address || init.message !== message) {
    return withCORS(
      req,
      new NextResponse(JSON.stringify({ error: 'nonce_invalid' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      })
    );
  }

  if (!verifySignature(message, signature, address)) {
    return withCORS(
      req,
      new NextResponse(JSON.stringify({ error: 'bad_signature' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      })
    );
  }

  const user = await upsertUserByWallet(address);
  setSessionCookie(req, user.id);

  return withCORS(
    req,
    new NextResponse(JSON.stringify({ ok: true, userId: user.id }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  );
}
