import type { NextRequest } from 'next/server';
import { withCORS, handleCorsOptions, validateRequestOrigin } from '@/src/lib/cors';
import { verifySignature, setSessionCookie } from '@/src/lib/auth';
import { consumeSiwsNonce, extractNonceFromMessage } from '@/src/lib/nonce-store';
import { upsertUserByWallet } from '@/src/lib/db';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok) return validation.response;

  const { address, signature, message } = await req.json().catch(() => ({}));
  if (!address || !signature || !message) {
    const bad = new Response(JSON.stringify({ error: 'missing fields' }), {
      status: 400,
      headers: { 'content-type': 'application/json' },
    });
    return withCORS(bad, validation.evaluation);
  }

  const nonce = extractNonceFromMessage(message);
  if (!nonce) {
    const bad = new Response(JSON.stringify({ error: 'nonce_missing' }), { status: 400, headers: { 'content-type': 'application/json' } });
    return withCORS(bad, validation.evaluation);
  }

  const stored = consumeSiwsNonce(nonce);
  if (!stored || stored.address !== address || stored.message !== message) {
    const bad = new Response(JSON.stringify({ error: 'nonce_invalid' }), { status: 400, headers: { 'content-type': 'application/json' } });
    return withCORS(bad, validation.evaluation);
  }

  const ok = verifySignature(message, signature, address);
  if (!ok) {
    const bad = new Response(JSON.stringify({ error: 'bad_signature' }), { status: 401, headers: { 'content-type': 'application/json' } });
    return withCORS(bad, validation.evaluation);
  }

  const user = await upsertUserByWallet(address);
  setSessionCookie(req, user.id);

  const res = new Response(JSON.stringify({ ok: true, userId: user.id }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
  return withCORS(res, validation.evaluation);
}
