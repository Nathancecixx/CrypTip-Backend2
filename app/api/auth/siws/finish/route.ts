import { verifySignature, setSessionCookie } from '@/src/lib/auth';
import { upsertUserByWallet } from '@/src/lib/db';
import { handleCorsOptions, validateRequestOrigin, withCORS } from '@/src/lib/cors';
import { consumeSiwsNonce } from '@/src/lib/nonce-store';
export const runtime = 'nodejs';

export const OPTIONS = handleCorsOptions;

export async function POST(req: Request) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok) {
    return validation.response;
  }

  let payload: any;
  try {
    payload = await req.json();
  } catch {
    return withCORS(Response.json({ error: 'bad_request' }, { status: 400 }), validation.evaluation);
  }

  const fieldErrors: Record<string, string> = {};

  const addressRaw = payload?.address;
  const signatureRaw = payload?.signature;
  const nonceRaw = payload?.nonce;

  const address = typeof addressRaw === 'string' ? addressRaw.trim() : '';
  const signature = typeof signatureRaw === 'string' ? signatureRaw.trim() : '';
  const nonce = typeof nonceRaw === 'string' ? nonceRaw.trim() : '';

  if (!address) {
    fieldErrors.address = 'required';
  }
  if (!signature) {
    fieldErrors.signature = 'required';
  }
  if (!nonce) {
    fieldErrors.nonce = 'required';
  }

  if (Object.keys(fieldErrors).length > 0) {
    return withCORS(
      Response.json({ error: 'bad_request', fields: fieldErrors }, { status: 400 }),
      validation.evaluation,
    );
  }

  const stored = consumeSiwsNonce(nonce);
  if (!stored || stored.address !== address) {
    return withCORS(Response.json({ error: 'invalid_nonce' }, { status: 400 }), validation.evaluation);
  }

  const ok = verifySignature(stored.message, signature, address);
  if (!ok) {
    return withCORS(Response.json({ error: 'invalid_signature' }, { status: 400 }), validation.evaluation);
  }

  const user = await upsertUserByWallet(address);
  setSessionCookie(req, user.id);
  return withCORS(Response.json({ user: { id: user.id, address } }), validation.evaluation);
}
