import { z } from 'zod';
import { verifySignature, setSessionCookie } from '@/src/lib/auth';
import { upsertUserByWallet } from '@/src/lib/db';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';
import { consumeSiwsNonce, extractNonceFromMessage } from '@/src/lib/nonce-store';
export const runtime = 'nodejs';

const Body = z.object({ wallet: z.string(), signature: z.string(), message: z.string() });

export const OPTIONS = handleCorsOptions;

export async function POST(req: Request) {
  let payload;
  try {
    payload = Body.parse(await req.json());
  } catch {
    return withCORS(Response.json({ error: 'Invalid payload' }, { status: 400 }), req);
  }
  const { wallet, signature, message } = payload;
  const nonce = extractNonceFromMessage(message);
  if (!nonce) {
    return withCORS(Response.json({ error: 'Bad nonce' }, { status: 400 }), req);
  }

  const stored = consumeSiwsNonce(nonce);
  if (!stored || stored.wallet !== wallet || stored.message !== message) {
    return withCORS(Response.json({ error: 'Bad nonce' }, { status: 400 }), req);
  }

  const ok = verifySignature(stored.message, signature, wallet);
  if (!ok) {
    return withCORS(Response.json({ error: 'Invalid signature' }, { status: 401 }), req);
  }

  const user = await upsertUserByWallet(wallet);
  setSessionCookie(req, user.id);
  return withCORS(Response.json({ user: { id: user.id, wallet } }), req);
}
