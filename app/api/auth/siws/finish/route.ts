import { z } from 'zod';
import { cookies } from 'next/headers';
import { verifySignature, setSessionCookie } from '@/src/lib/auth';
import { upsertUserByWallet } from '@/src/lib/db';
import { handleCorsOptions, withCors } from '@/src/middleware/cors';
export const runtime = 'nodejs';

const Body = z.object({ wallet: z.string(), signature: z.string(), message: z.string() });

export const OPTIONS = handleCorsOptions;

export const POST = withCors(async (req: Request) => {
  let payload;
  try {
    payload = Body.parse(await req.json());
  } catch {
    return Response.json({ error: 'Invalid payload' }, { status: 400 });
  }
  const { wallet, signature, message } = payload;
  const nonceCookie = cookies().get('ctj_nonce')?.value;
  if (!nonceCookie || !message.includes(`Nonce: ${nonceCookie}`)) {
    return Response.json({ error: 'Bad nonce' }, { status: 400 });
  }
  const ok = verifySignature(message, signature, wallet);
  if (!ok) return Response.json({ error: 'Invalid signature' }, { status: 401 });

  const user = await upsertUserByWallet(wallet);
  setSessionCookie(req, user.id);
  return Response.json({ user: { id: user.id, wallet } });
});
