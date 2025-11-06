import { z } from 'zod';
import { cookies } from 'next/headers';
import { verifySignature, setSessionCookie } from '@/src/lib/auth';
import { upsertUserByWallet } from '@/src/lib/db';
export const runtime = 'nodejs';

const Body = z.object({ wallet: z.string(), signature: z.string(), message: z.string() });

export async function POST(req: Request) {
  const { wallet, signature, message } = Body.parse(await req.json());
  const nonceCookie = cookies().get('ctj_nonce')?.value;
  if (!nonceCookie || !message.includes(`Nonce: ${nonceCookie}`)) {
    return new Response('Bad nonce', { status: 400 });
  }
  const ok = verifySignature(message, signature, wallet);
  if (!ok) return new Response('Invalid signature', { status: 401 });

  const user = await upsertUserByWallet(wallet);
  setSessionCookie(user.id);
  return Response.json({ user: { id: user.id, wallet } });
}
