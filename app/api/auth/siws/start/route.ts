import { cookies } from 'next/headers';
import { z } from 'zod';
import { makeNonce, buildSiwsMessage } from '@/src/lib/auth';
export const runtime = 'nodejs';

const Body = z.object({ wallet: z.string().min(32) });

export async function POST(req: Request) {
  const payload = Body.parse(await req.json());
  const nonce = makeNonce();
  cookies().set('ctj_nonce', nonce, { httpOnly: true, sameSite: 'lax', secure: true, path: '/', maxAge: 600 });
  const message = buildSiwsMessage(payload.wallet, nonce);
  return Response.json({ nonce, message });
}
