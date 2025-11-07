import { cookies } from 'next/headers';
import { z } from 'zod';
import { makeNonce, buildSiwsMessage, cookiePolicyForRequest } from '@/src/lib/auth';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';
export const runtime = 'nodejs';

const Body = z.object({ wallet: z.string().min(32) });

export const OPTIONS = handleCorsOptions;

export async function POST(req: Request) {
  let payload;
  try {
    payload = Body.parse(await req.json());
  } catch {
    return withCORS(Response.json({ error: 'Invalid payload' }, { status: 400 }), req);
  }
  const nonce = makeNonce();
  const policy = cookiePolicyForRequest(req);
  cookies().set('ctj_nonce', nonce, {
    httpOnly: true,
    sameSite: policy.sameSite,
    secure: policy.secure,
    path: '/',
    maxAge: 600,
  });
  const message = buildSiwsMessage(payload.wallet, nonce);
  return withCORS(Response.json({ nonce, message }), req);
}
