import { cookies } from 'next/headers';
import { z } from 'zod';
import { makeNonce, buildSiwsMessage, cookiePolicyForRequest } from '@/src/lib/auth';
import { handleCorsOptions, withCors } from '@/src/middleware/cors';
export const runtime = 'nodejs';

const Body = z.object({ wallet: z.string().min(32) });

export const OPTIONS = handleCorsOptions;

export const POST = withCors(async (req: Request) => {
  let payload;
  try {
    payload = Body.parse(await req.json());
  } catch {
    return Response.json({ error: 'Invalid payload' }, { status: 400 });
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
  return Response.json({ nonce, message });
});
