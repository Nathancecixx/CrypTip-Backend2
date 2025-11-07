import { cookies } from 'next/headers';
import { z } from 'zod';
import { makeNonce, buildSiwsMessage } from '@/src/lib/auth';
import { corsHeaders, getAllowedOrigin, notAllowedResponse, preflight } from '@/src/lib/cors';
export const runtime = 'nodejs';

const Body = z.object({ wallet: z.string().min(32) });

export async function OPTIONS(req: Request) {
  return preflight(req);
}

export async function POST(req: Request) {
  const origin = getAllowedOrigin(req);
  if (!origin) return notAllowedResponse();

  const payload = Body.parse(await req.json());
  const nonce = makeNonce();
  cookies().set('ctj_nonce', nonce, { httpOnly: true, sameSite: 'none', secure: true, path: '/', maxAge: 600 });
  const message = buildSiwsMessage(payload.wallet, nonce);
  return Response.json({ nonce, message }, { headers: corsHeaders(origin) });
}
