import { z } from 'zod';
import { makeNonce, buildSiwsMessage } from '@/src/lib/auth';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';
import { saveSiwsNonce } from '@/src/lib/nonce-store';
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
  const { message, fields } = buildSiwsMessage(payload.wallet, nonce);

  saveSiwsNonce({ wallet: payload.wallet, nonce, issuedAt: fields.issuedAt, message });

  return withCORS(
    Response.json({
      nonce,
      message,
      domain: fields.domain,
      statement: fields.statement,
      address: fields.address,
      chainId: fields.chainId,
      issuedAt: fields.issuedAt,
      resources: fields.resources,
    }),
    req,
  );
}
