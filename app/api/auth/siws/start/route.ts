import { makeNonce, buildSiwsMessage } from '@/src/lib/auth';
import { handleCorsOptions, validateRequestOrigin, withCORS } from '@/src/lib/cors';
import { saveSiwsNonce } from '@/src/lib/nonce-store';
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

  const address = typeof payload?.address === 'string' ? payload.address.trim() : '';

  if (!address) {
    return withCORS(
      Response.json({ error: 'bad_request', fields: { address: 'required' } }, { status: 400 }),
      validation.evaluation,
    );
  }

  const nonce = makeNonce();
  const { message, fields } = buildSiwsMessage(address, nonce);

  saveSiwsNonce({ address, nonce, issuedAt: fields.issuedAt, message });

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
    validation.evaluation,
  );
}
