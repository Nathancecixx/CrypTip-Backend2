import { makeNonce, buildSiwsMessage } from '@/src/lib/auth';
import { env } from '@/src/lib/env';
import {
  handleCorsOptions,
  resolveAllowedRequestDomain,
  validateRequestOrigin,
  withCORS,
} from '@/src/lib/cors';
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
  const domain =
    resolveAllowedRequestDomain(req, validation.evaluation) ?? validation.evaluation.originUrl?.host ??
    env.SIWS_DOMAIN;
  const resources = validation.evaluation.origin ? [validation.evaluation.origin] : undefined;
  const { message, fields } = buildSiwsMessage(address, nonce, { domain, resources });

  saveSiwsNonce({ address, nonce, issuedAt: fields.issuedAt, message });

  return withCORS(Response.json({ nonce, message }), validation.evaluation);
}
