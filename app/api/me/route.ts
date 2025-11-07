import { requireSession } from '@/src/lib/auth';
import { listEntitlements } from '@/src/lib/db';
import { corsHeaders, getAllowedOrigin, notAllowedResponse, preflight } from '@/src/lib/cors';
export const runtime = 'nodejs';

export async function OPTIONS(req: Request) {
  return preflight(req);
}

export async function GET(req: Request) {
  const origin = getAllowedOrigin(req);
  if (!origin) return notAllowedResponse();

  let auth;
  try {
    auth = requireSession();
  } catch {
    return new Response('Unauthorized', { status: 401, headers: corsHeaders(origin) });
  }
  const ents = await listEntitlements(auth.userId);
  return Response.json({ me: { id: auth.userId }, entitlements: ents }, { headers: corsHeaders(origin) });
}
