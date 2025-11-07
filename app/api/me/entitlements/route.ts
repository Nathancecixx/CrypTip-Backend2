import { corsHeaders, getAllowedOrigin, notAllowedResponse, preflight } from '@/src/lib/cors';

export async function OPTIONS(req: Request) {
  return preflight(req);
}

export async function GET(req: Request) {
  const origin = getAllowedOrigin(req);
  if (!origin) return notAllowedResponse();

  const auth = req.headers.get('authorization');
  if (!auth?.startsWith('Bearer ')) {
    return Response.json({ error: 'Missing or invalid Authorization header' }, {
      status: 401,
      headers: corsHeaders(origin),
    });
  }

  const token = auth.slice('Bearer '.length).trim();
  void token; // TODO: verify token and derive user id…

  return Response.json({ entitlements: [] }, { headers: corsHeaders(origin) });
}
