import { env } from './env';

const ALLOWED_ORIGIN = env.FRONTEND_ORIGIN;

export function getAllowedOrigin(req: Request): string | null {
  const origin = req.headers.get('origin');
  if (!origin) return ALLOWED_ORIGIN;
  return origin === ALLOWED_ORIGIN ? origin : null;
}

export function corsHeaders(origin: string): HeadersInit {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Vary': 'Origin',
  };
}

export function preflight(req: Request): Response {
  const origin = getAllowedOrigin(req);
  if (!origin) {
    return new Response(null, { status: 403, headers: { Vary: 'Origin' } });
  }
  return new Response(null, { status: 204, headers: corsHeaders(origin) });
}

export function notAllowedResponse(): Response {
  return new Response('Origin not allowed', { status: 403, headers: { Vary: 'Origin' } });
}
