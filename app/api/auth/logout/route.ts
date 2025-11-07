import { NextRequest } from 'next/server';
import { cookies } from 'next/headers';
import { env } from '@/src/lib/env';
import { withCORS, handleCorsOptions } from '@/src/lib/cors';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  const jar = cookies();
  jar.delete({ name: env.SESSION_COOKIE_NAME, path: '/' });

  // IMPORTANT: withCORS(req, res)  — old code had the args reversed
  return withCORS(req, new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  }));
}
