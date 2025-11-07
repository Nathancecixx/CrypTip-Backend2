import { cookies } from 'next/headers';

import { handleCorsOptions, withCORS } from '@/src/lib/cors';
import { env } from '@/src/lib/env';

export const runtime = 'nodejs';

export const OPTIONS = handleCorsOptions;

export async function POST(req: Request) {
  const jar = cookies();
  jar.delete({ name: env.SESSION_COOKIE_NAME, path: '/' });
  return withCORS(Response.json({ success: true }), req);
}
