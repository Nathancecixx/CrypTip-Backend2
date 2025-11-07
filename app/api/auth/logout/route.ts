import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { env } from '@/src/lib/env';
import { withCORS, handleCorsOptions } from '@/src/lib/cors';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  const jar = cookies();
  // keep your existing cookie name + path semantics
  jar.delete({ name: env.SESSION_COOKIE_NAME, path: '/' });

  // Use NextResponse (not the web Response) so the type matches withCORS
  const res = NextResponse.json({ success: true }, { status: 200 });
  return withCORS(req, res);
}
