import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { handleCorsOptions, withCORS, validateRequestOrigin } from '@/src/lib/cors';
import { clearSessionCookie } from '@/src/lib/auth';

export const runtime = 'nodejs';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  const originCheck = validateRequestOrigin(req);
  if (!originCheck.ok && originCheck.response) return withCORS(req, originCheck.response);

  const res = NextResponse.json({ ok: true }, { status: 200 });
  // Clear the cookie with matching attributes
  clearSessionCookie(res);
  return withCORS(req, res);
}
