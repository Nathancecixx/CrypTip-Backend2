import { NextRequest, NextResponse } from 'next/server';
import { requireSession } from '@/src/lib/auth';
import { listEntitlements } from '@/src/lib/db';
import { handleCorsOptions, validateRequestOrigin, withCORS } from '@/src/lib/cors';

export const runtime = 'nodejs';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function GET(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) return validation.response;

  try {
    const { userId } = requireSession();
    const entitlements = await listEntitlements(userId);
    return withCORS(req, NextResponse.json({ me: { id: userId }, entitlements }, { status: 200 }));
  } catch {
    const res = NextResponse.json(
      { error: 'unauthorized' },
      { status: 401, headers: { 'WWW-Authenticate': 'Bearer realm="siws"' } }
    );
    return withCORS(req, res);
  }
}
