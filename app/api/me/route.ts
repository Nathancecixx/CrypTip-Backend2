import { NextRequest, NextResponse } from 'next/server';
import { requireSession, logUnauthorizedAccess } from '@/src/lib/auth';
import { listEntitlements } from '@/src/lib/db';
import { handleCorsOptions, validateRequestOrigin, withCORS } from '@/src/lib/cors';

export const runtime = 'nodejs';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function GET(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) return withCORS(req, validation.response);

  try {
    const { userId } = requireSession(req);
    const entitlements = await listEntitlements(userId);
    return withCORS(req, NextResponse.json({ me: { id: userId }, entitlements }, { status: 200 }));
  } catch (error) {
    logUnauthorizedAccess(req, error);
    return withCORS(req, NextResponse.json({ error: 'unauthorized' }, { status: 401 }));
  }
}
