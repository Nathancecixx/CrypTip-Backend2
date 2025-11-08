import { NextRequest, NextResponse } from 'next/server';
import { withCORS, handleCorsOptions, validateRequestOrigin } from '@/src/lib/cors';
import { requireSessionMiddleware } from '@/src/lib/auth';
import { listEntitlements } from '@/src/lib/db';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function GET(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) return withCORS(req, validation.response);

  const sessionResult = requireSessionMiddleware(req);
  if (!sessionResult.ok) return withCORS(req, sessionResult.response);
  const { userId } = sessionResult.session;

  try {
    const rows = await listEntitlements(userId);
    return withCORS(req, NextResponse.json({ entitlements: rows }, { status: 200 }));
  } catch (e) {
    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
