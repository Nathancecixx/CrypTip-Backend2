import { NextRequest, NextResponse } from 'next/server';
import { withCORS, handleCorsOptions, validateRequestOrigin } from '@/src/lib/cors';
import { requireSession, UnauthorizedError } from '@/src/lib/auth';
import { listEntitlements } from '@/src/lib/db';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function GET(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) return withCORS(req, validation.response);

  try {
    const { userId } = requireSession(req);
    const rows = await listEntitlements(userId);
    return withCORS(req, NextResponse.json(rows, { status: 200 }));
  } catch (e) {
    if (e instanceof UnauthorizedError) {
      return withCORS(req, NextResponse.json({ error: 'unauthorized' }, { status: 401 }));
    }

    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
