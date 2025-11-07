import type { NextRequest } from 'next/server';
import { withCORS, handleCorsOptions, validateRequestOrigin } from '@/src/lib/cors';
import { requireSession, UnauthorizedError } from '@/src/lib/auth';
import { listEntitlements } from '@/src/lib/db';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function GET(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok) return validation.response;

  try {
    const { userId } = requireSession();
    const rows = await listEntitlements(userId);
    const res = new Response(JSON.stringify(rows), { status: 200, headers: { 'content-type': 'application/json' } });
    return withCORS(res, validation.evaluation);
  } catch (e) {
    const code = e instanceof UnauthorizedError ? 401 : 500;
    const res = new Response(JSON.stringify({ error: 'unauthorized' }), { status: code, headers: { 'content-type': 'application/json' } });
    return withCORS(res, validation.evaluation);
  }
}
