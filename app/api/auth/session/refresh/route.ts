import { NextRequest, NextResponse } from 'next/server';
import { handleCorsOptions, validateRequestOrigin, withCORS } from '@/src/lib/cors';
import { issueSessionJWT, requireSession, setSessionCookie, UnauthorizedError } from '@/src/lib/auth';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) return validation.response;

  try {
    const { userId } = requireSession(req);
    const token = issueSessionJWT(userId);
    const res = NextResponse.json({ ok: true, userId }, { status: 200 });
    setSessionCookie(res, token);
    return withCORS(req, res);
  } catch (e) {
    if (e instanceof UnauthorizedError) {
      return withCORS(req, NextResponse.json({ error: 'unauthorized' }, { status: 401 }));
    }

    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
