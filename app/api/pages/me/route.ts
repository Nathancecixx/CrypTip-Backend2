import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { handleCorsOptions, withCORS, validateRequestOrigin } from '@/src/lib/cors';
import { getSessionFromRequest } from '@/src/lib/session';
import { getOrCreateDefaultPageForUser } from '@/src/lib/pages'; // implement in lib/pages.ts

export const runtime = 'nodejs';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function GET(req: NextRequest) {
  const originCheck = validateRequestOrigin(req);
  if (!originCheck.ok && originCheck.response) return withCORS(req, originCheck.response);

  const sess = await getSessionFromRequest(req);
  if (!sess) return withCORS(req, NextResponse.json({ error: 'unauthorized' }, { status: 401 }));

  try {
    const page = await getOrCreateDefaultPageForUser(sess.sub);
    return withCORS(req, NextResponse.json(page, { status: 200 }));
  } catch (e) {
    console.error('pages.me.error', e);
    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
