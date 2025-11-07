import { NextRequest, NextResponse } from 'next/server';
import { requireSession, logUnauthorizedAccess } from '@/src/lib/auth';
import { getPageByWallet, getUserById } from '@/src/lib/db';
import { handleCorsOptions, validateRequestOrigin, withCORS } from '@/src/lib/cors';

export const runtime = 'nodejs';
export const OPTIONS = handleCorsOptions;

export async function GET(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) return withCORS(req, validation.response);

  let userId: string;
  try {
    ({ userId } = requireSession(req));
  } catch (error) {
    logUnauthorizedAccess(req, error);
    return withCORS(req, NextResponse.json({ error: 'unauthorized' }, { status: 401 }));
  }

  try {
    const user = await getUserById(userId);
    if (!user) {
      return withCORS(req, NextResponse.json({ error: 'Not found' }, { status: 404 }));
    }

    const candidates = Array.from(
      new Set(
        [user.handle ?? undefined, user.wallet_pubkey]
          .filter((value): value is string => typeof value === 'string' && value.length > 0),
      ),
    );

    for (const candidate of candidates) {
      const page = await getPageByWallet(candidate);
      if (page) {
        return withCORS(req, NextResponse.json({ page }, { status: 200 }));
      }
    }

    return withCORS(req, NextResponse.json({ error: 'Not found' }, { status: 404 }));
  } catch {
    return withCORS(req, NextResponse.json({ error: 'Failed to load page' }, { status: 500 }));
  }
}
