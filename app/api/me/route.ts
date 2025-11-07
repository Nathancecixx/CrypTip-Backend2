import { requireSession } from '@/src/lib/auth';
import { listEntitlements } from '@/src/lib/db';
import { handleCorsOptions, validateRequestOrigin, withCORS } from '@/src/lib/cors';
export const runtime = 'nodejs';

export const OPTIONS = handleCorsOptions;

export async function GET(req: Request) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok) {
    return validation.response;
  }

  let userId: string;
  try {
    ({ userId } = requireSession());
  } catch {
    const unauthorized = Response.json({ error: 'unauthorized' }, { status: 401 });
    unauthorized.headers.set('WWW-Authenticate', 'Bearer realm="siws"');
    return withCORS(unauthorized, validation.evaluation);
  }

  try {
    const entitlements = await listEntitlements(userId);
    return withCORS(Response.json({ me: { id: userId }, entitlements }), validation.evaluation);
  } catch {
    return withCORS(
      Response.json({ error: 'Failed to load profile' }, { status: 500 }),
      validation.evaluation,
    );
  }
}
