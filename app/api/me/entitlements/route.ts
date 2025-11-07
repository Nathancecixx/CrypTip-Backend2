import { requireSession } from '@/src/lib/auth';
import { listEntitlements } from '@/src/lib/db';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';

export const OPTIONS = handleCorsOptions;

export async function GET(req: Request) {
  let userId: string;
  try {
    ({ userId } = requireSession());
  } catch {
    return withCORS(Response.json({ error: 'Unauthorized' }, { status: 401 }), req);
  }

  try {
    const entitlements = await listEntitlements(userId);
    return withCORS(Response.json({ entitlements }), req);
  } catch {
    return withCORS(Response.json({ error: 'Failed to load entitlements' }, { status: 500 }), req);
  }
}
