import { requireSession } from '@/src/lib/auth';
import { listEntitlements } from '@/src/lib/db';
import { handleCorsOptions, withCors } from '@/src/middleware/cors';
export const runtime = 'nodejs';

export const OPTIONS = handleCorsOptions;

export const GET = withCors(async () => {
  let userId: string;
  try {
    ({ userId } = requireSession());
  } catch {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const entitlements = await listEntitlements(userId);
    return Response.json({ me: { id: userId }, entitlements });
  } catch {
    return Response.json({ error: 'Failed to load profile' }, { status: 500 });
  }
});
