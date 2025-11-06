import { requireSession } from '@/src/lib/auth';
import { listEntitlements } from '@/src/lib/db';
export const runtime = 'nodejs';

export async function GET() {
  let auth; try { auth = requireSession(); } catch { return new Response('Unauthorized', { status: 401 }); }
  const ents = await listEntitlements(auth.userId);
  return Response.json({ me: { id: auth.userId }, entitlements: ents });
}
