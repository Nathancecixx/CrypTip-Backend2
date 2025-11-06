import { z } from 'zod';
import { requireSession } from '@/src/lib/auth';
import { createOrUpdatePage, getUserById, listEntitlements } from '@/src/lib/db';
import { authorizePageUpdate, ForbiddenError } from '@/src/lib/pageAccess';
export const runtime = 'nodejs';

const Body = z.object({
  slug: z.string().min(3).optional(),
  template_key: z.string().default('base.simple'),
  theme_json: z.any().default({}),
  custom_domain: z.string().optional(),
});

export async function POST(req: Request) {
  let auth; try { auth = requireSession(); } catch { return new Response('Unauthorized', { status: 401 }); }
  const body = Body.parse(await req.json());
  const entitlements = await listEntitlements(auth.userId);
  const user = await getUserById(auth.userId);
  if (!user) {
    return new Response('Unauthorized', { status: 401 });
  }

  let payload;
  try {
    payload = authorizePageUpdate(body, { entitlements, wallet: user.wallet_pubkey });
  } catch (err) {
    if (err instanceof ForbiddenError) {
      return new Response('Forbidden', { status: 403 });
    }
    throw err;
  }

  const page = await createOrUpdatePage(auth.userId, payload);
  return Response.json({ page });
}
