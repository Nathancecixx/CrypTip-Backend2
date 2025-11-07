import { z } from 'zod';
import { requireSession } from '@/src/lib/auth';
import { createOrUpdatePage } from '@/src/lib/db';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';
export const runtime = 'nodejs';

const Body = z.object({
  slug: z.string().min(3).optional(),
  template_key: z.string().default('base.simple'),
  theme_json: z.any().default({}),
  custom_domain: z.string().optional(),
});

export const OPTIONS = handleCorsOptions;

export async function POST(req: Request) {
  let userId: string;
  try {
    ({ userId } = requireSession());
  } catch {
    return withCORS(Response.json({ error: 'Unauthorized' }, { status: 401 }), req);
  }

  let body;
  try {
    body = Body.parse(await req.json());
  } catch {
    return withCORS(Response.json({ error: 'Invalid payload' }, { status: 400 }), req);
  }

  try {
    const page = await createOrUpdatePage(userId, body);
    return withCORS(Response.json({ page }), req);
  } catch {
    return withCORS(Response.json({ error: 'Failed to save page' }, { status: 500 }), req);
  }
}
