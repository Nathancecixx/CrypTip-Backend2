import { z } from 'zod';
import { requireSession } from '@/src/lib/auth';
import { createOrUpdatePage } from '@/src/lib/db';
import { handleCorsOptions, withCors } from '@/src/middleware/cors';
export const runtime = 'nodejs';

const Body = z.object({
  slug: z.string().min(3).optional(),
  template_key: z.string().default('base.simple'),
  theme_json: z.any().default({}),
  custom_domain: z.string().optional(),
});

export const OPTIONS = handleCorsOptions;

export const POST = withCors(async (req: Request) => {
  let userId: string;
  try {
    ({ userId } = requireSession());
  } catch {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let body;
  try {
    body = Body.parse(await req.json());
  } catch {
    return Response.json({ error: 'Invalid payload' }, { status: 400 });
  }

  try {
    const page = await createOrUpdatePage(userId, body);
    return Response.json({ page });
  } catch {
    return Response.json({ error: 'Failed to save page' }, { status: 500 });
  }
});
