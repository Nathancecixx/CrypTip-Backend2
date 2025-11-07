import { z } from 'zod';
import { NextRequest, NextResponse } from 'next/server';
import { requireSession, logUnauthorizedAccess } from '@/src/lib/auth';
import { createOrUpdatePage } from '@/src/lib/db';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';

export const runtime = 'nodejs';

const Body = z.object({
  slug: z.string().min(3).optional(),
  template_key: z.string().default('base.simple'),
  theme_json: z.any().default({}),
  custom_domain: z.string().optional(),
});

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  let userId: string;
  try {
    ({ userId } = requireSession(req));
  } catch (error) {
    logUnauthorizedAccess(req, error);
    return withCORS(req, NextResponse.json({ error: 'Unauthorized' }, { status: 401 }));
  }

  let body: z.infer<typeof Body>;
  try {
    body = Body.parse(await req.json());
  } catch {
    return withCORS(req, NextResponse.json({ error: 'Invalid payload' }, { status: 400 }));
  }

  try {
    const page = await createOrUpdatePage(userId, body);
    return withCORS(req, NextResponse.json({ page }, { status: 200 }));
  } catch {
    return withCORS(req, NextResponse.json({ error: 'Failed to save page' }, { status: 500 }));
  }
}
