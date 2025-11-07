import { z } from 'zod';
import { requireSession } from '@/src/lib/auth';
import { createOrUpdatePage } from '@/src/lib/db';
import { corsHeaders, getAllowedOrigin, notAllowedResponse, preflight } from '@/src/lib/cors';
export const runtime = 'nodejs';

const Body = z.object({
  slug: z.string().min(3).optional(),
  template_key: z.string().default('base.simple'),
  theme_json: z.any().default({}),
  custom_domain: z.string().optional(),
});

export async function OPTIONS(req: Request) {
  return preflight(req);
}

export async function POST(req: Request) {
  const origin = getAllowedOrigin(req);
  if (!origin) return notAllowedResponse();

  let auth;
  try {
    auth = requireSession();
  } catch {
    return new Response('Unauthorized', { status: 401, headers: corsHeaders(origin) });
  }
  const body = Body.parse(await req.json());
  const page = await createOrUpdatePage(auth.userId, body);
  return Response.json({ page }, { headers: corsHeaders(origin) });
}
