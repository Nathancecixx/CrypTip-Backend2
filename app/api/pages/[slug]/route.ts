import { getPageByWallet } from '@/src/lib/db';
import { corsHeaders, getAllowedOrigin, notAllowedResponse, preflight } from '@/src/lib/cors';
export const runtime = 'nodejs';

export async function OPTIONS(req: Request) {
  return preflight(req);
}

export async function GET(req: Request, { params }: { params: { slug: string } }) {
  const origin = getAllowedOrigin(req);
  if (!origin) return notAllowedResponse();

  const page = await getPageByWallet(params.slug);
  if (!page || !page.public) {
    return new Response('Not found', { status: 404, headers: corsHeaders(origin) });
  }
  return Response.json({ page }, { headers: corsHeaders(origin) });
}
