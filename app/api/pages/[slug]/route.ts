import { getPageByWallet } from '@/src/lib/db';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';
export const runtime = 'nodejs';

export const OPTIONS = handleCorsOptions;

export async function GET(req: Request, { params }: { params: { slug: string } }) {
  try {
    const page = await getPageByWallet(params.slug);
    if (!page || !page.public) {
      return withCORS(Response.json({ error: 'Not found' }, { status: 404 }), req);
    }
    return withCORS(Response.json({ page }), req);
  } catch {
    return withCORS(Response.json({ error: 'Failed to load page' }, { status: 500 }), req);
  }
}
