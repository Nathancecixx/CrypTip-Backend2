import { getPageByWallet } from '@/src/lib/db';
import { handleCorsOptions, withCors } from '@/src/middleware/cors';
export const runtime = 'nodejs';

export const OPTIONS = handleCorsOptions;

export const GET = withCors(async (_req: Request, { params }: { params: { slug: string } }) => {
  try {
    const page = await getPageByWallet(params.slug);
    if (!page || !page.public) {
      return Response.json({ error: 'Not found' }, { status: 404 });
    }
    return Response.json({ page });
  } catch {
    return Response.json({ error: 'Failed to load page' }, { status: 500 });
  }
});
