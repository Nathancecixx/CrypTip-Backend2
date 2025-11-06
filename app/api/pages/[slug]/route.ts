import { getPageByWallet } from '@/src/lib/db';
export const runtime = 'nodejs';

export async function GET(_: Request, { params }: { params: { slug: string } }) {
  const page = await getPageByWallet(params.slug);
  if (!page || !page.public) return new Response('Not found', { status: 404 });
  return Response.json({ page });
}
