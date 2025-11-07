import { NextRequest, NextResponse } from 'next/server';
import { getPageByWallet } from '@/src/lib/db';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';

export const runtime = 'nodejs';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function GET(req: NextRequest, { params }: { params: { slug: string } }) {
  try {
    const page = await getPageByWallet(params.slug);
    if (!page || !page.public) {
      return withCORS(req, NextResponse.json({ error: 'Not found' }, { status: 404 }));
    }
    return withCORS(req, NextResponse.json({ page }, { status: 200 }));
  } catch {
    return withCORS(req, NextResponse.json({ error: 'Failed to load page' }, { status: 500 }));
  }
}
