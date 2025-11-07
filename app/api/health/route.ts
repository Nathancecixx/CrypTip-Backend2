import { handleCorsOptions, withCORS } from '@/src/lib/cors';

export const runtime = 'nodejs';

export const OPTIONS = handleCorsOptions;

export async function GET(req: Request) {
  return withCORS(
    Response.json({ ok: true, build: process.env.VERCEL_GIT_COMMIT_SHA ?? 'dev' }),
    req,
  );
}
