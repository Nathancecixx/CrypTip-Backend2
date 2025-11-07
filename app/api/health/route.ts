import { handleCorsOptions, withCors } from '@/src/middleware/cors';

export const runtime = 'nodejs';

export const OPTIONS = handleCorsOptions;

export const GET = withCors(async () => {
  return Response.json({ ok: true, build: process.env.VERCEL_GIT_COMMIT_SHA ?? 'dev' });
});
