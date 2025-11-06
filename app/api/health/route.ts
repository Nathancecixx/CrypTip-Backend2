export const runtime = 'nodejs';

export async function GET() {
  return Response.json({ ok: true, build: process.env.VERCEL_GIT_COMMIT_SHA ?? 'dev' });
}
