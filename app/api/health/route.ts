import { checkDbHealth } from '@/src/lib/db';
import { checkRpcHealth } from '@/src/lib/rpc';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';

export const runtime = 'nodejs';

export const OPTIONS = handleCorsOptions;

export async function GET(req: Request) {
  const [db, rpc] = await Promise.all([checkDbHealth(), checkRpcHealth()]);
  const build = { commit: process.env.VERCEL_GIT_COMMIT_SHA ?? 'dev' };

  return withCORS(Response.json({ build, db, rpc }), req);
}
