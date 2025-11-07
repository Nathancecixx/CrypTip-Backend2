import { NextRequest, NextResponse } from 'next/server';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function GET(req: NextRequest) {
  const build = {
    commit: process.env.VERCEL_GIT_COMMIT_SHA ?? 'dev',
    node: process.version,
  };
  // quick env sanity flags so you can see wiring at a glance
  const db = {
    supabaseUrl: !!process.env.NEXT_PUBLIC_SUPABASE_URL,
    serviceKey: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
  };
  const rpc = {
    primary: !!process.env.RPC_PRIMARY_URL,
    fallback: !!process.env.RPC_FALLBACK_URL,
  };

  const res = NextResponse.json({ ok: true, build, db, rpc, at: new Date().toISOString() }, { status: 200 });
  return withCORS(req, res);
}
