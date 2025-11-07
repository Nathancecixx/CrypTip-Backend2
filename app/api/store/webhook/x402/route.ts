import { NextRequest, NextResponse } from 'next/server';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';
import { handleX402Webhook } from './handler';

export const runtime = 'nodejs';
export const maxDuration = 60;

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  // handler already returns a NextResponse; it just expects a web Request
  const res = await handleX402Webhook(req as unknown as Request);
  return withCORS(req, res);
}
