import type { NextRequest } from 'next/server';

import { handleX402Webhook } from './handler';

export const runtime = 'nodejs';
export const maxDuration = 60; // allow the 20s finality wait without timing out

export async function POST(req: NextRequest) {
  return handleX402Webhook(req);
}
