import { handleX402Webhook } from './handler';
import { handleCorsOptions, withCORS } from '@/src/lib/cors';

export const runtime = 'nodejs';
export const maxDuration = 60; // allow the 20s finality wait without timing out

export const OPTIONS = handleCorsOptions;

export async function POST(req: Request) {
  const response = await handleX402Webhook(req);
  return withCORS(response, req);
}
