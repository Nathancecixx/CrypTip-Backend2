import { handleX402Webhook } from './handler';
import { handleCorsOptions, withCors } from '@/src/middleware/cors';

export const runtime = 'nodejs';
export const maxDuration = 60; // allow the 20s finality wait without timing out

export const OPTIONS = handleCorsOptions;

export const POST = withCors(async (req: Request) => {
  return handleX402Webhook(req);
});
