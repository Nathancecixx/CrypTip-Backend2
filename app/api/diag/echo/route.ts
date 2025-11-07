import { cookies } from 'next/headers';

import { handleCorsOptions, validateRequestOrigin, withCORS } from '@/src/lib/cors';

export const runtime = 'nodejs';

export const OPTIONS = handleCorsOptions;

export async function GET(req: Request) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok) {
    return validation.response;
  }

  const cookieJar = cookies();
  const cookieNames = cookieJar.getAll().map((cookie) => cookie.name);

  return withCORS(
    Response.json(
      {
        origin: req.headers.get('origin'),
        host: req.headers.get('host'),
        cookieNames,
      },
      { status: 200 },
    ),
    validation.evaluation,
  );
}
