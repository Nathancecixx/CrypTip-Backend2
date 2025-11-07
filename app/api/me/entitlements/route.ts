const ORIGIN_DEFAULT = process.env.FRONTEND_ORIGIN ?? 'https://crytip-frontend2.vercel.app';

function cors(origin: string) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    // If you use cookie auth, keep this and DO NOT use '*':
    'Access-Control-Allow-Credentials': 'true',
  };
}

export async function OPTIONS(req: Request) {
  const origin = req.headers.get('origin') ?? ORIGIN_DEFAULT;
  return new Response(null, { status: 204, headers: cors(origin) });
}

export async function GET(req: Request) {
  const origin = req.headers.get('origin') ?? ORIGIN_DEFAULT;

  const auth = req.headers.get('authorization');
  if (!auth?.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'Missing or invalid Authorization header' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...cors(origin) },
    });
  }

  const token = auth.slice('Bearer '.length).trim();
  // TODO: verify token and derive user id…

  // Return entitlements
  return new Response(JSON.stringify({ entitlements: [] }), {
    status: 200,
    headers: { 'Content-Type': 'application/json', ...cors(origin) },
  });
}
