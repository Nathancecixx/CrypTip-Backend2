import { NextRequest, NextResponse } from 'next/server';
import { handleCorsOptions, withCORS, validateRequestOrigin } from '@/src/lib/cors';

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function GET(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) return withCORS(req, validation.response);

  const origin = req.headers.get('origin') ?? null;
  const data = {
    ok: true,
    method: 'GET',
    origin,
    url: req.nextUrl.toString(),
    headers: Object.fromEntries(req.headers.entries()),
  };

  return withCORS(
    req,
    NextResponse.json(data, { status: 200 })
  );
}

export async function POST(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) return withCORS(req, validation.response);

  let body: unknown = null;
  try {
    body = await req.json();
  } catch {
    /* non-JSON bodies will be null */
  }

  const origin = req.headers.get('origin') ?? null;
  const data = {
    ok: true,
    method: 'POST',
    origin,
    url: req.nextUrl.toString(),
    headers: Object.fromEntries(req.headers.entries()),
    body,
  };

  return withCORS(
    req,
    NextResponse.json(data, { status: 200 })
  );
}
