// app/api/auth/siws/start/route.ts
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { env } from '@/src/lib/env';
import { handleCorsOptions, withCORS, validateRequestOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { makeNonce } from '@/src/lib/auth';
import { saveSiwsNonce } from '@/src/lib/nonce-store';

export const runtime = 'nodejs';
export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  const validation = validateRequestOrigin(req);
  if (!validation.ok && validation.response) return validation.response;

  const { address } = await req.json().catch(() => ({} as any));
  if (!address || typeof address !== 'string') {
    return withCORS(
      req,
      NextResponse.json({ error: 'bad_request', fields: { address: 'required' } }, { status: 400 })
    );
  }

  const domain =
    resolveAllowedRequestDomain(req, validation.evaluation) ??
    env.SIWS_DOMAIN ??
    new URL(req.url).host;

  const nonce = makeNonce();
  const issuedAt = new Date().toISOString();

  // Canonical, parseable, and byte-stable message (no trailing spaces)
  const message = [
    `${domain} wants you to sign in with your Solana account:`,
    address,
    '',
    `Domain: ${domain}`,
    `Address: ${address}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join('\n');

  await saveSiwsNonce({ address, nonce, issuedAt, message });

  return withCORS(req, NextResponse.json({ nonce, message }, { status: 200, headers: { 'Cache-Control': 'no-store' } }));
}
