// app/api/auth/siws/start/route.ts
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { env } from '@/src/lib/env';
import { handleCorsOptions, withCORS, validateRequestOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { issueNonce } from '@/src/lib/nonce-store';

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

  const normalizedAddress = address.trim();
  if (!normalizedAddress) {
    return withCORS(
      req,
      NextResponse.json({ error: 'bad_request', fields: { address: 'required' } }, { status: 400 })
    );
  }

  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  const userAgent = req.headers.get('user-agent') ?? undefined;

  const { nonce, issuedAt } = await issueNonce({
    address: normalizedAddress,
    domain,
    ip: ip || undefined,
    userAgent,
  });

  // Canonical, parseable, and byte-stable message (no trailing spaces)
  const message = [
    `${domain} wants you to sign in with your Solana account:`,
    normalizedAddress,
    '',
    `Domain: ${domain}`,
    `Address: ${normalizedAddress}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join('\n');

  return withCORS(
    req,
    NextResponse.json({ nonce, message }, { status: 200, headers: { 'Cache-Control': 'no-store' } })
  );
}
