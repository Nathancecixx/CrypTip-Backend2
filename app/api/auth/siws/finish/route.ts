import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { env } from '@/src/lib/env';
import { verifySignature, setSessionCookie } from '@/src/lib/auth';
import { upsertUserByWallet } from '@/src/lib/db';
import { handleCorsOptions, withCORS, validateRequestOrigin } from '@/src/lib/cors';

export const runtime = 'nodejs';
const TTL_MS = 10 * 60 * 1000; // 10 min login window

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

function field(message: string, label: string): string | null {
  const m = message.match(new RegExp(`(?:^|\\n)${label}:\\s*([^\\n]+)`));
  return m ? m[1].trim() : null;
}

export async function POST(req: NextRequest) {
  try {
    const originCheck = validateRequestOrigin(req);
    if (!originCheck.ok && originCheck.response) return originCheck.response;

    const { address, signature, message } = await req.json().catch(() => ({} as any));
    if (!address || !signature || !message) {
      return withCORS(req, NextResponse.json(
        { error: 'bad_request', fields: { address: 'required', signature: 'required', message: 'required' } },
        { status: 400 }
      ));
    }

    // Parse minimal SIWS fields from the human-readable message
    const domain     = field(message, 'Domain');
    const issuedAtS  = field(message, 'Issued At') ?? field(message, 'IssuedAt');
    const nonce      = field(message, 'Nonce');

    if (!domain || !issuedAtS || !nonce) {
      return withCORS(req, NextResponse.json(
        { error: 'bad_request', fields: { message: 'malformed' } },
        { status: 400 }
      ));
    }

    // Domain must match the site users are signing into
    const allowedDomain = new URL(env.FRONTEND_ORIGIN).hostname;
    if (domain !== env.SIWS_DOMAIN && domain !== allowedDomain) {
      return withCORS(req, NextResponse.json({ error: 'domain_mismatch' }, { status: 400 }));
    }

    // Simple TTL window to prevent stale replays
    const issuedAt = Date.parse(issuedAtS);
    if (!Number.isFinite(issuedAt) || (Date.now() - issuedAt) > TTL_MS) {
      return withCORS(req, NextResponse.json({ error: 'nonce_expired' }, { status: 400 }));
    }

    // Wallet proves authorship of the message
    if (!verifySignature(message, signature, address)) {
      return withCORS(req, NextResponse.json({ error: 'bad_signature' }, { status: 401 }));
    }

    // Upsert user + issue session
    const user = await upsertUserByWallet(address);
    setSessionCookie(req, user.id);

    return withCORS(req, NextResponse.json({ ok: true, userId: user.id }, { status: 200 }));
  } catch (e) {
    // Always return CORS on error paths
    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
