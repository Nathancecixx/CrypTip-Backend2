import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { env } from '@/src/lib/env';
import { verifySignature, setSessionCookie } from '@/src/lib/auth';
import { upsertUserByWallet } from '@/src/lib/db';
import { handleCorsOptions, withCORS, validateRequestOrigin } from '@/src/lib/cors';

export const runtime = 'nodejs';
const TTL_MS = 10 * 60 * 1000; // accept messages issued within 10 minutes

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

// --- helpers --------------------------------------------------------------

function findHeader(message: string, labels: string[]): string | null {
  for (const label of labels) {
    const re = new RegExp(`(?:^|\\n)${label}\\s*:\\s*([^\\n]+)`, 'i');
    const m = message.match(re);
    if (m) return m[1].trim();
  }
  return null;
}

function parseDomain(message: string): string | null {
  // 1) Explicit "Domain:" header (some libs include it)
  const hdr = findHeader(message, ['Domain']);
  if (hdr) return hdr;

  // 2) First-line form: "<domain> wants you to sign in with your <chain> account:"
  const first = message.split('\n', 1)[0] ?? '';
  const m = first.match(/^([^\s]+)\s+wants you to sign in with your/i);
  if (m) return m[1].trim();

  // 3) Fallback: derive from URI header if present
  const uri = findHeader(message, ['URI', 'Uri']);
  if (uri) {
    try { return new URL(uri).host; } catch { /* ignore */ }
  }
  return null;
}

function parseIssuedAt(message: string): number | null {
  const s = findHeader(message, ['Issued At', 'IssuedAt', 'Issued at', 'Issued']);
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

// --- handler --------------------------------------------------------------

export async function POST(req: NextRequest) {
  try {
    const originCheck = validateRequestOrigin(req);
    if (!originCheck.ok && originCheck.response) return originCheck.response;

    const body = await req.json().catch(() => ({} as any));
    const { address, signature, message } = body ?? {};
    if (!address || !signature || !message || typeof message !== 'string') {
      return withCORS(req, NextResponse.json(
        { error: 'bad_request', fields: { address: 'required', signature: 'required', message: 'required' } },
        { status: 400 }
      ));
    }

    // Parse flexible SIWS fields
    const domain = parseDomain(message);
    const issuedAt = parseIssuedAt(message); // may be null (some libs omit)
    const allowedHost = (() => {
      try { return new URL(env.FRONTEND_ORIGIN).host; } catch { return env.SIWS_DOMAIN; }
    })();
    const expectedDomain = env.SIWS_DOMAIN || allowedHost;

    // Domain check: if present, require it to match one of our allowed hosts
    if (domain && domain !== expectedDomain && domain !== allowedHost) {
      return withCORS(req, NextResponse.json({ error: 'domain_mismatch' }, { status: 400 }));
    }

    // TTL check: only if Issued At is present; otherwise allow (some libs omit it)
    if (issuedAt !== null && (Date.now() - issuedAt) > TTL_MS) {
      return withCORS(req, NextResponse.json({ error: 'nonce_expired' }, { status: 400 }));
    }

    // Verify the wallet actually signed THIS exact message
    if (!verifySignature(message, signature, address)) {
      return withCORS(req, NextResponse.json({ error: 'bad_signature' }, { status: 401 }));
    }

    // Upsert user & set session
    const user = await upsertUserByWallet(address);
    setSessionCookie(req, user.id);

    return withCORS(req, NextResponse.json({ ok: true, userId: user.id }, { status: 200 }));
  } catch {
    // Ensure CORS even on unexpected exceptions
    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
