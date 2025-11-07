// app/api/auth/siws/finish/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { withCORS, handleCorsOptions, validateRequestOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { upsertUserByWallet } from '@/src/lib/db';
import { issueSessionJWT, setSessionCookie } from '@/src/lib/auth';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

export const runtime = 'nodejs';
export const OPTIONS = handleCorsOptions;

function parseMessage(msg: string) {
  // Robust parser: tolerate CRLF and casing of keys like "Nonce:"
  const lines = msg.replace(/\r/g, '').split('\n');
  const map: Record<string, string> = {};
  for (const raw of lines) {
    const i = raw.indexOf(':');
    if (i <= 0) continue;
    const k = raw.slice(0, i).trim().toLowerCase();
    const v = raw.slice(i + 1).trim();
    map[k] = v;
  }
  return {
    domain: map['domain'] || '',
    address: map['address'] || '',
    nonce: map['nonce'] || '',
    issuedAt: map['issued at'] || '',
  };
}

export async function POST(req: NextRequest) {
  const v = validateRequestOrigin(req);
  if (!v.ok) return withCORS(req, v.response!);

  const body = await req.json().catch(() => null);
  const address = (body?.address ?? '') as string;
  const signatureB58 = (body?.signature ?? '') as string;
  const message = (body?.message ?? '') as string;

  if (!address || !signatureB58 || !message) {
    return withCORS(req, NextResponse.json(
      { error: 'bad_request', fields: { address: !!address, signature: !!signatureB58, message: !!message } },
      { status: 400 }
    ));
  }

  // 1) Parse + validate message fields
  const fields = parseMessage(message);
  const domainExpected = resolveAllowedRequestDomain(req) ?? new URL(req.url).host;

  if (!fields.address || fields.address !== address) {
    return withCORS(req, NextResponse.json({ error: 'message_address_mismatch' }, { status: 400 }));
  }
  if (!fields.domain || fields.domain !== domainExpected) {
    return withCORS(req, NextResponse.json({ error: 'domain_mismatch' }, { status: 400 }));
  }
  if (!fields.nonce || fields.nonce.length < 8) {
    return withCORS(req, NextResponse.json({ error: 'nonce_invalid' }, { status: 400 }));
  }
  if (fields.issuedAt) {
    const ageMs = Date.now() - Date.parse(fields.issuedAt);
    if (isFinite(ageMs) && ageMs > 10 * 60 * 1000) {
      return withCORS(req, NextResponse.json({ error: 'message_expired' }, { status: 400 }));
    }
  }

  // 2) Verify signature (Ed25519 over the exact message bytes)
  try {
    const sig = bs58.decode(signatureB58);
    const pub = bs58.decode(address);
    const enc = new TextEncoder().encode(message);
    const ok = nacl.sign.detached.verify(enc, sig, pub);
    if (!ok) {
      return withCORS(req, NextResponse.json({ error: 'bad_signature' }, { status: 400 }));
    }
  } catch {
    return withCORS(req, NextResponse.json({ error: 'signature_malformed' }, { status: 400 }));
  }

  // 3) Upsert + issue session
  try {
    const user = await upsertUserByWallet(address);
    const token = issueSessionJWT(user.id);

    const res = NextResponse.json({ ok: true, userId: user.id }, {
      status: 200,
      headers: { 'Cache-Control': 'no-store' },
    });

    // First-party session cookie on this origin
    setSessionCookie(res, token);
    return withCORS(req, res);
  } catch (e: any) {
    return withCORS(
      req,
      NextResponse.json({ error: 'db_error', code: e?.code ?? 'unknown', hint: e?.hint ?? 'upsertUserByWallet' }, { status: 500 })
    );
  }
}
