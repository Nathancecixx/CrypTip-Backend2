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
  // very small parser for SIWS fields we generated
  const lines = msg.split('\n').map(l => l.trim());
  const get = (k: string) => (lines.find(l => l.startsWith(`${k}:`)) || '').split(':').slice(1).join(':').trim();
  return {
    domain: get('Domain'),
    address: get('Address'),
    nonce: get('Nonce'),
    issuedAt: get('Issued At'),
  };
}

export async function POST(req: NextRequest) {
  const v = validateRequestOrigin(req);
  if (!v.ok) return withCORS(req, v.response!);

  const body = await req.json().catch(() => null);
  const address = body?.address as string | undefined;
  const signatureB58 = body?.signature as string | undefined;
  const message = body?.message as string | undefined;

  if (!address || !signatureB58 || !message) {
    return withCORS(req, NextResponse.json(
      { error: 'bad_request', fields: { address: !!address, signature: !!signatureB58, message: !!message } },
      { status: 400 }
    ));
  }

  // 1) basic message checks
  const fields = parseMessage(message);
  const domainExpected = resolveAllowedRequestDomain(req);
  if (!fields.address || fields.address !== address) {
    return withCORS(req, NextResponse.json({ error: 'message_address_mismatch' }, { status: 400 }));
  }
  if (!fields.domain || (fields.domain !== domainExpected)) {
    return withCORS(req, NextResponse.json({ error: 'domain_mismatch' }, { status: 400 }));
  }
  if (!fields.nonce || fields.nonce.length < 8) {
    return withCORS(req, NextResponse.json({ error: 'nonce_invalid' }, { status: 400 }));
  }
  if (fields.issuedAt) {
    const age = Date.now() - Date.parse(fields.issuedAt);
    if (isFinite(age) && age > 1000 * 60 * 10) { // >10 minutes old
      return withCORS(req, NextResponse.json({ error: 'message_expired' }, { status: 400 }));
    }
  }

  // 2) verify signature (ed25519)
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

  // 3) upsert user + issue session
  try {
    const user = await upsertUserByWallet(address);
    const token = issueSessionJWT(user.id);
    const res = NextResponse.json({ ok: true, userId: user.id }, { status: 200 });
    setSessionCookie(res, token);
    return withCORS(req, res);
  } catch (e: any) {
    return withCORS(
      req,
      NextResponse.json({ error: 'db_error', code: e?.code ?? 'unknown', hint: e?.hint ?? 'upsertUserByWallet' }, { status: 500 })
    );
  }
}
