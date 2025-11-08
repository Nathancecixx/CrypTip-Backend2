import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import {
  handleCorsOptions,
  withCORS,
  validateRequestOrigin,
  resolveAllowedRequestDomain,
} from '@/src/lib/cors';
import { buildSiwsMessage } from '@/src/lib/auth';
import { issueNonce } from '@/src/lib/nonce-store';

export const runtime = 'nodejs';

const ADDRESS_PLACEHOLDER = '<WALLET_ADDRESS>';
const NONCE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function deriveExpectedDomain(req: NextRequest): string {
  const pinned = (process.env.SIWS_DOMAIN || '').trim();
  if (pinned) return pinned;
  return resolveAllowedRequestDomain(req);
}

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  try {
    const originCheck = validateRequestOrigin(req);
    if (!originCheck.ok && originCheck.response) return withCORS(req, originCheck.response);

    const expectedDomain = deriveExpectedDomain(req);

    let nonceRec;
    try {
      // Persist the domain if your table has the column (recommended)
      nonceRec = await issueNonce({ domain: expectedDomain });
    } catch (e: any) {
      console.error('siws.start.issueNonce.error', { code: e?.code, message: e?.message });
      return withCORS(req, NextResponse.json({ error: 'internal_error', hint: 'issueNonce_failed' }, { status: 500 }));
    }

    const { nonce, createdAt } = nonceRec;
    const message = buildSiwsMessage(expectedDomain, ADDRESS_PLACEHOLDER, nonce, createdAt);

    return withCORS(
      req,
      NextResponse.json({
        nonce,
        message,
        expiresAt: new Date(new Date(createdAt).getTime() + NONCE_TTL_MS).toISOString(),
      }),
    );
  } catch (err) {
    console.error('siws.start.error', err);
    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
