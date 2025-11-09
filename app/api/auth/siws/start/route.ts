// src/app/api/auth/siws/start/route.ts
import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { handleCorsOptions, withCORS, validateRequestOrigin, resolveAllowedRequestDomain } from '@/src/lib/cors';
import { buildSiwsMessage } from '@/src/lib/auth';
import { issueNonce } from '@/src/lib/nonce-store';

export const runtime = 'nodejs';

const ADDRESS_PLACEHOLDER = '<WALLET_ADDRESS>';

function expectedDomain(req: NextRequest): string {
  const pinned = (process.env.SIWS_DOMAIN || '').trim();
  return pinned || resolveAllowedRequestDomain(req);
}

export async function OPTIONS(req: NextRequest) {
  return handleCorsOptions(req);
}

export async function POST(req: NextRequest) {
  try {
    const originCheck = validateRequestOrigin(req);
    if (!originCheck.ok && originCheck.response) {
      return withCORS(req, originCheck.response);
    }

    const domain = expectedDomain(req);

    let rec: { id: string; nonce: string; createdAt: string; expiresAt: string };
    try {
      rec = await issueNonce({ domain });
    } catch (e: any) {
      console.error('siws.start.issueNonce.error', { code: e?.code, message: e?.message });
      return withCORS(req, NextResponse.json({ error: 'internal_error', hint: 'issueNonce_failed' }, { status: 500 }));
    }

    const message = buildSiwsMessage(domain, ADDRESS_PLACEHOLDER, rec.nonce, rec.createdAt);

    return withCORS(
      req,
      NextResponse.json(
        {
          nonce: rec.nonce,
          message,
          createdAt: rec.createdAt,
          expiresAt: rec.expiresAt,
        },
        { status: 200 },
      ),
    );
  } catch (err) {
    console.error('siws.start.error', err);
    return withCORS(req, NextResponse.json({ error: 'internal_error' }, { status: 500 }));
  }
}
