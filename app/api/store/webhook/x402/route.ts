import { verifyX402Webhook } from '@/src/lib/x402';
import { markPurchaseStatus, addEntitlement, supa } from '@/src/lib/db';
import { waitForFinalized } from '@/src/lib/rpc';
import { log } from '@/src/lib/logger';
import { mintAddon, mintLicense } from '@/src/lib/mint';
import { SKU } from '@/src/constants';
export const runtime = 'nodejs';

const defaultDeps = {
  verifyX402Webhook,
  supa,
  waitForFinalized,
  markPurchaseStatus,
  log,
  mintAddon,
  mintLicense,
  addEntitlement,
};

export type X402WebhookDeps = typeof defaultDeps;

export async function handleX402Webhook(req: Request, deps: X402WebhookDeps = defaultDeps) {
  const raw = await req.text();
  const sig = req.headers.get('x-402-signature') || '';
  const idem = req.headers.get('x-idempotency-key') || '';

  const valid = deps.verifyX402Webhook(raw, sig);
  await deps.supa
    .from('webhook_events')
    .insert({ provider: 'x402', raw_json: raw, signature_valid: valid, idempotency_key: idem });
  if (!valid) return new Response('Unauthorized', { status: 401 });

  const body = JSON.parse(raw) as { order_id: string; sku: string; tx_sig: string; amount_atomic: number; user_wallet?: string };

  const ok = await deps.waitForFinalized(body.tx_sig, 20000);
  if (!ok) return new Response('Unconfirmed', { status: 202 });

  const { row: purchase, previous_status } = await deps.markPurchaseStatus(body.order_id, 'paid', body.tx_sig);
  if (purchase.status === 'paid' && previous_status === 'paid') {
    deps.log('purchase.duplicate', { purchase_id: purchase.id, sku: purchase.sku, tx: body.tx_sig });
    return Response.json({ status: 'ok' });
  }

  deps.log('purchase.paid', { purchase_id: purchase.id, sku: purchase.sku, tx: body.tx_sig });

  try {
    if (purchase.sku === SKU.TEMPLATES_PACK_A) {
      const res = await deps.mintLicense(body.user_wallet || '', purchase.sku);
      await deps.addEntitlement({ user_id: purchase.user_id, type: 'license', sku: purchase.sku, ref_mint: res.mint, status: 'active', source_purchase: purchase.id });
    } else if (purchase.sku === SKU.ADDON_HALO_V1) {
      const res = await deps.mintAddon(body.user_wallet || '', purchase.sku);
      await deps.addEntitlement({ user_id: purchase.user_id, type: 'addon', sku: purchase.sku, ref_mint: res.mint, status: 'active', source_purchase: purchase.id });
    } else if (purchase.sku === SKU.VANITY_MONTHLY) {
      const now = new Date();
      const end = new Date(now.getTime() + 30*24*60*60*1000);
      await deps.supa
        .from('entitlements')
        .insert({ user_id: purchase.user_id, type: 'subscription', sku: purchase.sku, status: 'active', expires_at: end.toISOString(), source_purchase: purchase.id });
    }
    return Response.json({ status: 'ok' });
  } catch (e) {
    await deps.markPurchaseStatus(body.order_id, 'paid-pending-mint');
    deps.log('mint.defer', { purchase_id: body.order_id, error: String(e) });
    return new Response('Deferred', { status: 202 });
  }
}

export async function POST(req: Request) {
  return handleX402Webhook(req);
}
