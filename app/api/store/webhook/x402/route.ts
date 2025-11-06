import { verifyX402Webhook } from '@/src/lib/x402';
import { markPurchaseStatus, addEntitlement, supa, getPurchaseById } from '@/src/lib/db';
import { waitForFinalized } from '@/src/lib/rpc';
import { log } from '@/src/lib/logger';
import { mintAddon, mintLicense } from '@/src/lib/mint';
import { SKU } from '@/src/constants';
export const runtime = 'nodejs';

type WebhookDeps = {
  verifyX402Webhook: typeof verifyX402Webhook;
  supa: typeof supa;
  waitForFinalized: typeof waitForFinalized;
  getPurchaseById: typeof getPurchaseById;
  markPurchaseStatus: typeof markPurchaseStatus;
  addEntitlement: typeof addEntitlement;
  log: typeof log;
  mintLicense: typeof mintLicense;
  mintAddon: typeof mintAddon;
};

const defaultDeps: WebhookDeps = {
  verifyX402Webhook,
  supa,
  waitForFinalized,
  getPurchaseById,
  markPurchaseStatus,
  addEntitlement,
  log,
  mintLicense,
  mintAddon,
};

export async function handleX402Webhook(req: Request, deps: WebhookDeps = defaultDeps) {
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

  const existingPurchase = await deps.getPurchaseById(body.order_id);
  if (!existingPurchase) {
    deps.log('purchase.not_found', { purchase_id: body.order_id });
    return new Response('Not Found', { status: 404 });
  }

  if (existingPurchase.amount_atomic !== body.amount_atomic) {
    deps.log('purchase.amount_mismatch', {
      purchase_id: existingPurchase.id,
      expected_atomic: existingPurchase.amount_atomic,
      received_atomic: body.amount_atomic,
      tx: body.tx_sig,
    });
    await deps.markPurchaseStatus(existingPurchase.id, 'failed');
    return new Response('Amount mismatch', { status: 422 });
  }

  const purchase = await deps.markPurchaseStatus(existingPurchase.id, 'paid', body.tx_sig);
  deps.log('purchase.paid', { purchase_id: purchase.id, sku: purchase.sku, tx: body.tx_sig });

  try {
    if (purchase.sku === SKU.TEMPLATES_PACK_A) {
      const res = await deps.mintLicense(body.user_wallet || '', purchase.sku);
      await deps.addEntitlement({
        user_id: purchase.user_id,
        type: 'license',
        sku: purchase.sku,
        ref_mint: res.mint,
        status: 'active',
        source_purchase: purchase.id,
      });
    } else if (purchase.sku === SKU.ADDON_HALO_V1) {
      const res = await deps.mintAddon(body.user_wallet || '', purchase.sku);
      await deps.addEntitlement({
        user_id: purchase.user_id,
        type: 'addon',
        sku: purchase.sku,
        ref_mint: res.mint,
        status: 'active',
        source_purchase: purchase.id,
      });
    } else if (purchase.sku === SKU.VANITY_MONTHLY) {
      const now = new Date();
      const end = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
      await deps.supa.from('entitlements').insert({
        user_id: purchase.user_id,
        type: 'subscription',
        sku: purchase.sku,
        status: 'active',
        expires_at: end.toISOString(),
        source_purchase: purchase.id,
      });
    }
    return Response.json({ status: 'ok' });
  } catch (e) {
    await deps.markPurchaseStatus(existingPurchase.id, 'paid-pending-mint');
    deps.log('mint.defer', { purchase_id: existingPurchase.id, error: String(e) });
    return new Response('Deferred', { status: 202 });
  }
}

export async function POST(req: Request) {
  return handleX402Webhook(req);
}
