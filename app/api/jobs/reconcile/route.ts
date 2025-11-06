import { supa, markPurchaseStatus, addEntitlement } from '@/src/lib/db';
import { mintAddon, mintLicense } from '@/src/lib/mint';
import { log } from '@/src/lib/logger';
export const runtime = 'nodejs';

export type ReconcilePurchaseRow = {
  id: string;
  user_id: string;
  sku: string;
  users: { wallet_pubkey: string | null } | null;
};

type ReconcileDeps = {
  mintLicense: typeof mintLicense;
  mintAddon: typeof mintAddon;
  addEntitlement: typeof addEntitlement;
  markPurchaseStatus: typeof markPurchaseStatus;
};

const defaultDeps: ReconcileDeps = {
  mintLicense,
  mintAddon,
  addEntitlement,
  markPurchaseStatus,
};

export async function processPurchase(purchase: ReconcilePurchaseRow, deps: ReconcileDeps = defaultDeps) {
  const wallet = purchase.users?.wallet_pubkey;
  if (!wallet) throw new Error('Wallet missing for purchase');

  if (purchase.sku.startsWith('templates.')) {
    const res = await deps.mintLicense(wallet, purchase.sku);
    await deps.addEntitlement({
      user_id: purchase.user_id,
      type: 'license',
      sku: purchase.sku,
      ref_mint: res.mint,
      status: 'active',
      source_purchase: purchase.id,
    });
  } else if (purchase.sku.startsWith('addon.')) {
    const res = await deps.mintAddon(wallet, purchase.sku);
    await deps.addEntitlement({
      user_id: purchase.user_id,
      type: 'addon',
      sku: purchase.sku,
      ref_mint: res.mint,
      status: 'active',
      source_purchase: purchase.id,
    });
  }

  await deps.markPurchaseStatus(purchase.id, 'paid');
}

export async function GET() {
  const { data: rows, error } = await supa
    .from('purchases')
    .select('id, user_id, sku, users(wallet_pubkey)')
    .eq('status', 'paid-pending-mint')
    .limit(50);
  if (error) return new Response('DB error', { status: 500 });
  const purchases = (rows ?? []) as unknown as ReconcilePurchaseRow[];
  for (const p of purchases) {
    try {
      await processPurchase(p);
      log('reconcile.ok', { purchase_id: p.id });
    } catch (e) {
      log('reconcile.err', { purchase_id: p.id, error: String(e) });
    }
  }
  // Expire subscriptions whose expires_at is in the past
  await supa.from('entitlements')
    .update({ status: 'expired' })
    .eq('type', 'subscription')
    .eq('status', 'active')
    .lt('expires_at', new Date().toISOString());
  return Response.json({ processed: rows?.length ?? 0 });
}
