import { supa, markPurchaseStatus, addEntitlement } from '@/src/lib/db';
import { mintAddon, mintLicense } from '@/src/lib/mint';
import { log } from '@/src/lib/logger';
export const runtime = 'nodejs';

export async function GET() {
  const { data: rows, error } = await supa
    .from('purchases')
    .select('id, user_id, sku')
    .eq('status', 'paid-pending-mint')
    .limit(50);
  if (error) return new Response('DB error', { status: 500 });
  for (const p of rows ?? []) {
    try {
      if (p.sku.startsWith('templates.')) {
        const res = await mintLicense('unknown', p.sku);
        await addEntitlement({ user_id: p.user_id, type: 'license', sku: p.sku, ref_mint: res.mint, status: 'active', source_purchase: p.id });
      } else if (p.sku.startsWith('addon.')) {
        const res = await mintAddon('unknown', p.sku);
        await addEntitlement({ user_id: p.user_id, type: 'addon', sku: p.sku, ref_mint: res.mint, status: 'active', source_purchase: p.id });
      }
      await markPurchaseStatus(p.id, 'paid');
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
