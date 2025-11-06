import { z } from 'zod';
import { requireSession } from '@/src/lib/auth';
import { insertPurchase } from '@/src/lib/db';
import { SKU, SKU_ALLOWLIST } from '@/src/constants';
import { buildX402Payload } from '@/src/lib/x402';
import { randomId } from '@/src/lib/crypto';
export const runtime = 'nodejs';

const AllowedSkus = z.enum([
  SKU.VANITY_MONTHLY,
  SKU.TEMPLATES_PACK_A,
  SKU.ADDON_HALO_V1,
]);

const Body = z.object({ sku: AllowedSkus });

const SKU_PRICE_ATOMIC: Record<(typeof SKU)[keyof typeof SKU], number> = {
  'vanity.monthly': 1000000,
  'templates.packA': 3000000,
  'addon.halo.v1': 5000000
};

export async function POST(req: Request) {
  let auth; try { auth = requireSession(); } catch { return new Response('Unauthorized', { status: 401 }); }
  const { sku } = Body.parse(await req.json());
  if (!SKU_ALLOWLIST.has(sku)) return new Response('Invalid SKU', { status: 400 });
  const idempotency_key = randomId();
  const amount = SKU_PRICE_ATOMIC[sku];

  const purchase = await insertPurchase({
    user_id: auth.userId,
    sku,
    amount_atomic: amount,
    status: 'pending',
    idempotency_key,
  });

  const payload = buildX402Payload(purchase.id, sku, amount);
  return Response.json({ order_id: purchase.id, x402: payload });
}
