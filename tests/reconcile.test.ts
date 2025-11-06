import assert from 'node:assert/strict';
import test from 'node:test';
import type { ReconcilePurchaseRow } from '../app/api/jobs/reconcile/route';

type ReconcileModule = typeof import('../app/api/jobs/reconcile/route');
type ProcessDeps = NonNullable<Parameters<ReconcileModule['processPurchase']>[1]>;

const envDefaults: Record<string, string> = {
  NEXT_PUBLIC_SUPABASE_URL: 'https://example.supabase.co',
  SUPABASE_SERVICE_ROLE_KEY: 'service-role-key-1234567890',
  RPC_PRIMARY_URL: 'https://rpc.example.com',
  JWT_SECRET: '12345678901234567890123456789012',
  SIWS_DOMAIN: 'example.com',
  X402_WEBHOOK_SECRET: 'webhooksecret12345',
  MINT_COLLECTION_ADDRESS: 'MintCollectionAddress11111',
  MINT_SIGNER_SECRET: 'MintSignerSecretKey1111',
  ENABLE_FAKE_MINT: '1',
};

for (const [key, value] of Object.entries(envDefaults)) {
  if (!process.env[key]) process.env[key] = value;
}

test('processPurchase forwards the user wallet to minting helpers', async () => {
  const { processPurchase } = await import('../app/api/jobs/reconcile/route');

  const wallets: string[] = [];
  const markStatuses: Array<{ id: string; status: string }> = [];

  const deps: ProcessDeps = {
    mintLicense: async (wallet, sku) => {
      wallets.push(`${sku}:${wallet}`);
      return { mint: 'mint-license' };
    },
    mintAddon: async (wallet, sku) => {
      wallets.push(`${sku}:${wallet}`);
      return { mint: 'mint-addon' };
    },
    addEntitlement: async () => ({} as any),
    markPurchaseStatus: async (id, status) => {
      markStatuses.push({ id, status });
      return {} as any;
    },
  };

  const licensePurchase: ReconcilePurchaseRow = {
    id: 'purchase-license',
    user_id: 'user-1',
    sku: 'templates.packA',
    users: { wallet_pubkey: 'WalletLicense' },
  };

  const addonPurchase: ReconcilePurchaseRow = {
    id: 'purchase-addon',
    user_id: 'user-2',
    sku: 'addon.halo.v1',
    users: { wallet_pubkey: 'WalletAddon' },
  };

  await processPurchase(licensePurchase, deps);
  await processPurchase(addonPurchase, deps);

  assert.deepEqual(wallets, [
    'templates.packA:WalletLicense',
    'addon.halo.v1:WalletAddon',
  ]);
  assert.deepEqual(markStatuses, [
    { id: 'purchase-license', status: 'paid' },
    { id: 'purchase-addon', status: 'paid' },
  ]);
});
