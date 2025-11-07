import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SKU } from '@/src/constants';
import type { PurchaseStatusResult, PurchaseRow } from '@/src/lib/db';
import type { X402WebhookDeps } from '@/app/api/store/webhook/x402/handler';

const envDefaults = {
  RPC_PRIMARY_URL: 'http://localhost:8899',
  NEXT_PUBLIC_SUPABASE_URL: 'http://localhost:54321',
  SUPABASE_SERVICE_ROLE_KEY: 'service-role-key',
  JWT_SECRET: 'jwt-secret-value-that-is-32-chars',
  SIWS_DOMAIN: 'localhost',
  X402_WEBHOOK_SECRET: 'webhook-secret',
  X402_MERCHANT_USDC_ACCOUNT: 'merchant-usdc-account-0001',
  X402_USDC_MINT: 'usdc-mint-address-0001',
  MINT_COLLECTION_ADDRESS: 'collection-address-12345',
  MINT_SIGNER_SECRET: 'signer-secret-value-6789',
};

for (const [key, value] of Object.entries(envDefaults)) {
  if (!process.env[key]) {
    process.env[key] = value;
  }
}

function makeParsedTransaction(amount: string, memo: string) {
  return {
    transaction: {
      message: {
        instructions: [
          {
            program: 'spl-token',
            parsed: {
              type: 'transfer',
              info: {
                destination: process.env.X402_MERCHANT_USDC_ACCOUNT,
                mint: process.env.X402_USDC_MINT,
                amount,
              },
            },
          },
          {
            program: 'spl-memo',
            parsed: {
              type: 'memo',
              info: { memo },
            },
          },
        ],
      },
    },
  };
}

function makeSupa({
  storedPurchase,
  webhookEvents,
  subscriptionInserts,
}: {
  storedPurchase: PurchaseRow;
  webhookEvents: any[];
  subscriptionInserts: any[];
}) {
  return {
    from(table: string) {
      if (table === 'webhook_events') {
        return {
          insert: async (payload: any) => {
            webhookEvents.push(payload);
            return { data: payload, error: null };
          },
        };
      }
      if (table === 'purchases') {
        const chain: any = {
          select: () => chain,
          eq: () => chain,
          single: async () => ({ data: { ...storedPurchase }, error: null }),
        };
        return chain;
      }
      if (table === 'entitlements') {
        return {
          insert: async (payload: any) => {
            subscriptionInserts.push(payload);
            return { data: payload, error: null };
          },
        };
      }
      throw new Error(`Unexpected table ${table}`);
    },
  } as unknown as X402WebhookDeps['supa'];
}

test('duplicate webhooks do not trigger additional mints', async () => {
  const minted: Array<{ wallet: string; sku: string }> = [];
  const addedEntitlements: any[] = [];
  const subscriptionInserts: any[] = [];
  const logs: Array<{ event: string; payload: any }> = [];
  const webhookEvents: any[] = [];

  const storedPurchase: PurchaseRow = {
    id: 'order-1',
    sku: SKU.TEMPLATES_PACK_A,
    user_id: 'user-1',
    amount_atomic: 100,
    status: 'pending',
    tx_sig: null,
  };

  const paidPurchase: PurchaseRow = { ...storedPurchase, status: 'paid', tx_sig: 'tx-1' };

  let markCalls = 0;
  const markPurchaseStatus = async (): Promise<PurchaseStatusResult> => {
    markCalls += 1;
    return markCalls === 1
      ? { row: paidPurchase, previous_status: 'pending', updated: true }
      : { row: paidPurchase, previous_status: 'paid', updated: false };
  };

  const parsedTx = makeParsedTransaction(
    String(storedPurchase.amount_atomic),
    `ctj:${storedPurchase.id}:${storedPurchase.sku}`,
  );

  const deps: X402WebhookDeps = {
    verifyX402Webhook: () => true,
    supa: makeSupa({ storedPurchase, webhookEvents, subscriptionInserts }),
    waitForFinalized: async () => true,
    getParsedTransaction: async () => parsedTx as any,
    markPurchaseStatus,
    log(event: string, payload: any) {
      logs.push({ event, payload });
    },
    mintAddon: async () => {
      throw new Error('mintAddon should not be called');
    },
    mintLicense: async (wallet: string, sku: string) => {
      minted.push({ wallet, sku });
      return { mint: `mint-${minted.length}` };
    },
    addEntitlement: async (payload: any) => {
      addedEntitlements.push(payload);
      return payload;
    },
  };

  const payload = {
    order_id: storedPurchase.id,
    sku: storedPurchase.sku,
    tx_sig: paidPurchase.tx_sig!,
    amount_atomic: storedPurchase.amount_atomic,
    user_wallet: 'wallet-1',
  };

  const headers = new Headers({
    'x-402-signature': 'sig-1',
    'x-idempotency-key': 'idem-1',
  });

  const { handleX402Webhook } = await import('@/app/api/store/webhook/x402/handler');

  const firstResponse = await handleX402Webhook(
    new Request('http://localhost/api/store/webhook/x402', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    }),
    deps,
  );

  assert.equal(firstResponse.status, 200);
  await firstResponse.json();

  const secondResponse = await handleX402Webhook(
    new Request('http://localhost/api/store/webhook/x402', {
      method: 'POST',
      headers: new Headers({
        'x-402-signature': 'sig-1',
        'x-idempotency-key': 'idem-1',
      }),
      body: JSON.stringify(payload),
    }),
    deps,
  );

  assert.equal(secondResponse.status, 200);
  await secondResponse.json();

  assert.equal(markCalls, 2);
  assert.equal(minted.length, 1);
  assert.equal(addedEntitlements.length, 1);
  assert.equal(subscriptionInserts.length, 0);
  const duplicateLog = logs.find((entry) => entry.event === 'purchase.duplicate');
  assert.ok(duplicateLog, 'expected duplicate log entry');
  assert.equal(webhookEvents.length, 2);
});

test('rejects webhook when amount does not match purchase record', async () => {
  const logs: Array<{ event: string; payload: any }> = [];
  const webhookEvents: any[] = [];
  const subscriptionInserts: any[] = [];

  const storedPurchase: PurchaseRow = {
    id: 'order-amount-mismatch',
    sku: SKU.TEMPLATES_PACK_A,
    user_id: 'user-amount',
    amount_atomic: 500,
    status: 'pending',
    tx_sig: null,
  };

  const deps: X402WebhookDeps = {
    verifyX402Webhook: () => true,
    supa: makeSupa({ storedPurchase, webhookEvents, subscriptionInserts }),
    waitForFinalized: async () => true,
    getParsedTransaction: async () => makeParsedTransaction('500', `ctj:${storedPurchase.id}:${storedPurchase.sku}`) as any,
    markPurchaseStatus: async () => {
      throw new Error('markPurchaseStatus should not be called');
    },
    log(event: string, payload: any) {
      logs.push({ event, payload });
    },
    mintAddon: async () => {
      throw new Error('mintAddon should not be called');
    },
    mintLicense: async () => {
      throw new Error('mintLicense should not be called');
    },
    addEntitlement: async () => {
      throw new Error('addEntitlement should not be called');
    },
  };

  const payload = {
    order_id: storedPurchase.id,
    sku: storedPurchase.sku,
    tx_sig: 'tx-mismatch',
    amount_atomic: storedPurchase.amount_atomic + 1,
  };

  const headers = new Headers({
    'x-402-signature': 'sig-amount',
  });

  const { handleX402Webhook } = await import('@/app/api/store/webhook/x402/handler');

  const response = await handleX402Webhook(
    new Request('http://localhost/api/store/webhook/x402', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    }),
    deps,
  );

  assert.equal(response.status, 422);
  assert.equal(logs.some((entry) => entry.event === 'purchase.mismatch'), true);
  assert.equal(webhookEvents.length, 1);
});

test('rejects webhook when transaction memo does not match expected format', async () => {
  const logs: Array<{ event: string; payload: any }> = [];
  const webhookEvents: any[] = [];
  const subscriptionInserts: any[] = [];

  const storedPurchase: PurchaseRow = {
    id: 'order-memo-mismatch',
    sku: SKU.TEMPLATES_PACK_A,
    user_id: 'user-memo',
    amount_atomic: 700,
    status: 'pending',
    tx_sig: null,
  };

  const deps: X402WebhookDeps = {
    verifyX402Webhook: () => true,
    supa: makeSupa({ storedPurchase, webhookEvents, subscriptionInserts }),
    waitForFinalized: async () => true,
    getParsedTransaction: async () =>
      makeParsedTransaction('700', 'ctj:other-order:other-sku') as any,
    markPurchaseStatus: async () => {
      throw new Error('markPurchaseStatus should not be called');
    },
    log(event: string, payload: any) {
      logs.push({ event, payload });
    },
    mintAddon: async () => {
      throw new Error('mintAddon should not be called');
    },
    mintLicense: async () => {
      throw new Error('mintLicense should not be called');
    },
    addEntitlement: async () => {
      throw new Error('addEntitlement should not be called');
    },
  };

  const payload = {
    order_id: storedPurchase.id,
    sku: storedPurchase.sku,
    tx_sig: 'tx-memo',
    amount_atomic: storedPurchase.amount_atomic,
  };

  const headers = new Headers({
    'x-402-signature': 'sig-memo',
  });

  const { handleX402Webhook } = await import('@/app/api/store/webhook/x402/handler');

  const response = await handleX402Webhook(
    new Request('http://localhost/api/store/webhook/x402', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    }),
    deps,
  );

  assert.equal(response.status, 422);
  assert.equal(logs.some((entry) => entry.event === 'purchase.memo_mismatch'), true);
  assert.equal(webhookEvents.length, 1);
});
