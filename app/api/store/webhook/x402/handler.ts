import { NextResponse } from 'next/server';

import { verifyX402Webhook } from '@/src/lib/x402';
import { markPurchaseStatus, addEntitlement, supa } from '@/src/lib/db';
import { waitForFinalized, getParsedTransaction } from '@/src/lib/rpc';
import { log } from '@/src/lib/logger';
import { mintAddon, mintLicense } from '@/src/lib/mint';
import { SKU } from '@/src/constants';
import { env } from '@/src/lib/env';

export const defaultDeps = {
  verifyX402Webhook,
  supa,
  waitForFinalized,
  getParsedTransaction,
  markPurchaseStatus,
  log,
  mintAddon,
  mintLicense,
  addEntitlement,
};
export type X402WebhookDeps = typeof defaultDeps;

export async function handleX402Webhook(req: Request, deps: X402WebhookDeps = defaultDeps) {
  const raw = await req.text();
  const sig = req.headers.get('x-402-signature') ?? '';
  const idem = req.headers.get('x-idempotency-key') ?? '';

  const valid = deps.verifyX402Webhook(raw, sig);

  // Audit all events
  await deps.supa
    .from('webhook_events')
    .insert({ provider: 'x402', raw_json: raw, signature_valid: valid, idempotency_key: idem });

  if (!valid) return new NextResponse('Unauthorized', { status: 401 });

  let body: { order_id: string; sku: string; tx_sig: string; amount_atomic: number; user_wallet?: string };
  try {
    body = JSON.parse(raw);
  } catch {
    return new NextResponse('Bad JSON', { status: 400 });
  }

  const ok = await deps.waitForFinalized(body.tx_sig, 20_000);
  if (!ok) return new NextResponse('Unconfirmed', { status: 202 });

  const { data: storedPurchase, error: purchaseError } = await deps.supa
    .from('purchases')
    .select('id, user_id, sku, amount_atomic, status, tx_sig')
    .eq('id', body.order_id)
    .single();

  if (purchaseError || !storedPurchase) {
    deps.log('purchase.missing', { purchase_id: body.order_id, error: purchaseError?.message });
    return new NextResponse('Purchase not found', { status: 404 });
  }

  const expectedSku = storedPurchase.sku;
  if (expectedSku !== body.sku) {
    deps.log('purchase.mismatch', {
      purchase_id: storedPurchase.id,
      field: 'sku',
      expected: expectedSku,
      received: body.sku,
    });
    return new NextResponse('Purchase mismatch', { status: 422 });
  }

  const storedAmount = BigInt(storedPurchase.amount_atomic);
  const receivedAmount = BigInt(body.amount_atomic);
  if (storedAmount !== receivedAmount) {
    deps.log('purchase.mismatch', {
      purchase_id: storedPurchase.id,
      field: 'amount_atomic',
      expected: storedAmount.toString(),
      received: receivedAmount.toString(),
    });
    return new NextResponse('Purchase mismatch', { status: 422 });
  }

  const tx = await deps.getParsedTransaction(body.tx_sig);
  if (!tx) {
    deps.log('purchase.transaction_missing', { purchase_id: storedPurchase.id, tx: body.tx_sig });
    return new NextResponse('Transaction invalid', { status: 422 });
  }

  const merchantAccount = env.X402_MERCHANT_USDC_ACCOUNT;
  const usdcMint = env.X402_USDC_MINT;
  if (!merchantAccount || !usdcMint) {
    deps.log('purchase.env_missing', { purchase_id: storedPurchase.id });
    return new NextResponse('Server misconfigured', { status: 500 });
  }

  const instructions = (tx.transaction.message as any)?.instructions ?? [];
  const transferIx = instructions.find((ix: any) => ix?.program === 'spl-token' && ix?.parsed?.type === 'transfer');

  const transferInfo = transferIx?.parsed?.info ?? null;
  if (!transferInfo) {
    deps.log('purchase.transfer_missing', { purchase_id: storedPurchase.id, tx: body.tx_sig });
    return new NextResponse('Transaction invalid', { status: 422 });
  }

  if (transferInfo.destination !== merchantAccount || transferInfo.mint !== usdcMint) {
    deps.log('purchase.transfer_mismatch', {
      purchase_id: storedPurchase.id,
      tx: body.tx_sig,
      destination: transferInfo.destination,
      mint: transferInfo.mint,
    });
    return new NextResponse('Transaction invalid', { status: 422 });
  }

  try {
    const transferAmount = BigInt(transferInfo.amount);
    if (transferAmount !== storedAmount) {
      deps.log('purchase.transfer_amount_mismatch', {
        purchase_id: storedPurchase.id,
        tx: body.tx_sig,
        expected: storedAmount.toString(),
        received: transferInfo.amount,
      });
      return new NextResponse('Transaction invalid', { status: 422 });
    }
  } catch (err) {
    deps.log('purchase.transfer_amount_parse_error', {
      purchase_id: storedPurchase.id,
      tx: body.tx_sig,
      amount: transferInfo.amount,
      error: String(err),
    });
    return new NextResponse('Transaction invalid', { status: 422 });
  }

  const memoIx = instructions.find((ix: any) => ix?.program === 'spl-memo');
  const memo = memoIx?.parsed?.info?.memo ?? memoIx?.parsed?.memo ?? null;
  const expectedMemo = `ctj:${storedPurchase.id}:${storedPurchase.sku}`;
  if (memo !== expectedMemo) {
    deps.log('purchase.memo_mismatch', {
      purchase_id: storedPurchase.id,
      tx: body.tx_sig,
      expected: expectedMemo,
      received: memo,
    });
    return new NextResponse('Transaction invalid', { status: 422 });
  }

  const { row: purchase, previous_status } = await deps.markPurchaseStatus(body.order_id, 'paid', body.tx_sig);

  // Idempotency: if already paid, accept quietly
  if (purchase.status === 'paid' && previous_status === 'paid') {
    deps.log('purchase.duplicate', { purchase_id: purchase.id, sku: purchase.sku, tx: body.tx_sig });
    return NextResponse.json({ status: 'ok' });
  }

  deps.log('purchase.paid', { purchase_id: purchase.id, sku: purchase.sku, tx: body.tx_sig });

  try {
    if (purchase.sku === SKU.TEMPLATES_PACK_A) {
      const res = await deps.mintLicense(body.user_wallet ?? '', purchase.sku);
      await deps.addEntitlement({
        user_id: purchase.user_id,
        type: 'license',
        sku: purchase.sku,
        ref_mint: res.mint,
        status: 'active',
        source_purchase: purchase.id,
      });
    } else if (purchase.sku === SKU.ADDON_HALO_V1) {
      const res = await deps.mintAddon(body.user_wallet ?? '', purchase.sku);
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

    return NextResponse.json({ status: 'ok' });
  } catch (e) {
    await deps.markPurchaseStatus(body.order_id, 'paid-pending-mint');
    deps.log('mint.defer', { purchase_id: body.order_id, error: String(e) });
    return new NextResponse('Deferred', { status: 202 });
  }
}
