import { createClient } from '@supabase/supabase-js';
import { env } from './env';

export const supa = createClient(env.NEXT_PUBLIC_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

export type UserRow = {
  id: string;
  wallet_pubkey: string;
  handle: string | null;
  created_at: string;
  last_login: string | null;
};

export async function upsertUserByWallet(pubkey: string) {
  const { data, error } = await supa
    .from('users')
    .upsert({ wallet_pubkey: pubkey }, { onConflict: 'wallet_pubkey' })
    .select()
    .single();
  if (error) throw error;
  return data as UserRow;
}

export async function getPageBySlug(slug: string) {
  const { data, error } = await supa
    .from('pages')
    .select('id, user_id, slug, custom_domain, template_key, theme_json, public, created_at')
    .eq('slug', slug)
    .maybeSingle();
  if (error) throw error;
  return data;
}

export async function getPageByWallet(walletOrSlug: string) {
  // Try vanity first
  const bySlug = await getPageBySlug(walletOrSlug);
  if (bySlug) return bySlug;
  // Else find by user's wallet
  const { data: user, error: uerr } = await supa
    .from('users')
    .select('id')
    .eq('wallet_pubkey', walletOrSlug)
    .maybeSingle();
  if (uerr) throw uerr;
  if (!user) return null;
  const { data: page } = await supa
    .from('pages')
    .select('id, user_id, slug, custom_domain, template_key, theme_json, public, created_at')
    .eq('user_id', user.id)
    .maybeSingle();
  return page ?? null;
}

export async function createOrUpdatePage(userId: string, payload: any) {
  const up = { ...payload, user_id: userId };
  const { data, error } = await supa.from('pages').upsert(up, { onConflict: 'user_id' }).select().single();
  if (error) throw error;
  return data;
}

export async function insertPurchase(row: any) {
  const { data, error } = await supa.from('purchases').insert(row).select().single();
  if (error) throw error;
  return data;
}

export type PurchaseStatus = 'pending' | 'paid' | 'paid-pending-mint' | 'failed';

export type PurchaseRow = {
  id: string;
  user_id: string;
  sku: string;
  amount_atomic: number;
  status: PurchaseStatus;
  tx_sig: string | null;
};

export type PurchaseStatusResult = {
  row: PurchaseRow;
  previous_status: PurchaseStatus;
  updated: boolean;
};

export async function markPurchaseStatus(
  id: string,
  status: 'paid' | 'paid-pending-mint' | 'failed',
  txSig?: string,
): Promise<PurchaseStatusResult> {
  const { data: existing, error: existingError } = await supa
    .from('purchases')
    .select('*')
    .eq('id', id)
    .single();
  if (existingError) throw existingError;

  const previousStatus = existing.status as PurchaseStatus;
  const updates: Record<string, unknown> = {};

  if (status === 'paid') {
    if (previousStatus === 'pending' || previousStatus === 'paid-pending-mint') {
      updates.status = status;
    }
  } else if (status !== previousStatus) {
    updates.status = status;
  }

  if (txSig !== undefined && existing.tx_sig !== txSig) {
    updates.tx_sig = txSig;
  }

  if (Object.keys(updates).length === 0) {
    return {
      row: existing as PurchaseRow,
      previous_status: previousStatus,
      updated: false,
    };
  }

  const { data, error } = await supa
    .from('purchases')
    .update(updates)
    .eq('id', id)
    .select()
    .single();
  if (error) throw error;
  return {
    row: data as PurchaseRow,
    previous_status: previousStatus,
    updated: true,
  };
}

export async function addEntitlement(row: any) {
  const { data, error } = await supa.from('entitlements').insert(row).select().single();
  if (error) throw error;
  return data;
}

export async function listEntitlements(userId: string) {
  const { data, error } = await supa
    .from('entitlements')
    .select('*')
    .eq('user_id', userId)
    .eq('status', 'active');
  if (error) throw error;
  return data ?? [];
}
