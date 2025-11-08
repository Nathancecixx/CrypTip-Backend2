import { supa, getUserById } from './db';

export type PageRow = {
  id: string;
  user_id: string;
  slug: string | null;
  custom_domain: string | null;
  template_key: string;
  theme_json: any;
  public: boolean;
  created_at: string;
};

function normalizeHandle(handle: string | null): string | null {
  if (!handle) return null;
  const cleaned = handle.trim().toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const collapsed = cleaned.replace(/-+/g, '-').replace(/^-|-$/g, '');
  return collapsed || null;
}

async function getPageForUser(userId: string): Promise<PageRow | null> {
  const { data, error } = await supa
    .from('pages')
    .select('id, user_id, slug, custom_domain, template_key, theme_json, public, created_at')
    .eq('user_id', userId)
    .maybeSingle();

  if (error) throw error;
  return (data as PageRow | null) ?? null;
}

async function insertDefaultPage(userId: string, slug: string): Promise<PageRow> {
  const payload = {
    user_id: userId,
    slug,
    template_key: 'base.simple',
    theme_json: {},
    public: true,
  };

  const { data, error } = await supa
    .from('pages')
    .insert(payload)
    .select('id, user_id, slug, custom_domain, template_key, theme_json, public, created_at')
    .single();

  if (error) throw error;
  return data as PageRow;
}

export async function getOrCreateDefaultPageForUser(userId: string): Promise<PageRow> {
  const existing = await getPageForUser(userId);
  if (existing) return existing;

  const user = await getUserById(userId);
  if (!user) {
    throw new Error(`user_not_found:${userId}`);
  }

  const normalized = normalizeHandle(user.handle);
  const slug = normalized ?? user.wallet_pubkey;

  try {
    return await insertDefaultPage(userId, slug);
  } catch (error: any) {
    if (error?.code === '23505') {
      const retry = await getPageForUser(userId);
      if (retry) return retry;
    }
    throw error;
  }
}
