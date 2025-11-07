-- Supabase schema for Crypto Tip Jar MVP

create extension if not exists pgcrypto;

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  wallet_pubkey text unique not null,
  handle text unique,
  created_at timestamptz default now(),
  last_login timestamptz
);

create table if not exists pages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  slug text unique,
  custom_domain text,
  template_key text not null default 'base.simple',
  theme_json jsonb not null default '{}'::jsonb,
  public boolean not null default true,
  created_at timestamptz default now()
);
create unique index if not exists ux_pages_user on pages(user_id);
create index if not exists idx_pages_slug on pages(slug);

create table if not exists purchases (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  sku text not null,
  amount_atomic bigint not null,
  tx_sig text unique,
  status text not null check (status in ('pending','paid','paid-pending-mint','failed')),
  idempotency_key text unique,
  created_at timestamptz default now()
);

create table if not exists entitlements (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  type text not null check (type in ('license','addon','subscription')),
  sku text not null,
  ref_mint text,
  status text not null check (status in ('active','expired','revoked')),
  expires_at timestamptz,
  source_purchase uuid references purchases(id) on delete set null,
  created_at timestamptz default now()
);
create index if not exists idx_entitlements_owner_sku on entitlements(user_id, type, sku);

create table if not exists nfts_minted (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  purchase_id uuid references purchases(id) on delete set null,
  mint_address text unique,
  kind text not null check (kind in ('license','addon')),
  collection text,
  metadata_uri text,
  collection_verified boolean,
  created_at timestamptz default now()
);

create table if not exists subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  feature text not null check (feature in ('vanity','custom_domain')),
  period_start timestamptz not null,
  period_end timestamptz not null,
  status text not null check (status in ('active','grace','expired'))
);

create table if not exists domains (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  domain text unique not null,
  verification_txt text not null,
  ssl_status text,
  status text not null default 'pending',
  created_at timestamptz default now()
);

create table if not exists webhook_events (
  id uuid primary key default gen_random_uuid(),
  provider text not null,
  raw_json jsonb not null,
  signature_valid boolean not null,
  idempotency_key text,
  processed boolean not null default false,
  created_at timestamptz default now()
);

create table if not exists siws_nonces (
  address text primary key,
  nonce text not null,
  domain text not null,
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  ip text,
  user_agent text
);
