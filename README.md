# Crypto Tip Jar — MVP (Server & Deployment) v1.0

This is a ready-to-deploy Next.js BFF implementing SIWS auth, x402 checkout + webhook (with HMAC), entitlement snapshots, pages CRUD, and a daily reconcile job. Supabase hosts the data. Optional fake-mint mode lets you run E2E before wiring real mints.

## Quickstart (Local)

```bash
pnpm i   # or npm/yarn
pnpm dev

# Health
curl http://localhost:3000/api/health
```

1. Create a Supabase project and run `supabase/schema.sql`.
2. Copy `.env.example` to `.env.local` and fill values.
3. Visit `/tip/<walletOrSlug>` or just `/<walletOrSlug>` (both work).

## Deploy to Vercel

1. Push this repo to GitHub and import into Vercel.
2. Set env vars from `.env.example` in Vercel > Settings > Environment Variables.
3. Cron from `vercel.json` auto-registers for `/api/jobs/reconcile`.
4. Create a Helius free key and set `RPC_PRIMARY_URL`.
5. Configure x402 webhook to `https://<your-app>.vercel.app/api/store/webhook/x402` and set the shared secret.

## Real Minting

This repo ships with `ENABLE_FAKE_MINT=1` to avoid private-key mint logic during development. Implement real mints in `src/lib/mint.ts` (Token-2022 non-transferable for licenses, Metaplex for add-ons), remove the flag, and rotate keys.

## Routes (selected)

- `POST /api/auth/siws/start` → { nonce, message }
- `POST /api/auth/siws/finish` → sets HttpOnly session
- `POST /api/pages` → create/update the page (auth)
- `GET  /api/pages/:slug` → public page metadata
- `GET  /api/me` / `/api/me/entitlements` → snapshots (auth)
- `POST /api/store/checkout` → returns x402 tx payload (auth)
- `POST /api/store/webhook/x402` → HMAC verify → on-chain confirm → mark paid → mint/activate
- `GET  /api/jobs/reconcile` → retry mints, expire subs

## Notes

- This MVP uses Supabase **Service Role** key server-side only. Add RLS later if you expose anon DB access.
- A dynamic route `app/[slug]` mirrors `app/tip/[slug]` so `https://cryptip.org/<walletOrSlug>` works without middleware.
