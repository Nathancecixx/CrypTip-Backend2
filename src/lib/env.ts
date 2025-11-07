import { z } from 'zod';

const EnvSchema = z.object({
  NEXT_PUBLIC_SOLANA_CLUSTER: z.enum(['mainnet-beta','devnet','testnet']).default('mainnet-beta'),
  RPC_PRIMARY_URL: z.string().url(),
  RPC_FALLBACK_URL: z.string().url().optional(),

  NEXT_PUBLIC_SUPABASE_URL: z.string().url(),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(10),

  // Sessions use SESSION_SECRET. JWT_SECRET is optional legacy compatibility.
  JWT_SECRET: z.string().min(32).optional(),
  SESSION_SECRET: z.string().min(32).optional(),
  SIWS_DOMAIN: z.string().min(3),
  SESSION_COOKIE_NAME: z.string().optional(),
  COOKIE_NAME: z.string().optional(),
  FRONTEND_ORIGIN: z.string().url().default('https://cryptip-frontend.vercel.app'),
  ORIGIN_ALLOWLIST: z.string().optional(),

  X402_WEBHOOK_SECRET: z.string().min(10),
  X402_MERCHANT_USDC_ACCOUNT: z.string().min(20).optional(),
  X402_USDC_MINT: z.string().min(20).optional(),

  MINT_COLLECTION_ADDRESS: z.string().min(20),
  MINT_SIGNER_SECRET: z.string().min(20),
  ENABLE_FAKE_MINT: z.string().optional(),

  UPSTASH_REDIS_REST_URL: z.string().url().optional(),
  UPSTASH_REDIS_REST_TOKEN: z.string().optional(),
});

const raw = EnvSchema.parse({
  NEXT_PUBLIC_SOLANA_CLUSTER: process.env.NEXT_PUBLIC_SOLANA_CLUSTER,
  RPC_PRIMARY_URL: process.env.RPC_PRIMARY_URL,
  RPC_FALLBACK_URL: process.env.RPC_FALLBACK_URL,

  NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,

  JWT_SECRET: process.env.JWT_SECRET,
  SESSION_SECRET: process.env.SESSION_SECRET,
  SIWS_DOMAIN: process.env.SIWS_DOMAIN,
  SESSION_COOKIE_NAME: process.env.SESSION_COOKIE_NAME,
  COOKIE_NAME: process.env.COOKIE_NAME,
  FRONTEND_ORIGIN: process.env.FRONTEND_ORIGIN,
  ORIGIN_ALLOWLIST: process.env.ORIGIN_ALLOWLIST,

  X402_WEBHOOK_SECRET: process.env.X402_WEBHOOK_SECRET,
  X402_MERCHANT_USDC_ACCOUNT: process.env.X402_MERCHANT_USDC_ACCOUNT,
  X402_USDC_MINT: process.env.X402_USDC_MINT,

  MINT_COLLECTION_ADDRESS: process.env.MINT_COLLECTION_ADDRESS,
  MINT_SIGNER_SECRET: process.env.MINT_SIGNER_SECRET,
  ENABLE_FAKE_MINT: process.env.ENABLE_FAKE_MINT,

  UPSTASH_REDIS_REST_URL: process.env.UPSTASH_REDIS_REST_URL,
  UPSTASH_REDIS_REST_TOKEN: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const {
  SESSION_COOKIE_NAME: legacySessionCookieName,
  COOKIE_NAME,
  SESSION_SECRET: explicitSessionSecret,
  JWT_SECRET: legacyJwtSecret,
  ...rest
} = raw;

const sessionSecret = explicitSessionSecret ?? legacyJwtSecret;
if (!sessionSecret) {
  throw new Error('SESSION_SECRET env var is required (or set JWT_SECRET for legacy).');
}

const sessionCookieName = COOKIE_NAME ?? legacySessionCookieName ?? 'ctj_sess';

export const env = {
  ...rest,
  SESSION_SECRET: sessionSecret,
  SESSION_COOKIE_NAME: sessionCookieName,
};
