type StoredNonceRecord = {
  address: string;
  nonce: string;
  issuedAt: string;
  message: string;
  domain: string;
  expiresAt: number;
};

const TTL_MS = 10 * 60 * 1000;

declare global {
  // eslint-disable-next-line no-var
  var __ctjNonceStore: Map<string, StoredNonceRecord> | undefined;
}

const globalStore = globalThis.__ctjNonceStore ?? new Map<string, StoredNonceRecord>();

if (!globalThis.__ctjNonceStore) {
  globalThis.__ctjNonceStore = globalStore;
}

export function saveSiwsNonce(record: Omit<StoredNonceRecord, 'expiresAt'>) {
  cleanupExpired();
  globalStore.set(record.nonce, { ...record, expiresAt: Date.now() + TTL_MS });
}

export function consumeSiwsNonce(nonce: string): Omit<StoredNonceRecord, 'expiresAt'> | null {
  cleanupExpired();
  const stored = globalStore.get(nonce);
  if (!stored) {
    return null;
  }

  globalStore.delete(nonce);

  if (stored.expiresAt <= Date.now()) {
    return null;
  }

  const { address, message, issuedAt, domain } = stored;
  return { address, nonce, message, issuedAt, domain };
}

export function extractNonceFromMessage(message: string): string | null {
  const match = message.match(/(?:^|\n)Nonce: ([^\n]+)/);
  return match ? match[1].trim() : null;
}

function cleanupExpired() {
  const now = Date.now();
  for (const [nonce, record] of globalStore.entries()) {
    if (record.expiresAt <= now) {
      globalStore.delete(nonce);
    }
  }
}
