type StoredNonceRecord = {
  address: string;
  nonce: string;
  issuedAt: string;
  message: string;
  expiresAt: number;
};

const TTL_MS = 15 * 60 * 1000;

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
  const storedRecord: StoredNonceRecord = {
    ...record,
    expiresAt: Date.now() + TTL_MS,
  };
  globalStore.set(record.address, storedRecord);
}

export function loadSiwsNonce(address: string): Omit<StoredNonceRecord, 'expiresAt'> | null {
  cleanupExpired();
  const stored = globalStore.get(address);
  if (!stored) {
    return null;
  }

  if (stored.expiresAt <= Date.now()) {
    globalStore.delete(address);
    return null;
  }

  const { nonce, message, issuedAt } = stored;
  return { address, nonce, message, issuedAt };
}

export function consumeSiwsNonce(address: string) {
  cleanupExpired();
  globalStore.delete(address);
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
