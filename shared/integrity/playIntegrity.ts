import {NativeModules, Platform} from 'react-native';

const KeyAttestation = NativeModules.KeyAttestation;

export const APP_INTEGRITY_ENABLED = true;
const NONCE_TIMEOUT_MS = 3000;

let registeredHost: string | null = null;

let registrationInFlight: {
  host: string;
  promise: Promise<void>;
} | null = null;

async function fetchNonce(host: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NONCE_TIMEOUT_MS);

  try {
    const res = await fetch(`${host}/v1/mimoto/integrity/nonce`, {
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`Nonce request failed: ${res.status}`);
    }

    const data = await res.json();

    if (typeof data.nonce !== 'string' || !data.nonce) {
      throw new Error('Invalid nonce response');
    }

    return data.nonce;
  } finally {
    clearTimeout(timer);
  }
}

async function registerAttestedKey(host: string): Promise<void> {
  // Always use a brand-new key made with a fresh nonce, so the proof is recent.
  const challenge = await fetchNonce(host);

  await KeyAttestation.deleteKey();

  const certificateChain: string[] = await KeyAttestation.generateAttestedKey(
    challenge,
  );

  if (!certificateChain?.length) {
    throw new Error('Attestation certificate chain is empty');
  }

  const keyId: string = await KeyAttestation.getKeyId();

  const response = await fetch(`${host}/v1/mimoto/integrity/register`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({keyId, certificateChain}),
  });

  if (!response.ok) {
    throw new Error(`Attestation registration failed: ${response.status}`);
  }
}

async function ensureRegistered(host: string): Promise<void> {
  if (registeredHost === host) {
    return;
  }

  if (registrationInFlight?.host === host) {
    return registrationInFlight.promise;
  }

  const promise = registerAttestedKey(host).then(() => {
    registeredHost = host;
  });

  registrationInFlight = {host, promise};

  try {
    await promise;
  } finally {
    if (registrationInFlight?.promise === promise) {
      registrationInFlight = null;
    }
  }
}

export async function getIntegrityHeaders(
  method: string,
  path: string,
  body: string,
  host: string,
): Promise<Record<string, string>> {
  try {
    if (!KeyAttestation) {
      throw new Error('Android Key Attestation module is unavailable');
    }

    const normalizedHost = host.replace(/\/+$/, '');
    console.info('INTEGRITY-DEBUG: start', method, path);

    await ensureRegistered(normalizedHost);

    const nonce = await fetchNonce(normalizedHost);

    const uri = path.split('?')[0].replace(/^\/v1\/mimoto(?=\/|$)/, '') || '/';

    const payload = [method.toUpperCase(), uri, body, nonce].join('|');

    const keyId: string = await KeyAttestation.getKeyId();

    const signature: string = await KeyAttestation.signPayload(payload);

    const result = {
      'X-Integrity-Nonce': nonce,
      'X-Integrity-Key-Id': keyId,
      'X-Integrity-Signature': signature,
    };
    console.info('INTEGRITY-HEADERS', JSON.stringify({path, headers: result}));
    return result;
  } catch (e) {
    console.warn('App integrity headers skipped:', e);
    return {};
  }
}
