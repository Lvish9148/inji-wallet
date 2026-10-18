import {NativeModules, Platform} from 'react-native';

const {PlayIntegrity} = NativeModules;

export const APP_INTEGRITY_ENABLED = true;
// Fill in later, when the Google Cloud project is ready.
const CLOUD_PROJECT_NUMBER = '';
const NONCE_TIMEOUT_MS = 3000;

let prepared: Promise<void> | null = null;

function prepareProvider(): Promise<void> {
  if (!prepared) {
    prepared = PlayIntegrity.prepareProvider(CLOUD_PROJECT_NUMBER).catch(
      (e: unknown) => {
        prepared = null;
        throw e;
      },
    );
  }
  return prepared;
}

async function fetchNonce(host: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NONCE_TIMEOUT_MS);
  try {
    const res = await fetch(`${host}/v1/mimoto/integrity/nonce`, {
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`nonce request failed: ${res.status}`);
    }
    return (await res.json()).nonce;
  } finally {
    clearTimeout(timer);
  }
}

export async function getIntegrityHeaders(
  method: string,
  path: string,
  body: string,
  host: string,
): Promise<Record<string, string>> {
  if (!APP_INTEGRITY_ENABLED || Platform.OS !== 'android' || !PlayIntegrity) {
    return {};
  }
  try {
    const nonce = await fetchNonce(host);
    const headers: Record<string, string> = {'X-Integrity-Nonce': nonce};
    if (CLOUD_PROJECT_NUMBER) {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const Crypto = require('expo-crypto');
      const uri = path.split('?')[0];
      const hash = await Crypto.digestStringAsync(
        Crypto.CryptoDigestAlgorithm.SHA256,
        [method.toUpperCase(), uri, body, nonce].join('|'),
      );
      try {
        await prepareProvider();
        headers['X-Integrity-Token'] = await PlayIntegrity.requestToken(hash);
      } catch (e) {
        prepared = null;
        console.warn('Integrity token unavailable:', e);
      }
    }
    return headers;
  } catch (e) {
    console.warn('App integrity headers skipped:', e);
    return {};
  }
}
