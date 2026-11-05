// Hedefi CANLI fetch et, PHP surumunu header/body'den cikar.
// IP/port degisikliginden bagimsiz: her seferinde hedefi yeniden sorar.
import { extractVersion } from './version.js';

const TIMEOUT_MS = 8000;
const PROBE_PATHS = ['/', '/index.php', '/phpinfo.php'];

/** "127.0.0.1:18101" / "http://..." -> URL | null. Bare host -> http://. */
export function toUrl(input) {
  let s = String(input || '').trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `http://${s}`;
  try {
    return new URL(s);
  } catch {
    return null;
  }
}

function friendlyError(e) {
  const msg = String(e?.message || e || '');
  if (e?.name === 'AbortError') return 'TIMEOUT — target zamaninda yanit vermedi.';
  if (/ERR_CERT|CERT_|SSL|TLS/i.test(msg)) return 'TLS hatasi — self-signed/invalid cert. Local target for dusuk http:// kullan.';
  if (/ERR_CONNECTION_REFUSED|ECONNREFUSED/i.test(msg)) return 'Baglanti reddedildi — target o portta open mi?';
  if (/ERR_NAME_NOT_RESOLVED|ENOTFOUND/i.test(msg)) return 'DNS — host cozumlenemiyor.';
  if (/ERR_CONNECTION_RESET/i.test(msg)) return 'Baglanti target tarafindan kesildi.';
  if (/Failed to fetch|NetworkError/i.test(msg)) return 'Ag hatasi — target bu tarayicidan erisilemiyor.';
  return msg || 'Bilinmeyen fetch hatasi.';
}

async function probe(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      credentials: 'omit',
      signal: ctrl.signal,
      headers: { Accept: 'text/html,*/*' },
    });
    const headers = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    let text = '';
    try { text = (await res.text()).slice(0, 200000); } catch { /* body okunamadi */ }
    return { ok: res.ok, status: res.status, url: res.url || url, headers, text };
  } catch (e) {
    return { ok: false, status: 0, url, headers: {}, text: '', error: friendlyError(e) };
  } finally {
    clearTimeout(t);
  }
}

/**
 * Hedefi canli kontrol et. Version bulunana kadar probe path'lerini dener.
 * @returns {Promise<object>} { ok, host, url, httpStatus?, server?, xPoweredBy?, version?, versionSource?, note?, error?, message? }
 */
export async function checkTarget(input) {
  const url = toUrl(input);
  if (!url) return { ok: false, error: 'INVALID_URL', message: 'Gecerli host/URL gir — or. 127.0.0.1:18101' };
  const host = url.hostname;
  let lastResponse = null;
  let lastError = null;

  for (const p of new Set(PROBE_PATHS)) {
    const target = new URL(p, url).toString();
    const r = await probe(target);
    if (r.error) { lastError = r; continue; }
    lastResponse = r;
    const version =
      extractVersion(r.headers['x-powered-by'] || '') ||
      extractVersion(r.headers['server'] || '') ||
      extractVersion(r.text || '');
    if (version) {
      return {
        ok: true,
        host,
        url: r.url || target,
        httpStatus: r.status,
        server: r.headers['server'] || null,
        xPoweredBy: r.headers['x-powered-by'] || null,
        version,
        versionSource: r.headers['x-powered-by'] || r.headers['server'] ? 'header' : 'body',
      };
    }
  }

  if (lastResponse) {
    return {
      ok: true,
      host,
      url: lastResponse.url || url.toString(),
      httpStatus: lastResponse.status,
      server: lastResponse.headers['server'] || null,
      xPoweredBy: lastResponse.headers['x-powered-by'] || null,
      version: null,
      note: 'Hedef yanit verdi ama PHP surumu aciklamadi (expose_php=Off?). Altta manual gir.',
    };
  }
  if (lastError) return { ok: false, error: lastError.error, message: lastError.error, host, url: url.toString() };
  return { ok: false, error: 'NO_RESPONSE', message: 'Hedeften yanit alinamadi.', host, url: url.toString() };
}