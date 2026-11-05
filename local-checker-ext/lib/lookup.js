// SURUM-TABANLI risk DB'si (data/db.json) sorgulama.
// db.json = { cve, updated, rules, versions: { "8.4": { status, note } } }
import { branchOf, scoreVersion, statusMeta } from './version.js';

let dbCache = null;

async function loadDb(force = false) {
  if (dbCache && !force) return dbCache;
  const url = chrome.runtime.getURL('data/db.json');
  const res = await fetch(url);
  if (!res.ok) throw new Error(`db.json okunamadi (HTTP ${res.status})`);
  dbCache = await res.json();
  return dbCache;
}

/** db.json meta (cve, updated). */
export async function getMeta() {
  const db = await loadDb();
  return { cve: db.cve || '', updated: db.updated || '' };
}

/**
 * PHP surumunu db.json'da sorgula (branch eslesmesi; yoksa rules fallback).
 * @returns {{ok:boolean, branch:string|null, status:string, tone:string, label:string, note:string, source:'db'|'rules'}}
 */
export async function lookupVersion(version) {
  const branch = branchOf(version);
  if (!branch) {
    const m = statusMeta('INCOMPLETE_VERSION');
    return { ok: false, branch: null, status: 'INCOMPLETE_VERSION', tone: m.tone, label: m.label, note: 'Surum parse edilemedi (x.y(.z) gir).', source: 'db' };
  }
  const db = await loadDb();
  const entry = (db.versions || {})[branch];
  if (entry) {
    const m = statusMeta(entry.status);
    return { ok: true, branch, status: entry.status, tone: m.tone, label: m.label, note: entry.note || '', source: 'db' };
  }
  const sc = scoreVersion(version, db.rules || {});
  return { ok: true, branch, status: sc.status, tone: sc.tone, label: sc.label, note: sc.reason, source: 'rules' };
}

/** db.json -> versions listesi (branch sirasiyla). */
export async function listVersions() {
  const db = await loadDb();
  return Object.entries(db.versions || {})
    .map(([branch, v]) => ({ branch, status: v.status, note: v.note || '' }))
    .sort((a, b) => a.branch.localeCompare(b.branch, undefined, { numeric: true }));
}
