// api.js — typed client for the P2S backend (server.py).
// Same-origin in production (served by server.py); Vite proxies in dev.

const BASE = '' // relative — same origin

async function req(path, opt) {
  const r = await fetch(BASE + path, opt)
  const text = await r.text()
  let data
  try { data = text ? JSON.parse(text) : {} } catch { data = { _raw: text } }
  if (!r.ok) throw new Error((data && data.error) || `HTTP ${r.status}`)
  return data
}
const post = (path, body) => req(path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body || {}),
})
const del = (path) => req(path, { method: 'DELETE' })

export const api = {
  health: () => req('/health'),
  cves: (software, version) => {
    const p = new URLSearchParams()
    if (software) p.set('software', software)
    if (version) p.set('version', version)
    const q = p.toString()
    return req('/cves' + (q ? '?' + q : ''))
  },
  pocs: () => req('/pocs'),
  profiles: () => req('/profiles'),
  profile: (id) => req('/profiles/' + encodeURIComponent(id)),
  rescan: (id, body) => post(`/profiles/${encodeURIComponent(id)}/rescan`, body),
  deleteProfile: (id) => del('/profiles/' + encodeURIComponent(id)),
  renameProfile: (id, name) => post(`/profiles/${encodeURIComponent(id)}/rename`, { name }),
  scan: (body) => post('/scan', body),
  probe: (body) => post('/probe', body),
  runPoc: (cve, params) => post('/poc/' + encodeURIComponent(cve), { params }),
  runPocProfile: (pid, cve, params) => post(`/profiles/${encodeURIComponent(pid)}/poc/${encodeURIComponent(cve)}`, { params }),
  pocRuns: (pid) => req(`/profiles/${encodeURIComponent(pid)}/poc-runs`),
  scans: (pid) => req(`/profiles/${encodeURIComponent(pid)}/scans`),
  reportUrl: (id, fmt) => `/profiles/${encodeURIComponent(id)}/report?fmt=${fmt}`,
  logs: ({ level, category, q, limit } = {}) => {
    const p = new URLSearchParams()
    if (level) p.set('level', level)
    if (category) p.set('category', category)
    if (q) p.set('q', q)
    p.set('limit', String(limit || 300))
    return req('/logs?' + p.toString())
  },
  clearLogs: () => post('/logs/clear'),
}
