import { useState } from 'react'
import { api } from '../api.js'

const MCP_TOOLS = [
  ['scan_target', 'url, name?, save?', 'Fingerprint + WAF + port + TLS + CVE + risk; profile SQLite\'a kaydeder'],
  ['list_cves', 'software?, version?', 'Kritik CVE listesi (filtreli)'],
  ['get_cve', 'id', 'Tek CVE (PoC paneliyle)'],
  ['poc_list', '—', 'Native PoC katalogu'],
  ['poc_describe', 'cve_id', 'Native PoC mantigi + parametreler'],
  ['run_poc', 'cve_id, params', 'Run a PoC with the native engine (socket/HTTP scanner\'dan)'],
  ['list_profilees', '—', 'Saved Target profilees (SQLite)'],
  ['get_profilee', 'id', 'Tek profile (tam + tarihce)'],
  ['delete_profilee', 'id', 'profilei sil'],
  ['export_report', 'id, fmt', 'Risk raporu (md/json) + yol'],
  ['risk_score', 'id | url', 'Risk puani + faktor kirilimi'],
  ['tls_fingerprint', 'host, port?', 'TLS/sertifika parmak izi'],
  ['port_scan', 'host, extra_ports?', 'TCP port + servis banner'],
  ['list_logs', 'level?, category?, limit?', 'Operation logs (SQLite + file)'],
]

const INSTALL = `# stdio MCP (Qwen Code)
qwen mcp add p2s -- /opt/homebrew/bin/python3.12 \\
  mcp_server.py
# then: tam Qwen restart (qwen mcp add hot-load yapmaz)

# HTTP API
curl -sX POST http://127.0.0.1:8123/scan -H 'Content-Type: application/json' -d '{"url":"http://127.0.0.1:18111/index.php"}'
curl -sX POST http://127.0.0.1:8123/poc/CVE-2026-109618 -H 'Content-Type: application/json' -d '{"params":{"url":"…","cmd":"id>/out/p1"}}'`

export default function McpView() {
  const [tool, setTool] = useState('poc_list')
  const [arg, setArg] = useState('')
  const [out, setOut] = useState('')
  const [show, setShow] = useState(false)
  const [err, setErr] = useState('')

  async function run() {
    let args = {}
    if (arg.trim()) {
      try { args = JSON.parse(arg) } catch (e) { setErr('Argument JSON gecersiz: ' + e.message); return }
    }
    setErr(''); setShow(true); setOut('calisiyor…')
    try {
      let res
      if (tool === 'poc_list') { const r = await api.pocs(); res = Object.keys(r.pocs || {}).length + ' PoC' }
      else if (tool === 'list_cves') { const r = await api.cves(args.software); res = { count: r.count, first: r.cves.slice(0, 3) } }
      else if (tool === 'risk_score') { const r = await api.scan({ url: args.url, save: false }); res = (r.scan || {}).risk || r.risk }
      else if (tool === 'list_logs') { const r = await api.logs({ limit: 10 }); res = { count: r.count, latest: r.logs.slice(0, 5) } }
      setOut(JSON.stringify(res, null, 2))
    } catch (e) { setOut('✗ ' + e.message) }
  }

  return (
    <>
      <div className="panel">
        <h3>MCP Server — Qwen Code entegrasyonu</h3>
        <p style={{ color: 'var(--text2)', fontSize: 13, marginBottom: 12 }}>
          Scanner, Model Context Protocol server to Qwen Code (and any MCP client). {MCP_TOOLS.length} native tool.
        </p>
        <div className="cmd-box">{INSTALL}</div>
        <p style={{ color: 'var(--text3)', fontSize: 11.5, marginTop: 8 }}>
          Not: <code>qwen mcp add</code> sonrasi a full Qwen restart is required (no hot-load). Server stdio, bagimliliksiz.
        </p>
      </div>
      <div className="panel">
        <h3>Tool'lar <span className="tag">{MCP_TOOLS.length}</span></h3>
        <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>Tool</th><th>Args</th><th>Aciklama</th></tr></thead>
          <tbody>
            {MCP_TOOLS.map(t => <tr key={t[0]}><td>{t[0]}</td><td>{t[1]}</td><td className="cell-txt">{t[2]}</td></tr>)}
          </tbody>
        </table></div>
      </div>
      <div className="panel">
        <h3>Canli deneme (HTTP API uzerinden)</h3>
        <div className="grid2">
          <div>
            <label className="f">Tool</label>
            <select value={tool} onChange={e => setTool(e.target.value)}>
              <option value="poc_list">poc_list</option>
              <option value="list_cves">list_cves</option>
              <option value="risk_score">risk_score (url)</option>
              <option value="list_logs">list_logs</option>
            </select>
          </div>
          <div>
            <label className="f">Argument (JSON / opsiyonel)</label>
            <input className="mono" placeholder='{"software":"PHP"}' value={arg} onChange={e => setArg(e.target.value)} />
          </div>
        </div>
        {err && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 8 }}>{err}</div>}
        <button className="btn primary" style={{ marginTop: 12 }} onClick={run}>▶ Run</button>
        {show && <pre className="outbox show" style={{ display: 'block' }}>{out}</pre>}
      </div>
    </>
  )
}