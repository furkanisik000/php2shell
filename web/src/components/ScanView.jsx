import { useState, useEffect } from 'react'
import { api } from '../api.js'
import RiskGauge from './RiskGauge.jsx'
import CveCard from './CveCard.jsx'

export default function ScanView({ pocs, activeprofileeId, onprofileesChanged, onLogsChanged }) {
  const [url, setUrl] = useState('')
  const [name, setName] = useState('')
  const [scanning, setScanning] = useState(false)
  const [state, setState] = useState('ready')
  const [scan, setScan] = useState(null)
  const [profileeId, setprofileeId] = useState(null)
  const [profileeName, setprofileeName] = useState('')
  const [history, setHistory] = useState(null)

  useEffect(() => {
    if (!activeprofileeId) return
    api.profilee(activeprofileeId).then(p => {
      setScan(p.scan || {})
      setprofileeId(p.id)
      setprofileeName(p.name || '')
      setUrl(p.url || '')
      setName(p.name || '')
      loadHistory(p.id)
    }).catch(() => {})
  }, [activeprofileeId])

  function loadHistory(pid) {
    Promise.all([api.scans(pid), api.pocRuns(pid)])
      .then(([sc, pc]) => setHistory({ scans: sc.scans, pocs: pc.runs }))
      .catch(() => setHistory(null))
  }

  async function doScan(save) {
    if (!url.trim()) { alert('Enter a target URL'); return }
    setScanning(true); setState('taraniyor…')
    try {
      const body = { url, save }
      if (name.trim()) body.name = name.trim()
      const p = await api.scan(body)
      setScan(p.scan || p)
      if (p.id) {
        setprofileeId(p.id)
        setprofileeName(p.name || '')
        if (save) { onprofileesChanged(); loadHistory(p.id) }
      }
      if (save) onLogsChanged()
      setState(save ? 'kaydedildi ✓' : 'tara')
    } catch (e) {
      setState('hata'); alert('Scanma hatasi: ' + e.message)
    }
    setScanning(false)
  }

  async function rescan() {
    if (!profileeId) return
    setState('yeniden taraniyor…')
    try {
      const p = await api.rescan(profileeId, {})
      setScan(p.scan || p)
      onprofileesChanged(); onLogsChanged()
      loadHistory(profileeId)
      setState('yeniden tarandi ✓')
    } catch (e) { setState('hata'); alert('Rescan hatasi: ' + e.message) }
  }

  const s = scan || {}
  return (
    <>
      {/* SIDE */}
      <div className="col-side">
        <div className="panel">
          <h3>Hedef <span className="tag">{state}</span></h3>
          <label className="f">Hedef URL</label>
          <input className="mono" value={url} onChange={e => setUrl(e.target.value)}
            placeholder="http://127.0.0.1:18111/index.php" spellCheck="false" />
          <label className="f" style={{ marginTop: 12 }}>profile adi (opsiyonel)</label>
          <input value={name} onChange={e => setName(e.target.value)} placeholder="orn: php-target-18111" spellCheck="false" />
          <div style={{ display: 'flex', gap: 8, marginTop: 14, flexWrap: 'wrap' }}>
            <button className="btn primary block" disabled={scanning} onClick={() => doScan(true)}>
              {scanning ? <span className="spin" /> : '🎯'} Scan + Kaydet
            </button>
          </div>
          <button className="btn sm block" style={{ marginTop: 8 }} disabled={scanning} onClick={() => doScan(false)}>Tek tara (kaydetme)</button>
        </div>
        {s.fingerprint && <FingerprintPanel s={s} />}
        {s.waf && s.waf.names && s.waf.names.length > 0 && <WafPanel waf={s.waf} />}
        <PortsPanel s={s} />
        {s.tls && s.tls.ok && <TlsPanel s={s} />}
        {s.headers_audit && s.headers_audit.length > 0 && <HeadersPanel s={s} />}
        <PathsPanel s={s} />
      </div>

      {/* MAIN */}
      <div className="col-main">
        {!s && (
          <div className="empty">
            <div className="big">🎯</div>
            Enter a target URL on the left → <b>Scan</b>. Scanner fingerprint + WAF + port + TLS + header cikarir,<br />
            eslesen kritik CVE'leri listeler, <b>0–100 risk puani</b> verir, logs every step <b>loglar</b> and sends native PoCs itself.
          </div>
        )}
        {s && (
          <>
            <RiskGauge risk={s.risk} />
            {s.waf && s.waf.names && s.waf.names.length > 0 && (
              <div className="waf-banner">🛡 WAF sinyali: {s.waf.names.join(', ')} — exploit denemeleri engellenebilir.</div>
            )}
            <div className="sec-head">Eslesen Kritik CVE'ler <span className="n">{(s.cves || []).length} · {(s.cves || []).filter(c => pocs[c.id]).length} native PoC</span></div>
            {(s.cves || []).length === 0 ? (
              <div className="sec-empty" style={{ marginTop: 8 }}>No critical CVE matches for the detected versions ✓</div>
            ) : (
              (s.cves || []).map(c => <CveCard key={c.id} cve={c} pocs={pocs} hitMajor={s.php_major}
                profileeId={profileeId} onRun={() => { onprofileesChanged(); onLogsChanged(); }} />)
            )}

            {profileeId && history && (
              <>
                <div className="sec-head">Scanma Tarihcesi <span className="n">{history.scans.length}</span>
                  <button className="btn sm" style={{ marginLeft: 'auto' }} onClick={rescan}>↻ Yeniden Scan (tarihe ekle)</button>
                </div>
                <div className="history-block">
                  <div className="tbl-wrap"><table className="tbl">
                    <thead><tr><th>#</th><th>Time (UTC)</th><th>URL</th><th>Risk</th><th>CVE</th></tr></thead>
                    <tbody>
                      {history.scans.map(x => (
                        <tr key={x.id}><td>{x.id}</td><td>{x.ts}</td><td>{x.url || ''}</td>
                          <td className={(x.risk && x.risk.score >= 65) ? 'warn' : 'ok'}>{x.risk ? x.risk.score : '—'}</td><td>{x.cve_count}</td></tr>
                      ))}
                    </tbody>
                  </table></div>
                </div>
                <div className="sec-head">PoC Runma Kayitlari <span className="n">{history.pocs.length}</span></div>
                <div className="history-block">
                  {history.pocs.length === 0 ? <div className="sec-empty">no PoC run records</div> : (
                    <div className="tbl-wrap"><table className="tbl">
                      <thead><tr><th>#</th><th>Time</th><th>CVE</th><th>Result</th><th>Evidence (short)</th></tr></thead>
                      <tbody>
                        {history.pocs.map(r => (
                          <tr key={r.id}><td>{r.id}</td><td>{r.ts}</td><td>{r.cve_id}</td>
                            <td className={r.success ? 'ok' : 'no'}>{r.success ? '✓ BASARILI' : '✗'}</td>
                            <td className="cell-txt">{(r.result && r.result.evidence || '').slice(0, 90)}</td></tr>
                        ))}
                      </tbody>
                    </table></div>
                  )}
                </div>
              </>
            )}
          </>
        )}
      </div>
    </>
  )
}

/* ---------- side panels ---------- */
function kvRows(s) {
  const rows = []
  const add = (k, v, cls) => { if (v !== '' && v != null && v !== 'unknown' && v !== '-') rows.push([k, v, cls || '']) }
  add('Durum', s.status ? ('HTTP ' + s.status) : (s.error || '—'), (s.status >= 200 && s.status < 500) ? 'ok' : 'bad')
  if (s.ttfb_ms != null) add('TTFB', s.ttfb_ms + ' ms')
  add('PHP', s.php_version, s.php_version ? 'ok' : '')
  add('Web', (s.webserver !== 'unknown' ? s.webserver : '') + (s.webserver_version ? ' ' + s.webserver_version : ''), s.webserver !== 'unknown' ? 'ok' : '')
  add('OS', s.os_hint)
  add('SAPI', s.sapi_guess !== 'unknown' ? s.sapi_guess : '')
  add('Server hdr', s.server)
  add('X-Powered-By', s.xpoweredby)
  if (!rows.length) rows.push(['Durum', s.error || 'erisilemedi', 'bad'])
  return rows
}

function FingerprintPanel({ s }) {
  return (
    <div className="panel">
      <h3>Fingerprint</h3>
      <div className="kv">
        {kvRows(s).map((r, i) => <div className="row" key={i}><span className="k">{r[0]}</span><span className={'v ' + r[2]}>{r[1]}</span></div>)}
      </div>
    </div>
  )
}
function WafPanel({ waf }) {
  return (
    <div className="panel">
      <h3>WAF / Mitigasyon</h3>
      <div className="pfacts">{waf.names.map(n => <span key={n} className="pfact" style={{ color: 'var(--amber)' }}>{n}</span>)}</div>
      {waf.challenge_note && <p style={{ color: 'var(--text2)', fontSize: 11.5, marginTop: 8 }}>{waf.challenge_note}</p>}
    </div>
  )
}
function PortsPanel({ s }) {
  const ports = s.ports || []
  return (
    <div className="panel">
      <h3>Open Ports <span className="tag">{ports.length}</span></h3>
      {ports.length === 0 ? <div className="sec-empty">No open ports found</div> : (
        <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
          <tbody>{ports.map(p => <tr key={p.port}><td className="ok">:{p.port}</td><td>{p.service || 'open'}</td><td>{p.version || '—'}</td></tr>)}</tbody>
        </table></div>
      )}
    </div>
  )
}
function TlsPanel({ s }) {
  const t = s.tls
  const rows = [
    ['Protocol', t.protocol], ['Cipher', `${(t.cipher || {}).name || ''} (${(t.cipher || {}).tls || ''})`],
    ['Issuer', (t.cert || {}).issuer], ['CN', (t.cert || {}).cn],
    ['SAN', ((t.cert || {}).san || []).join(', ')], ['Expiry', `${(t.cert || {}).not_after || ''} (${(t.cert || {}).days_to_expire} gun)`],
  ]
  return (
    <div className="panel">
      <h3>TLS / Sertifika</h3>
      <div className="kv">{rows.map((r, i) => <div className="row" key={i}><span className="k">{r[0]}</span><span className="v">{r[1] || '—'}</span></div>)}</div>
    </div>
  )
}
function HeadersPanel({ s }) {
  return (
    <div className="panel">
      <h3>HTTP Header Audit</h3>
      <div className="tbl-wrap"><table className="tbl">
        <thead><tr><th>Header</th><th>Durum</th></tr></thead>
        <tbody>{s.headers_audit.map((h, i) => <tr key={i}><td>{h.label}</td><td className={h.present ? 'ok' : 'no'}>{h.present ? '✅' : '❌'} <span className="cell-txt">{h.note || ''}</span></td></tr>)}</tbody>
      </table></div>
    </div>
  )
}
function PathsPanel({ s }) {
  const paths = (s.paths || []).filter(p => p.interesting)
  if (!paths.length) return null
  return (
    <div className="panel">
      <h3>Ilginc Path'ler</h3>
      <div className="tbl-wrap"><table className="tbl">
        <thead><tr><th>Path</th><th>HTTP</th></tr></thead>
        <tbody>{paths.map(p => <tr key={p.path}><td>{p.path}</td><td className={p.status < 400 ? 'ok' : 'warn'}>{p.status}</td></tr>)}</tbody>
      </table></div>
    </div>
  )
}