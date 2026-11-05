import { useState } from 'react'
import { api } from '../api.js'

export default function CveCard({ cve, pocs, hitMajor, profileeId, onRun }) {
  const spec = pocs[cve.id]
  const isHit = hitMajor && (cve.affected || []).includes(hitMajor)
  const scoreCls = cve.score >= 9.5 ? 'crit' : 'high'
  const nvd = `https://nvd.nist.gov/vuln/detail/${cve.id}`

  return (
    <div className={'cve' + (isHit ? ' hit' : '')}>
      <div className="cve-top">
        <span className="cve-id">{cve.id}</span>
        {isHit && <span className="badge b-hit">HIT</span>}
        <span className="badge b-sw">{cve.software || ''}</span>
        {(cve.exploit || {}).type && <span className="badge b-type">{cve.exploit.type}</span>}
        {(cve.exploit || {}).preauth && <span className="badge b-pre">PRE-AUTH</span>}
        {spec && <span className="badge b-nat">native</span>}
        <span className={'score ' + scoreCls}>{(cve.score || 0).toFixed(1)}</span>
      </div>
      <div className="cve-desc">{cve.desc || ''}</div>
      {cve.affected && cve.affected.length > 0 && (
        <div className="chips">
          {cve.affected.map(v => <span key={v} className={'chip' + (isHit && v === hitMajor ? ' hit' : '')}>{v}{isHit && v === hitMajor ? ' ◄' : ''}</span>)}
        </div>
      )}
      <div className="cve-meta">
        <span className="cwe">{cve.cwe || ''}</span>
        <span>📅 {cve.published || ''}</span>
        <span><a href={nvd} target="_blank" rel="noopener">NVD</a>{(cve.edb || []).length > 0 && <> <a href={cve.edb[0]} target="_blank" rel="noopener">EDB</a></>}</span>
      </div>
      {spec && <PocPanel cve={cve} spec={spec} profileeId={profileeId} onRun={onRun} />}
    </div>
  )
}

function PocPanel({ cve, spec, profileeId, onRun }) {
  const [params, setParams] = useState({})
  const [running, setRunning] = useState(false)
  const [out, setOut] = useState('')
  const [result, setResult] = useState(null)
  const [show, setShow] = useState(false)

  async function run() {
    const vals = {}
    ;(spec.inputs || []).forEach(i => { vals[i.key] = (params[i.key] || '').trim() })
    setRunning(true); setShow(true); setResult(null)
    setOut('native engine calisiyor… (socket/HTTP scanner\'dan atiliyor)')
    try {
      const r = profileeId
        ? await api.runPocprofilee(profileeId, cve.id, vals)
        : await api.runPoc(cve.id, vals)
      renderResult(r.result || r)
      onRun && onRun()
    } catch (e) {
      setOut('✗ ' + e.message)
    }
    setRunning(false)
  }

  function renderResult(res) {
    let h = ''
    if (res.error) h += `<span class="err">✗ ${esc(res.error)}</span>\n`
    if (res.status != null) h += `<span class="dim">HTTP ${res.status}</span>\n`
    if (res.evidence) h += `<span class="dim">EVIDENCE:</span>\n<span class="ev">${esc(res.evidence)}</span>\n`
    const det = res.detail || {}
    if (det.host) h += `<span class="dim">target: ${esc(det.host)}</span>\n`
    if (det.stage) h += `<span class="dim">asama: ${esc(det.stage)}</span>\n`
    if (det.chunk_base) h += `<span class="dim">chunk=${esc(det.chunk_base)} libphp=${esc(det.libphp_base || '')} zif=${esc(det.zif_abs || '')} htdata=${esc(det.htdata_abs || '')}</span>\n`
    if (res.log && res.log.length) h += `<span class="dim">── log ──</span>\n${res.log.map(l => '<span class="dim">' + esc(l) + '</span>').join('\n')}`
    if (!h) h = '<span class="dim">no output</span>'
    setOut(h)
    setResult(res)
  }

  const badge = result ? (
    result.success
      ? <span className="result-badge win">✓ SUCCESS — evidence captured</span>
      : (result.error
        ? <span className="result-badge lose">✗ basarisiz</span>
        : <span className="result-badge mid">○ ran — target defended / trigger not fired</span>)
  ) : null

  return (
    <div className="poc">
      <div className="poc-head">
        <span style={{ fontSize: 16 }}>⚔</span>
        <span className="pname">{spec.name || ''}</span>
        <span className="badge b-type">{spec.type || ''}</span>
        {spec.preauth && <span className="badge b-pre">PRE-AUTH</span>}
      </div>
      {spec.note && <div className="poc-note">⚠ {spec.note}</div>}
      {spec.inputs && spec.inputs.length > 0 && (
        <div className="poc-grid">
          {spec.inputs.map(inp => (
            <div key={inp.key}>
              <label className="f">{inp.label}{inp.req ? ' *' : ''}</label>
              <input
                className="mono"
                placeholder={inp.placeholder || ''}
                value={params[inp.key] || inp.default || ''}
                spellCheck="false"
                onChange={e => setParams(p => ({ ...p, [inp.key]: e.target.value }))}
              />
            </div>
          ))}
        </div>
      )}
      <button className="btn danger" disabled={running} onClick={run}>
        {running ? <span className="spin" /> : '▶'} Run (native engine)
      </button>
      {show && <div className="outbox show" dangerouslySetInnerHTML={{ __html: out }} />}
      {badge}
    </div>
  )
}

function esc(s) {
  const d = document.createElement('div')
  d.textContent = s == null ? '' : String(s)
  return d.innerHTML
}