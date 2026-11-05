import { useState, useMemo } from 'react'
import CveCard from './CveCard.jsx'

export default function DbView({ db, pocs }) {
  const [sw, setSw] = useState('')
  const [ver, setVer] = useState('')
  const [q, setQ] = useState('')

  const sws = useMemo(() => [...new Set(db.map(c => c.software))].sort(), [db])
  const versions = useMemo(() => {
    const set = new Set()
    db.forEach(c => { if (!sw || c.software === sw) (c.affected || []).forEach(v => set.add(v)) })
    return [...set].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
  }, [db, sw])

  const out = db.filter(c => {
    if (sw && c.software !== sw) return false
    if (ver && !(c.affected || []).includes(ver)) return false
    if (q && !(c.id || '').toLowerCase().includes(q) && !(c.desc || '').toLowerCase().includes(q)) return false
    return true
  }).sort((a, b) => b.score - a.score)

  return (
    <>
      <div className="panel">
        <h3>CVE Veritabanı <span className="tag">{out.length} CVE</span></h3>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <select style={{ maxWidth: 220 }} value={sw} onChange={e => { setSw(e.target.value); setVer('') }}>
            <option value="">Tüm yazılımlar</option>
            {sws.map(s => <option key={s}>{s}</option>)}
          </select>
          <select style={{ maxWidth: 180 }} value={ver} onChange={e => setVer(e.target.value)}>
            <option value="">Tüm sürümler</option>
            {versions.map(v => <option key={v}>{v}</option>)}
          </select>
          <input style={{ flex: 1, minWidth: 160, maxWidth: 340 }} placeholder="CVE / açıklama ara…"
            value={q} onChange={e => setQ(e.target.value.toLowerCase())} />
        </div>
      </div>
      {out.length === 0 ? <div className="sec-empty">Sonuç yok</div> : (
        <>
          {out.slice(0, 300).map(c => <CveCard key={c.id} cve={c} pocs={pocs} hitMajor={ver || null} />)}
          {out.length > 300 && <div className="empty">+ {out.length - 300} daha (filtre daralt)</div>}
        </>
      )}
    </>
  )
}
