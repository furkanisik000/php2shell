import { useState, useEffect, useRef } from 'react'
import { api } from '../api.js'

export default function LogView() {
  const [logs, setLogs] = useState([])
  const [count, setCount] = useState(0)
  const [level, setLevel] = useState('')
  const [cat, setCat] = useState('')
  const [q, setQ] = useState('')
  const [qLive, setQLive] = useState('')
  const [live, setLive] = useState(false)
  const [loading, setLoading] = useState(false)
  const timer = useRef(null)

  const load = (silent) => {
    if (!silent) setLoading(true)
    api.logs({ level, category: cat, q: qLive, limit: 300 })
      .then(r => { setLogs(r.logs || []); setCount(r.count) })
      .catch(() => {})
      .finally(() => { if (!silent) setLoading(false) })
  }

  useEffect(() => { load(true); /* eslint-disable-next-line */ }, [level, cat, qLive])

  useEffect(() => {
    if (live) timer.current = setInterval(() => load(true), 3000)
    return () => { if (timer.current) clearInterval(timer.current) }
  }, [live, level, cat, qLive])

  function clear() {
    if (!confirm('Tum loglari temizle?')) return
    api.clearLogs().then(() => load(true))
  }

  return (
    <div className="panel">
      <h3>Operasyon Logu <span className="tag">{loading ? 'yukleniyor…' : count}</span></h3>
      <div className="log-toolbar">
        <select value={level} onChange={e => setLevel(e.target.value)}>
          <option value="">Tum seviyeler</option>
          <option>INFO</option><option>SUCCESS</option><option>WARN</option><option>ERROR</option><option>DEBUG</option>
        </select>
        <select value={cat} onChange={e => setCat(e.target.value)}>
          <option value="">Tum kategoriler</option>
          <option>scan</option><option>poc</option><option>profile</option><option>store</option><option>system</option>
        </select>
        <input placeholder="log metni ara…" value={q}
          onChange={e => { setQ(e.target.value); const t = e.target.value; clearTimeout(load._d); load._d = setTimeout(() => setQLive(t), 300) }} />
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text2)', cursor: 'pointer' }}>
          <input type="checkbox" style={{ width: 'auto' }} checked={live} onChange={e => setLive(e.target.checked)} /> canli
        </label>
        <button className="btn sm" onClick={() => load()}>⟳ Yenile</button>
        <button className="btn sm danger" onClick={clear}>🗑 Temizle</button>
      </div>
      <div className="log-console">
        {logs.length === 0 ? <div className="log-line"><span className="msg" style={{ color: 'var(--text3)' }}>log yok</span></div> :
          logs.map(l => (
            <div className="log-line" key={l.id}>
              <span className="ts">{(l.ts || '').replace('T', ' ').replace('Z', '')}</span>
              <span className={'lvl ' + l.level}>{l.level}</span>
              <span className="cat">{l.category || '-'}</span>
              <span className="msg">{l.message || ''}</span>
              {l.data && <span className="data">{JSON.stringify(l.data)}</span>}
            </div>
          ))}
      </div>
      <p style={{ color: 'var(--text3)', fontSize: 11, marginTop: 8 }}>
        Loglar SQLite <code>logs</code> tablosuna + <code>db/logs.log</code> dosyasina yazilir. Her tarama, PoC calismasi ve hata kaydedilir.
      </p>
    </div>
  )
}
