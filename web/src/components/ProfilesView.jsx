import { useEffect } from 'react'
import { api } from '../api.js'

export default function ProfilesView({ profiles, onOpen, onChanged }) {
  async function rescan(id) {
    try {
      await api.rescan(id, {})
      onChanged()
      onOpen(id)
    } catch (e) { alert('Rescan hatası: ' + e.message) }
  }
  async function del(id) {
    if (!confirm('Bu profili ve tüm tarama/PoC kayıtlarını sil?')) return
    await api.deleteProfile(id)
    onChanged()
  }

  if (!profiles.length) {
    return (
      <div className="empty">
        <div className="big">📁</div>
        Henüz profil yok. "Tarama" sekmesinden hedef tara → profil SQLite'a kaydedilir.
      </div>
    )
  }

  return (
    <>
      <div className="sec-head" style={{ marginTop: 0 }}>Kayıtlı Hedef Profilleri <span className="n">{profiles.length}</span></div>
      <div className="profiles-grid">
        {profiles.map(p => {
          const r = p.risk || {}
          const score = r.score || 0
          const C = 2 * Math.PI * 26
          const col = score >= 85 ? 'var(--red)' : score >= 65 ? 'var(--orange)' : score >= 45 ? 'var(--amber)' : score >= 25 ? 'var(--green)' : 'var(--text3)'
          return (
            <div className="profile-card" key={p.id}>
              <div className="ph">
                <div style={{ minWidth: 0 }}>
                  <div className="pname">{p.name}</div>
                  <div className="purl">{p.url}</div>
                </div>
                <div className="mini-gauge">
                  <svg width="64" height="64" viewBox="0 0 64 64">
                    <circle cx="32" cy="32" r="26" fill="none" stroke="var(--bg4)" strokeWidth="7" />
                    <circle cx="32" cy="32" r="26" fill="none" stroke={col} strokeWidth="7" strokeLinecap="round"
                      transform="rotate(-90 32 32)" strokeDasharray={C} strokeDashoffset={C - (score / 100) * C} />
                  </svg>
                  <div className="mn" style={{ color: col }}>{Math.round(score)}</div>
                </div>
              </div>
              <div className="pfacts">
                <span className="pfact">{r.letter || '—'} {r.grade || ''}</span>
                <span className="pfact">{p.n_cve || 0} CVE</span>
                <span className="pfact">{(p.open_ports || []).length} port</span>
                <span className="pfact">{p.scans || 0} tarama</span>
                <span className="pfact">{p.poc_runs || 0} PoC</span>
              </div>
              <div className="pactions">
                <button className="btn sm primary" onClick={() => onOpen(p.id)}>Aç</button>
                <button className="btn sm" onClick={() => rescan(p.id)}>↻ Tara</button>
                <a className="btn sm" href={api.reportUrl(p.id, 'md')} download>⬇ Rapor</a>
                <button className="btn sm danger" onClick={() => del(p.id)}>Sil</button>
              </div>
            </div>
          )
        })}
      </div>
    </>
  )
}
