export default function RiskGauge({ risk }) {
  const score = (risk && risk.score) || 0
  const C = 2 * Math.PI * 64
  const col = score >= 85 ? 'var(--red)' : score >= 65 ? 'var(--orange)' : score >= 45 ? 'var(--amber)' : score >= 25 ? 'var(--green)' : 'var(--text3)'
  const factors = (risk && risk.factors) || []
  return (
    <div className="panel">
      <h3>Risk Assessment <span className="tag">{risk && risk.n_cve != null ? risk.n_cve + ' CVE' : ''}</span></h3>
      <div className="gauge-wrap">
        <div className="gauge">
          <svg width="150" height="150" viewBox="0 0 150 150">
            <circle cx="75" cy="75" r="64" fill="none" stroke="var(--bg4)" strokeWidth="14" />
            <circle
              cx="75" cy="75" r="64" fill="none" stroke={col} strokeWidth="14"
              strokeLinecap="round" transform="rotate(-90 75 75)"
              strokeDasharray={C} strokeDashoffset={C - (score / 100) * C}
            />
          </svg>
          <div className="center">
            <div className="num" style={{ color: col }}>{Math.round(score)}</div>
            <div className="lbl">risk / 100</div>
            <div className="grade" style={{ color: col }}>{(risk && risk.letter) || '—'}</div>
          </div>
        </div>
        <div className="factors">
          {factors.length === 0 && <div className="factor"><span className="fl">No factors</span></div>}
          {factors.map((f, i) => {
            const v = f.delta
            const cls = v > 0 ? 'pos' : v < 0 ? 'neg' : 'zero'
            return (
              <div className="factor" key={i}>
                <span className="fl">{f.label}{f.note ? <span style={{ color: 'var(--text3)' }}> · {f.note}</span> : null}</span>
                <span className={'fv ' + cls}>{v > 0 ? '+' : ''}{v}</span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}