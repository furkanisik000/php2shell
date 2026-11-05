export default function TopBar({ health, lastLog }) {
  const online = !!(health && health.ok)
  return (
    <div className="topbar">
      <div className="brand">
        <div className="mark">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L4 5v6c0 5 3.4 8.6 8 11 4.6-2.4 8-6 8-11V5l-8-3z" stroke="#4d9fff" strokeWidth="1.5" strokeLinejoin="round" />
            <circle cx="12" cy="11" r="4" stroke="#39c5e0" strokeWidth="1.5" />
            <path d="M12 7v4l2.5 1.5" stroke="#31c46a" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        </div>
        <div style={{ minWidth: 0 }}>
          <div className="name">P2S · <b>CVE Scanner</b></div>
          <div className="sub">native exploit engine · SQLite session · React</div>
        </div>
      </div>
      <div className="status">
        <span className={'dot' + (online ? ' on' : '')} />
        <span>{online ? `online · v${health.version}` : 'baglaniyor… / server offline (server.py)'}</span>
      </div>
      <div className="spacer" />
      <div className="live-tail">
        {lastLog ? <><b>{lastLog.level}</b> {lastLog.message}</> : '—'}
      </div>
      <div className="pill">
        {health ? `${health.vulns} CVE · ${health.with_poc} PoC · ${health.profilees} profile` : '—'}
      </div>
    </div>
  )
}