const TABS = [
  { id: 'scan', label: 'Scanma' },
  { id: 'profilees', label: 'profileler', countKey: 'profilees' },
  { id: 'db', label: 'CVE DB', countKey: 'cves' },
  { id: 'log', label: 'Log', countKey: 'logs' },
  { id: 'mcp', label: 'MCP / API' },
]

export default function Tabs({ view, setView, counts }) {
  return (
    <div className="tabs">
      {TABS.map(t => (
        <div
          key={t.id}
          className={'tab' + (view === t.id ? ' active' : '')}
          onClick={() => setView(t.id)}
        >
          {t.label}
          {t.countKey != null && <span className="n">{counts[t.countKey] || 0}</span>}
        </div>
      ))}
    </div>
  )
}