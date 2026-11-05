import { useState, useEffect, useCallback } from 'react'
import { api } from './api.js'
import TopBar from './components/TopBar.jsx'
import Tabs from './components/Tabs.jsx'
import ScanView from './components/ScanView.jsx'
import profileesView from './components/profileesView.jsx'
import DbView from './components/DbView.jsx'
import LogView from './components/LogView.jsx'
import McpView from './components/McpView.jsx'

export default function App() {
  const [view, setView] = useState('scan')
  const [health, setHealth] = useState(null)
  const [db, setDb] = useState([])
  const [pocs, setPocs] = useState({})
  const [profilees, setprofilees] = useState([])
  const [logCount, setLogCount] = useState(0)
  const [lastLog, setLastLog] = useState(null)
  const [activeprofileeId, setActiveprofileeId] = useState(null)

  const refreshprofilees = useCallback(() =>
    api.profilees().then(p => setprofilees(p.profilees || [])).catch(() => {}), [])
  const refreshLogs = useCallback(() =>
    api.logs({ limit: 1 }).then(l => { setLogCount(l.count); setLastLog(l.logs[0] || null) }).catch(() => {}), [])

  useEffect(() => {
    api.health().then(setHealth).catch(() => {})
    api.cves().then(c => setDb(c.cves || [])).catch(() => {})
    api.pocs().then(p => setPocs(p.pocs || {})).catch(() => {})
    refreshprofilees()
    refreshLogs()
  }, [refreshprofilees, refreshLogs])

  const openprofilee = (id) => { setActiveprofileeId(id); setView('scan') }

  return (
    <>
      <TopBar health={health} lastLog={lastLog} />
      <Tabs view={view} setView={setView} counts={{ profilees: profilees.length, cves: db.length, logs: logCount }} />
      <div className={view === 'scan' ? 'wrap' : ''}>
        {view === 'scan' && (
          <ScanView
            db={db} pocs={pocs}
            activeprofileeId={activeprofileeId}
            onprofileesChanged={refreshprofilees}
            onLogsChanged={refreshLogs}
          />
        )}
        {view === 'profilees' && (
          <div className="full">
            <profileesView profilees={profilees} onOpen={openprofilee} onChanged={refreshprofilees} />
          </div>
        )}
        {view === 'db' && (
          <div className="full">
            <DbView db={db} pocs={pocs} />
          </div>
        )}
        {view === 'log' && (
          <div className="full">
            <LogView />
          </div>
        )}
        {view === 'mcp' && (
          <div className="full">
            <McpView />
          </div>
        )}
      </div>
    </>
  )
}