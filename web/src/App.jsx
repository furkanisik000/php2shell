import { useState, useEffect, useCallback } from 'react'
import { api } from './api.js'
import TopBar from './components/TopBar.jsx'
import Tabs from './components/Tabs.jsx'
import ScanView from './components/ScanView.jsx'
import ProfilesView from './components/ProfilesView.jsx'
import DbView from './components/DbView.jsx'
import LogView from './components/LogView.jsx'
import McpView from './components/McpView.jsx'

export default function App() {
  const [view, setView] = useState('scan')
  const [health, setHealth] = useState(null)
  const [db, setDb] = useState([])
  const [pocs, setPocs] = useState({})
  const [profiles, setProfiles] = useState([])
  const [logCount, setLogCount] = useState(0)
  const [lastLog, setLastLog] = useState(null)
  const [activeProfileId, setActiveProfileId] = useState(null)

  const refreshProfiles = useCallback(() =>
    api.profiles().then(p => setProfiles(p.profiles || [])).catch(() => {}), [])
  const refreshLogs = useCallback(() =>
    api.logs({ limit: 1 }).then(l => { setLogCount(l.count); setLastLog(l.logs[0] || null) }).catch(() => {}), [])

  useEffect(() => {
    api.health().then(setHealth).catch(() => {})
    api.cves().then(c => setDb(c.cves || [])).catch(() => {})
    api.pocs().then(p => setPocs(p.pocs || {})).catch(() => {})
    refreshProfiles()
    refreshLogs()
  }, [refreshProfiles, refreshLogs])

  const openProfile = (id) => { setActiveProfileId(id); setView('scan') }

  return (
    <>
      <TopBar health={health} lastLog={lastLog} />
      <Tabs view={view} setView={setView} counts={{ profiles: profiles.length, cves: db.length, logs: logCount }} />
      <div className={view === 'scan' ? 'wrap' : ''}>
        {view === 'scan' && (
          <ScanView
            db={db} pocs={pocs}
            activeProfileId={activeProfileId}
            onProfilesChanged={refreshProfiles}
            onLogsChanged={refreshLogs}
          />
        )}
        {view === 'profiles' && (
          <div className="full">
            <ProfilesView profiles={profiles} onOpen={openProfile} onChanged={refreshProfiles} />
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
