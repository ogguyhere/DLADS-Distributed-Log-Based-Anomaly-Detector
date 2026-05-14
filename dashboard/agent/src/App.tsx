import { Routes, Route } from 'react-router-dom'
import { useApi } from './hooks/useApi'
import Sidebar from './components/Sidebar'
import LiveFeed from './pages/LiveFeed'
import Alerts from './pages/Alerts'
import Stats from './pages/Stats'
import NodeInfo from './pages/NodeInfo'

interface Status {
  node_id: string
  zmq_connected: boolean
}

export default function App() {
  const { data } = useApi<Status>('/api/status', 5000)

  return (
    <div className="flex h-screen bg-void overflow-hidden">
      <Sidebar
        nodeId={data?.node_id ?? 'connecting...'}
        online={!!data?.zmq_connected}
      />
      <main className="flex-1 overflow-hidden flex flex-col">
        <Routes>
          <Route path="/"       element={<LiveFeed />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/stats"  element={<Stats />} />
          <Route path="/node"   element={<NodeInfo />} />
        </Routes>
      </main>
    </div>
  )
}