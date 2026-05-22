import { useApi } from '../hooks/useApi'

interface Status {
  node_id: string
  watch_file: string
  coordinator_ip: string
  ids_mode: string
  uptime_sec: number
  zmq_connected: boolean
}

function formatUptime(sec: number) {
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = sec % 60
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`
}

function Row({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="flex items-start gap-4 py-3 border-b border-border last:border-0">
      <div className="font-mono text-xs text-dim tracking-wider w-40 shrink-0 pt-0.5">{label}</div>
      <div className={`font-mono text-xs ${accent ?? 'text-text'} break-all`}>{value}</div>
    </div>
  )
}

export default function NodeInfo() {
  const { data, error } = useApi<Status>('/api/status', 3000)

  return (
    <div className="p-6 overflow-y-auto h-full">
      <div className="mb-6">
        <h1 className="font-mono text-bright text-lg font-semibold tracking-wider">NODE INFO</h1>
        <p className="text-dim text-xs font-mono mt-0.5">agent identity and connection status</p>
      </div>

      {error && (
        <div className="font-mono text-xs text-red mb-4 bg-red/10 border border-red/20 rounded p-3">
          ✗ Cannot reach coordinator API at localhost:8080 — is the coordinator running?
        </div>
      )}

      {/* Status card */}
      <div className="bg-panel border border-border rounded p-5 mb-6">
        <div className="flex items-center gap-4 mb-6">
          <div className={`w-3 h-3 rounded-full ${data?.zmq_connected ? 'bg-green animate-pulse-slow' : 'bg-red'}`} />
          <div>
            <div className="font-mono text-xs text-dim tracking-wider">AGENT STATUS</div>
            <div className={`font-mono text-sm font-bold mt-0.5 ${data?.zmq_connected ? 'text-green' : 'text-red'}`}>
              {error ? 'OFFLINE' : data?.zmq_connected ? 'ONLINE — ZMQ CONNECTED' : 'ONLINE — ZMQ DISCONNECTED'}
            </div>
          </div>
        </div>

        <Row label="NODE ID"        value={data?.node_id        ?? '—'} accent="text-cyan" />
        <Row label="IDS MODE"       value={(data?.ids_mode ?? '—').toUpperCase()} accent="text-purple" />
        <Row label="WATCHING"       value={data?.watch_file     ?? '—'} />
        <Row label="COORDINATOR"    value={data?.coordinator_ip ? `${data.coordinator_ip}:5555` : '—'} />
        <Row label="UPTIME"         value={data ? formatUptime(data.uptime_sec) : '—'} accent="text-cyan" />
      </div>

      {/* Ports reference */}
      <div className="bg-panel border border-border rounded p-5">
        <div className="font-mono text-xs text-dim tracking-wider mb-4">PORT REFERENCE</div>
        {[
          { port: '5555', label: 'ZMQ PUB → coordinator alerts' },
          { port: '5556', label: 'ZMQ PUSH → coordinator heartbeat' },
          { port: '8080', label: 'HTTP REST API (this dashboard)' },
        ].map(({ port, label }) => (
          <div key={port} className="flex items-center gap-4 py-2 border-b border-border last:border-0">
            <span className="font-mono text-xs text-cyan w-12">{port}</span>
            <span className="font-mono text-xs text-dim">{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}