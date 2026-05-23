
import { useState, useCallback } from 'react'
import { useApi } from '../hooks/useApi'

interface Status {
  node_id: string
  watch_file: string
  coordinator_ip: string
  ids_mode: string
  eve_json_path: string
  uptime_sec: number
  zmq_connected: boolean
  alerts_fired: number
  zmq_sent: number
}

function formatUptime(sec: number) {
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = sec % 60
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
}

function Row({
  label,
  value,
  accent,
  mono = true,
}: {
  label: string
  value: string
  accent?: string
  mono?: boolean
}) {
  return (
    <div className="flex items-start gap-4 py-3 border-b border-border last:border-0">
      <div className="font-mono text-xs text-dim tracking-wider w-44 shrink-0 pt-0.5">
        {label}
      </div>
      <div className={`${mono ? 'font-mono' : ''} text-xs ${accent ?? 'text-text'} break-all`}>
        {value}
      </div>
    </div>
  )
}

// ── IDS Mode Toggle ────────────────────────────────────────────────────────────
function IDSModePanel({ status, onSwitch }: {
  status: Status | null
  onSwitch: (mode: string) => Promise<void>
}) {
  const [switching, setSwitching]     = useState(false)
  const [switchError, setSwitchError] = useState<string | null>(null)
  const [switchOk, setSwitchOk]       = useState<string | null>(null)

  const isBuiltin  = !status?.ids_mode || status.ids_mode.startsWith('builtin')
  const isSuricata = status?.ids_mode?.startsWith('suricata') && !status.ids_mode.includes('fallback')
  const isFallback = status?.ids_mode?.includes('fallback')

  const handleSwitch = async (mode: string) => {
    if (switching) return
    const current = isBuiltin ? 'builtin' : 'suricata'
    if (mode === current && !isFallback) return

    setSwitching(true)
    setSwitchError(null)
    setSwitchOk(null)
    try {
      await onSwitch(mode)
      setSwitchOk(`Switched to ${mode} mode`)
      setTimeout(() => setSwitchOk(null), 3000)
    } catch (e: any) {
      setSwitchError(e.message ?? 'Switch failed')
      setTimeout(() => setSwitchError(null), 5000)
    } finally {
      setSwitching(false)
    }
  }

  return (
    <div className="bg-panel border border-border rounded p-5 mb-6">
      {/* Header */}
      <div className="mb-5">
        <div className="font-mono text-xs text-dim tracking-wider mb-1">IDS ENGINE</div>
        <div className="font-mono text-sm font-bold text-bright">DETECTION MODE</div>
        <div className="font-mono text-[10px] text-dim mt-1">
          Click a mode card to switch. Change takes effect immediately — no restart needed.
        </div>
      </div>

      {/* Mode cards */}
      <div className="grid grid-cols-2 gap-3 mb-4">
        {/* Built-in */}
        <button
          disabled={switching}
          onClick={() => handleSwitch('builtin')}
          className={`rounded border p-4 text-left transition-all cursor-pointer
            ${isBuiltin && !isFallback
              ? 'border-cyan/50 bg-cyan/5 ring-1 ring-cyan/20'
              : 'border-border bg-void/40 hover:border-cyan/30 hover:bg-cyan/5'
            }
            ${switching ? 'opacity-50 cursor-not-allowed' : ''}
          `}
        >
          <div className="flex items-center gap-2 mb-2">
            <div className={`w-2 h-2 rounded-full transition-all ${
              isBuiltin && !isFallback ? 'bg-cyan animate-pulse' : 'bg-dim'
            }`} />
            <span className="font-mono text-xs font-semibold text-bright tracking-wider">
              BUILT-IN
            </span>
            {isBuiltin && !isFallback && (
              <span className="font-mono text-[10px] text-cyan ml-auto">● ACTIVE</span>
            )}
            {isFallback && (
              <span className="font-mono text-[10px] text-yellow ml-auto">● FALLBACK</span>
            )}
          </div>
          <p className="font-mono text-[10px] text-dim leading-relaxed">
            Rule engine watching syslog / auth.log. Works out-of-the-box.
            Rules: SSH brute force, port scan, priv-esc, multi-service auth.
          </p>
          <div className="mt-3 font-mono text-[10px] text-dim">
            <span className="text-text">Watch: </span>
            <span className="text-cyan">{status?.watch_file ?? '—'}</span>
          </div>
          {(!isBuiltin || isFallback) && !switching && (
            <div className="mt-3 font-mono text-[10px] text-cyan/60 border border-cyan/20 rounded px-2 py-1 inline-block">
              CLICK TO ACTIVATE
            </div>
          )}
        </button>

        {/* Suricata */}
        <button
          disabled={switching}
          onClick={() => handleSwitch('suricata')}
          className={`rounded border p-4 text-left transition-all cursor-pointer
            ${isSuricata
              ? 'border-purple/50 bg-purple/5 ring-1 ring-purple/20'
              : 'border-border bg-void/40 hover:border-purple/30 hover:bg-purple/5'
            }
            ${switching ? 'opacity-50 cursor-not-allowed' : ''}
          `}
        >
          <div className="flex items-center gap-2 mb-2">
            <div className={`w-2 h-2 rounded-full transition-all ${
              isSuricata ? 'bg-purple animate-pulse' : 'bg-dim'
            }`} />
            <span className="font-mono text-xs font-semibold text-bright tracking-wider">
              SURICATA
            </span>
            {isSuricata && (
              <span className="font-mono text-[10px] text-purple ml-auto">● ACTIVE</span>
            )}
          </div>
          <p className="font-mono text-[10px] text-dim leading-relaxed">
            Tails Suricata's eve.json. Requires Suricata installed and running
            with suricata-update rules loaded.
          </p>
          <div className="mt-3 font-mono text-[10px] text-dim">
            <span className="text-text">Eve.json: </span>
            <span className="text-purple">{status?.eve_json_path ?? '/var/log/suricata/eve.json'}</span>
          </div>
          {!isSuricata && !switching && (
            <div className="mt-3 font-mono text-[10px] text-purple/60 border border-purple/20 rounded px-2 py-1 inline-block">
              CLICK TO ACTIVATE
            </div>
          )}
        </button>
      </div>

      {/* Switching spinner */}
      {switching && (
        <div className="rounded border border-border bg-void/60 px-4 py-3 mb-3 flex items-center gap-3">
          <div className="w-3 h-3 rounded-full border border-cyan border-t-transparent animate-spin" />
          <span className="font-mono text-xs text-dim">Switching IDS engine…</span>
        </div>
      )}

      {/* Success */}
      {switchOk && (
        <div className="rounded border border-green/30 bg-green/5 px-4 py-3 mb-3">
          <span className="font-mono text-xs text-green">✓ {switchOk}</span>
        </div>
      )}

      {/* Error */}
      {switchError && (
        <div className="rounded border border-red/30 bg-red/5 px-4 py-3 mb-3">
          <div className="font-mono text-xs text-red font-semibold mb-1">✗ Switch failed</div>
          <div className="font-mono text-[10px] text-dim">{switchError}</div>
          {switchError.includes('eve.json') && (
            <div className="font-mono text-[10px] text-dim mt-2">
              Make sure Suricata is running:
              <br />
              <span className="text-text">sudo systemctl start suricata && sudo suricata-update</span>
            </div>
          )}
        </div>
      )}

      {/* Fallback warning */}
      {isFallback && (
        <div className="rounded border border-yellow/30 bg-yellow/5 px-4 py-3">
          <div className="font-mono text-xs text-yellow font-semibold mb-1">
            ⚠ SURICATA FALLBACK ACTIVE
          </div>
          <div className="font-mono text-[10px] text-dim">
            Agent could not find <span className="text-text">{status?.eve_json_path}</span>.
            Running built-in rule engine instead. Start Suricata then click the
            Suricata card above to retry.
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────
export default function NodeInfo() {
  const { data, error } = useApi<Status>('http://localhost:8081/status', 3000)

  const handleModeSwitch = useCallback(async (mode: string) => {
    const res = await fetch('http://localhost:8081/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids_mode: mode }),
    })
    const json = await res.json()
    if (!json.ok) throw new Error(json.error ?? `HTTP ${res.status}`)
  }, [])

  return (
    <div className="p-6 overflow-y-auto h-full">
      <div className="mb-6">
        <h1 className="font-mono text-bright text-lg font-semibold tracking-wider">
          NODE INFO
        </h1>
        <p className="text-dim text-xs font-mono mt-0.5">
          agent identity, connection status, and IDS configuration
        </p>
      </div>

      {error && (
        <div className="font-mono text-xs text-red mb-4 bg-red/10 border border-red/20 rounded p-3">
          ✗ Cannot reach agent at localhost:8081 — is the agent running?
        </div>
      )}

      {/* Connection status card */}
      <div className="bg-panel border border-border rounded p-5 mb-6">
        <div className="flex items-center gap-4 mb-5">
          <div
            className={`w-3 h-3 rounded-full ${
              data?.zmq_connected ? 'bg-green animate-pulse-slow' : 'bg-red'
            }`}
          />
          <div>
            <div className="font-mono text-xs text-dim tracking-wider">AGENT STATUS</div>
            <div
              className={`font-mono text-sm font-bold mt-0.5 ${
                data?.zmq_connected ? 'text-green' : 'text-red'
              }`}
            >
              {error
                ? 'OFFLINE'
                : data?.zmq_connected
                ? 'ONLINE — ZMQ CONNECTED'
                : 'ONLINE — ZMQ DISCONNECTED'}
            </div>
          </div>
        </div>

        <Row label="NODE ID"      value={data?.node_id ?? '—'}       accent="text-cyan" />
        <Row label="IDS MODE"     value={(data?.ids_mode ?? '—').toUpperCase()} accent="text-purple" />
        <Row label="WATCHING"     value={data?.watch_file ?? '—'} />
        <Row label="COORDINATOR"  value={data?.coordinator_ip ? `${data.coordinator_ip}:5555` : '—'} />
        <Row label="UPTIME"       value={data ? formatUptime(data.uptime_sec) : '—'} accent="text-cyan" />
        <Row label="ALERTS FIRED" value={data ? String(data.alerts_fired) : '—'} accent="text-red" />
        <Row label="ZMQ SENT"     value={data ? String(data.zmq_sent) : '—'} />
      </div>

      {/* IDS Mode toggle panel */}
      <IDSModePanel status={data ?? null} onSwitch={handleModeSwitch} />

      {/* Ports reference */}
      <div className="bg-panel border border-border rounded p-5">
        <div className="font-mono text-xs text-dim tracking-wider mb-4">PORT REFERENCE</div>
        {[
          { port: '5555', label: 'ZMQ PUB → coordinator alerts' },
          { port: '5556', label: 'ZMQ PUSH → coordinator heartbeat' },
          { port: '8080', label: 'HTTP REST API — coordinator (threats, alerts, nodes)' },
          { port: '8081', label: 'HTTP REST API — agent status + config (this page)' },
        ].map(({ port, label }) => (
          <div
            key={port}
            className="flex items-center gap-4 py-2 border-b border-border last:border-0"
          >
            <span className="font-mono text-xs text-cyan w-12">{port}</span>
            <span className="font-mono text-xs text-dim">{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}