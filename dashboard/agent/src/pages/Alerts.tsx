import { useState } from 'react'
import { useApi } from '../hooks/useApi'
import SevBadge from '../components/SevBadge'

interface Alert {
  alert_id: string
  rule_id: string
  severity: string
  description: string
  src_ip: string
  timestamp_ms: number
}

export default function Alerts() {
  const { data, error } = useApi<Alert[]>('/api/alerts', 2000)
  const [ipFilter, setIpFilter] = useState('')
  const [sevFilter, setSevFilter] = useState('ALL')
  const [ruleFilter, setRuleFilter] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)

  const alerts = (data ?? [])
    .filter(a => sevFilter === 'ALL' || a.severity === sevFilter)
    .filter(a => !ipFilter || a.src_ip.includes(ipFilter))
    .filter(a => !ruleFilter || a.rule_id.toLowerCase().includes(ruleFilter.toLowerCase()))

  const counts = (data ?? []).reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] ?? 0) + 1
    return acc
  }, {} as Record<string, number>)

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 py-5 border-b border-border">
        <h1 className="font-mono text-bright text-lg font-semibold tracking-wider">ALERTS</h1>
        <p className="text-dim text-xs font-mono mt-0.5">all rule-engine detections this session</p>
      </div>

      {/* Counters */}
      <div className="px-6 py-4 border-b border-border grid grid-cols-4 gap-3">
        {[
          { label: 'TOTAL',    val: data?.length ?? 0,       col: 'text-cyan'   },
          { label: 'CRITICAL', val: counts.CRITICAL ?? 0,    col: 'text-red'    },
          { label: 'HIGH',     val: counts.HIGH ?? 0,        col: 'text-orange' },
          { label: 'MEDIUM',   val: counts.MEDIUM ?? 0,      col: 'text-yellow' },
        ].map(({ label, val, col }) => (
          <div key={label} className="bg-panel border border-border rounded p-3">
            <div className="font-mono text-xs text-dim tracking-widest">{label}</div>
            <div className={`font-mono text-2xl font-bold mt-1 ${col}`}>{val}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="px-6 py-3 border-b border-border flex gap-3 flex-wrap items-center">
        <input
          placeholder="filter by IP..."
          value={ipFilter}
          onChange={e => setIpFilter(e.target.value)}
          className="w-36 bg-panel border border-border rounded px-3 py-1.5 font-mono text-xs text-text placeholder-dim focus:outline-none focus:border-cyan/50"
        />
        <input
          placeholder="filter by rule..."
          value={ruleFilter}
          onChange={e => setRuleFilter(e.target.value)}
          className="w-44 bg-panel border border-border rounded px-3 py-1.5 font-mono text-xs text-text placeholder-dim focus:outline-none focus:border-cyan/50"
        />
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
          <button
            key={s}
            onClick={() => setSevFilter(s)}
            className={`font-mono text-xs px-3 py-1.5 rounded border tracking-wider transition-all ${
              sevFilter === s
                ? 'border-cyan/50 text-cyan bg-cyan/10'
                : 'border-border text-dim hover:text-text hover:border-muted'
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        {error && (
          <div className="font-mono text-xs text-red px-6 py-4">
            ✗ Cannot reach agent API
          </div>
        )}
        {!error && alerts.length === 0 && (
          <div className="font-mono text-xs text-dim px-6 py-4">
            no alerts yet — run attack script to generate detections
          </div>
        )}
        {alerts.map(a => (
          <div key={a.alert_id}>
            <button
              onClick={() => setExpanded(expanded === a.alert_id ? null : a.alert_id)}
              className="w-full text-left px-6 py-3 border-b border-border hover:bg-panel/50 transition-colors"
            >
              <div className="flex items-center gap-4">
                <SevBadge sev={a.severity} small />
                <span className="font-mono text-xs text-cyan flex-1 truncate">{a.rule_id}</span>
                <span className="font-mono text-xs text-text truncate max-w-xs hidden md:block">{a.src_ip || '—'}</span>
                <span className="font-mono text-[10px] text-dim ml-auto shrink-0">
                  {new Date(a.timestamp_ms).toLocaleTimeString()}
                </span>
                <span className="text-dim text-xs">{expanded === a.alert_id ? '▲' : '▼'}</span>
              </div>
            </button>
            {expanded === a.alert_id && (
              <div className="px-6 py-4 bg-panel border-b border-border animate-fade-in">
                <div className="grid grid-cols-2 gap-4 font-mono text-xs">
                  <div>
                    <div className="text-dim mb-1">ALERT ID</div>
                    <div className="text-text">{a.alert_id}</div>
                  </div>
                  <div>
                    <div className="text-dim mb-1">SOURCE IP</div>
                    <div className="text-cyan">{a.src_ip || '—'}</div>
                  </div>
                  <div className="col-span-2">
                    <div className="text-dim mb-1">DESCRIPTION</div>
                    <div className="text-text leading-relaxed">{a.description}</div>
                  </div>
                  <div>
                    <div className="text-dim mb-1">TIMESTAMP</div>
                    <div className="text-text">{new Date(a.timestamp_ms).toISOString()}</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}