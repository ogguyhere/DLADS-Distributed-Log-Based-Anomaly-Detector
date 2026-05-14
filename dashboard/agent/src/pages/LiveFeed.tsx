import { useState, useEffect, useRef } from 'react'
import SevBadge from '../components/SevBadge'

interface FeedEntry {
  timestamp: string
  raw_line: string
  stage: string
  detail: string
  severity: string
}

const stageStyle: Record<string, string> = {
  alert:      'border-l-2 border-red bg-red/5',
  parse_fail: 'border-l-2 border-orange/40 bg-orange/5',
  parsed:     'border-l-2 border-border',
}

const stageDot: Record<string, string> = {
  alert:      'bg-red',
  parse_fail: 'bg-orange',
  parsed:     'bg-dim',
}

export default function LiveFeed() {
  // Accumulated entries — never replaced, only prepended
  const [entries, setEntries] = useState<FeedEntry[]>([])
  const [filter, setFilter] = useState('')
  const [stageFilter, setStageFilter] = useState('all')
  const [paused, setPaused] = useState(false)
  const [error, setError] = useState(false)
  const seenRef = useRef<Set<string>>(new Set())

  useEffect(() => {
    const poll = () => {
      fetch('/api/feed')
        .then(r => r.json())
        .then((fresh: FeedEntry[]) => {
          setError(false)
          if (paused) return
          // Deduplicate by timestamp+raw_line key so we never show duplicates
          const newEntries: FeedEntry[] = []
          for (const e of fresh) {
            const key = e.timestamp + '|' + e.raw_line
            if (!seenRef.current.has(key)) {
              seenRef.current.add(key)
              newEntries.push(e)
            }
          }
          if (newEntries.length > 0) {
            setEntries(prev => {
              const combined = [...newEntries, ...prev]
              return combined.slice(0, 500) // keep max 500 in view
            })
          }
        })
        .catch(() => setError(true))
    }

    poll()
    const id = setInterval(poll, 1500)
    return () => clearInterval(id)
  }, [paused])

  const visible = entries
    .filter(e => stageFilter === 'all' || e.stage === stageFilter)
    .filter(e =>
      !filter ||
      e.raw_line.toLowerCase().includes(filter.toLowerCase()) ||
      e.detail.toLowerCase().includes(filter.toLowerCase())
    )

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 py-5 border-b border-border flex items-center justify-between">
        <div>
          <h1 className="font-mono text-bright text-lg font-semibold tracking-wider">LIVE FEED</h1>
          <p className="text-dim text-xs font-mono mt-0.5">
            {entries.length} entries accumulated
            {error && <span className="text-red ml-2">· agent offline</span>}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => { setEntries([]); seenRef.current.clear() }}
            className="font-mono text-xs px-3 py-1.5 rounded border border-border text-dim hover:text-text hover:border-muted transition-all"
          >
            CLEAR
          </button>
          <button
            onClick={() => setPaused(p => !p)}
            className={`font-mono text-xs px-3 py-1.5 rounded border tracking-wider transition-all ${
              paused
                ? 'border-yellow/40 text-yellow bg-yellow/10 hover:bg-yellow/20'
                : 'border-green/40 text-green bg-green/10 hover:bg-green/20'
            }`}
          >
            {paused ? '▶ RESUME' : '⏸ PAUSE'}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="px-6 py-3 border-b border-border flex gap-3 items-center flex-wrap">
        <input
          type="text"
          placeholder="filter by IP, rule, or text..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="flex-1 min-w-48 bg-panel border border-border rounded px-3 py-1.5 font-mono text-xs text-text placeholder-dim focus:outline-none focus:border-cyan/50 transition-colors"
        />
        {(['all', 'alert', 'parsed', 'parse_fail'] as const).map(s => (
          <button
            key={s}
            onClick={() => setStageFilter(s)}
            className={`font-mono text-xs px-3 py-1.5 rounded border tracking-wider transition-all ${
              stageFilter === s
                ? 'border-cyan/50 text-cyan bg-cyan/10'
                : 'border-border text-dim hover:text-text hover:border-muted'
            }`}
          >
            {s.toUpperCase()}
          </button>
        ))}
      </div>

      {/* Feed list */}
      <div className="flex-1 overflow-y-auto px-6 py-3 space-y-1">
        {error && (
          <div className="font-mono text-xs text-red py-3">
            ✗ Cannot reach agent API — is the agent running on :8081?
          </div>
        )}
        {!error && entries.length === 0 && (
          <div className="font-mono text-xs text-dim py-4 flex items-center gap-2">
            <span className="animate-blink text-cyan">_</span>
            <span>waiting for log events — make sure agent is watching the right file</span>
          </div>
        )}
        {visible.map((e, i) => (
          <div
            key={i}
            className={`rounded px-3 py-2.5 ${stageStyle[e.stage] ?? 'border-l-2 border-border'}`}
          >
            <div className="flex items-start gap-3">
              <span className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${stageDot[e.stage] ?? 'bg-dim'}`} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className="font-mono text-[10px] text-dim">{e.timestamp}</span>
                  {e.stage === 'alert' && e.detail && (
                    <span className="font-mono text-[10px] text-red font-semibold">{e.detail}</span>
                  )}
                  {e.stage === 'alert' && e.severity && (
                    <SevBadge sev={e.severity} small />
                  )}
                  {e.stage === 'parse_fail' && (
                    <span className="font-mono text-[10px] text-orange">PARSE FAIL</span>
                  )}
                </div>
                <div className="font-mono text-xs text-text break-all leading-relaxed">
                  {e.raw_line}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}