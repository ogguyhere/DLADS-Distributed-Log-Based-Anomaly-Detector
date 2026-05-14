import { useApi } from '../hooks/useApi'
import { useAlertHistory } from '../hooks/useAlertHistory'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'

interface Stats {
  lines_seen: number
  parsed: number
  parse_fail: number
  alerts_fired: number
  zmq_sent: number
  zmq_dropped: number
  ring_size: number
}

function Gauge({ value, max, label, color }: { value: number; max: number; label: string; color: string }) {
  const pct = Math.min(100, (value / max) * 100)
  return (
    <div className="bg-panel border border-border rounded p-4">
      <div className="flex justify-between items-end mb-2">
        <span className="font-mono text-xs text-dim tracking-wider">{label}</span>
        <span className="font-mono text-sm font-bold" style={{ color }}>{value} / {max}</span>
      </div>
      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <div className="font-mono text-[10px] text-dim mt-1">{pct.toFixed(1)}% full</div>
    </div>
  )
}

function Counter({ label, value, color, sub }: { label: string; value: number; color: string; sub?: string }) {
  return (
    <div className="bg-panel border border-border rounded p-4">
      <div className="font-mono text-xs text-dim tracking-widest mb-2">{label}</div>
      <div className="font-mono text-3xl font-bold" style={{ color }}>{value.toLocaleString()}</div>
      {sub && <div className="font-mono text-[10px] text-dim mt-1">{sub}</div>}
    </div>
  )
}

export default function Stats() {
  const { data, error } = useApi<Stats>('/api/stats', 2000)
  const history = useAlertHistory(data?.alerts_fired ?? 0)

  if (error) return (
    <div className="p-6 font-mono text-xs text-red">✗ Cannot reach agent API</div>
  )

  const s = data ?? {
    lines_seen: 0, parsed: 0, parse_fail: 0,
    alerts_fired: 0, zmq_sent: 0, zmq_dropped: 0, ring_size: 0
  }

  const parseRate = s.lines_seen > 0
    ? ((s.parsed / s.lines_seen) * 100).toFixed(1)
    : '0.0'

  return (
    <div className="p-6 space-y-6 overflow-y-auto h-full">
      <div>
        <h1 className="font-mono text-bright text-lg font-semibold tracking-wider">STATS</h1>
        <p className="text-dim text-xs font-mono mt-0.5">pipeline performance metrics</p>
      </div>

      {/* Counters row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Counter label="LINES SEEN"    value={s.lines_seen}    color="#00d4ff" sub="total log lines ingested" />
        <Counter label="PARSED OK"     value={s.parsed}        color="#00ff9d" sub={`${parseRate}% success rate`} />
        <Counter label="PARSE FAILS"   value={s.parse_fail}    color={s.parse_fail > 0 ? '#ff8c42' : '#4a5a68'} sub="unrecognised formats" />
        <Counter label="ALERTS FIRED"  value={s.alerts_fired}  color={s.alerts_fired > 0 ? '#ff3b5c' : '#4a5a68'} sub="rule engine hits" />
      </div>

      {/* ZMQ row */}
      <div className="grid grid-cols-2 gap-3">
        <Counter label="ZMQ SENT"    value={s.zmq_sent}    color="#00d4ff" sub="alerts forwarded to coordinator" />
        <Counter label="ZMQ DROPPED" value={s.zmq_dropped} color={s.zmq_dropped > 0 ? '#ff3b5c' : '#4a5a68'} sub="queue overflow drops" />
      </div>

      {/* Ring buffer gauge */}
      <Gauge value={s.ring_size} max={4096} label="RING BUFFER" color="#9b5de5" />

      {/* Alert rate chart */}
      <div className="bg-panel border border-border rounded p-4">
        <div className="font-mono text-xs text-dim tracking-wider mb-4">CUMULATIVE ALERTS OVER TIME</div>
        {history.length < 2 ? (
          <div className="font-mono text-xs text-dim py-6 text-center">
            collecting data... run an attack to generate alerts
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={history}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2730" />
              <XAxis
                dataKey="time"
                tick={{ fill: '#4a5a68', fontSize: 9, fontFamily: 'JetBrains Mono' }}
                tickLine={false}
                axisLine={{ stroke: '#1e2730' }}
                interval="preserveStartEnd"
              />
              <YAxis
                tick={{ fill: '#4a5a68', fontSize: 9, fontFamily: 'JetBrains Mono' }}
                tickLine={false}
                axisLine={{ stroke: '#1e2730' }}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  background: '#0e1318', border: '1px solid #1e2730',
                  borderRadius: 4, fontFamily: 'JetBrains Mono', fontSize: 11, color: '#c8d8e8'
                }}
              />
              <Line
                type="monotone"
                dataKey="count"
                stroke="#ff3b5c"
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 3, fill: '#ff3b5c' }}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}