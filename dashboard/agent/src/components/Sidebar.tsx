import { NavLink } from 'react-router-dom'

const nav = [
  { to: '/',        label: 'Live Feed',  icon: '⬡' },
  { to: '/alerts',  label: 'Alerts',     icon: '◈' },
  { to: '/stats',   label: 'Stats',      icon: '◎' },
  { to: '/node',    label: 'Node Info',  icon: '◇' },
]

interface Props { nodeId: string; online: boolean }

export default function Sidebar({ nodeId, online }: Props) {
  return (
    <aside className="w-52 shrink-0 bg-surface border-r border-border flex flex-col h-screen sticky top-0">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-border">
        <div className="font-mono text-xs text-dim mb-1 tracking-widest uppercase">DLADS</div>
        <div className="font-mono text-cyan text-sm font-bold tracking-wider">AGENT NODE</div>
      </div>

      {/* Node ID */}
      <div className="px-5 py-4 border-b border-border">
        <div className="text-xs text-dim font-mono mb-1">NODE ID</div>
        <div className="font-mono text-xs text-bright truncate">{nodeId || '—'}</div>
        <div className="flex items-center gap-1.5 mt-2">
          <span className={`w-1.5 h-1.5 rounded-full ${online ? 'bg-green animate-pulse-slow' : 'bg-red'}`} />
          <span className="text-xs font-mono text-dim">{online ? 'ONLINE' : 'OFFLINE'}</span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4">
        {nav.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-5 py-3 font-mono text-xs transition-all duration-150 border-l-2 ${
                isActive
                  ? 'text-cyan border-cyan bg-cyan/5'
                  : 'text-dim border-transparent hover:text-text hover:border-muted hover:bg-muted/30'
              }`
            }
          >
            <span className="text-base leading-none">{icon}</span>
            <span className="tracking-wider uppercase">{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-border">
        <div className="font-mono text-xs text-dim">v0.1.0 · DLADS</div>
      </div>
    </aside>
  )
}