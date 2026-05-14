interface Props { sev: string; small?: boolean }

const cfg: Record<string, string> = {
  CRITICAL: 'bg-red/20 text-red border-red/40',
  HIGH:     'bg-orange/20 text-orange border-orange/40',
  MEDIUM:   'bg-yellow/20 text-yellow border-yellow/40',
  LOW:      'bg-dim/20 text-dim border-dim/40',
}

export default function SevBadge({ sev, small }: Props) {
  const cls = cfg[sev] ?? cfg.LOW
  return (
    <span className={`border font-mono tracking-wider rounded ${small ? 'text-[10px] px-1.5 py-0.5' : 'text-xs px-2 py-1'} ${cls}`}>
      {sev}
    </span>
  )
}