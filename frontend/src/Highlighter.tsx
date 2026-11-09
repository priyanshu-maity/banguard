import type { ReactNode, SyntheticEvent } from 'react'
import type { Finding, Indicator } from './api'

type Mark = { needle: string; title: string; reason: string; sev: 'high' | 'medium' | 'low'; kind: 'phrase' | 'indicator' }

const MOD: Record<string, string> = { M1: 'URL analysis', M2: 'Certificate', M3: 'Message analysis', M4: 'Correlation', M5: 'Site security' }
const mod = (s: string) => s.split(',').map(x => MOD[x.trim()] ?? x.trim()).join(', ')

const norm = (s: string): Mark['sev'] => {
  const v = s.toLowerCase()
  return v === 'high' || v === 'critical' ? 'high' : v === 'medium' ? 'medium' : 'low'
}
const rank = { high: 3, medium: 2, low: 1 }

// Tooltips are position:fixed so the scrollable message box cannot clip them.
const place = (e: SyntheticEvent<HTMLElement>) => {
  const el = e.currentTarget
  const tip = el.querySelector<HTMLElement>('.tip')
  if (!tip) return
  const r = el.getBoundingClientRect(), h = tip.offsetHeight, w = tip.offsetWidth
  tip.style.left = Math.max(8, Math.min(r.left, innerWidth - w - 8)) + 'px'
  tip.style.top = (r.bottom + 8 + h > innerHeight ? Math.max(8, r.top - h - 8) : r.bottom + 8) + 'px'
}

export default function Highlighter({ text, findings, indicators }: { text: string; findings: Finding[]; indicators: Indicator[] }) {
  const marks: Mark[] = []

  // M3 findings carry their exact snippets after "Evidence:", separated by "; ".
  findings.filter(f => f.source_module === 'M3').forEach(f => {
    const i = f.description.indexOf('Evidence:')
    if (i < 0) return
    const reason = f.description.slice(0, i).trim()
    f.description.slice(i + 9).split('; ').map(s => s.trim()).filter(s => s && !s.startsWith('No exact evidence'))
      .forEach(needle => marks.push({ needle, title: f.title, reason, sev: norm(f.severity), kind: 'phrase' }))
  })

  indicators.forEach(x => marks.push({
    needle: x.value,
    title: 'Extracted ' + x.indicator_type.replace(/_/g, ' '),
    reason: 'Pulled out of the message and checked by ' + mod(x.source_module) + '.',
    sev: 'low',
    kind: 'indicator',
  }))

  const found: { s: number; e: number; m: Mark }[] = []
  const missed: Mark[] = []

  marks.forEach(m => {
    const re = new RegExp(m.needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+'), 'gi')
    let hit = false
    for (const x of text.matchAll(re)) {
      if (!x[0]) continue
      found.push({ s: x.index!, e: x.index! + x[0].length, m })
      hit = true
    }
    if (!hit && m.kind === 'phrase') missed.push(m)
  })

  // When marks overlap, phrases beat indicators, then stronger, then longer.
  const score = (c: (typeof found)[number]) => (c.m.kind === 'phrase' ? 10 : 0) + rank[c.m.sev]
  const keep: typeof found = []
  ;[...found]
    .sort((a, b) => score(b) - score(a) || (b.e - b.s) - (a.e - a.s))
    .forEach(c => { if (!keep.some(k => c.s < k.e && c.e > k.s)) keep.push(c) })
  keep.sort((a, b) => a.s - b.s)

  const parts: ReactNode[] = []
  let pos = 0
  keep.forEach((r, k) => {
    if (r.s > pos) parts.push(text.slice(pos, r.s))
    parts.push(
      <mark key={k} tabIndex={0} onMouseEnter={place} onFocus={place} className={'hl ' + (r.m.kind === 'indicator' ? 'h-ind' : 'h-' + r.m.sev)}>
        {text.slice(r.s, r.e)}
        <span role="tooltip" className="tip"><b>{r.m.title}</b>{r.m.reason}</span>
      </mark>
    )
    pos = r.e
  })
  parts.push(text.slice(pos))

  const count = (f: (m: Mark) => boolean) => keep.filter(k => f(k.m)).length

  return (
    <>
      <div className="legend">
        <span className="lg h-high">strong signal · {count(m => m.kind === 'phrase' && m.sev === 'high')}</span>
        <span className="lg h-medium">moderate · {count(m => m.kind === 'phrase' && m.sev === 'medium')}</span>
        <span className="lg h-low">mild · {count(m => m.kind === 'phrase' && m.sev === 'low')}</span>
        <span className="lg h-ind">link, number or address · {count(m => m.kind === 'indicator')}</span>
      </div>
      <p className="msg">{parts}</p>
      <p className="dim sm">Hover or tab to a highlight to see why it was marked. Suspicious wording is a signal, not proof of fraud.</p>
      {keep.length === 0 && <p className="dim sm">Nothing in the text was marked. That does not mean the message is safe.</p>}
      {missed.length > 0 && <p className="dim sm">Flagged by the analyser but not found word for word in your text: {missed.map(m => `“${m.needle}”`).join(', ')}.</p>}
    </>
  )
}