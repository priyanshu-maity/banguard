import type { ReactNode, SyntheticEvent } from 'react'
import type { Evidence, Indicator } from './api'

type Sev = 'high' | 'medium' | 'low'
type Mark = { needle: string; title: string; reason: string; sev: Sev; kind: 'phrase' | 'indicator' }

const MOD: Record<string, string> = { M1: 'URL analysis', M2: 'Certificate', M3: 'Message analysis', M4: 'Correlation', M5: 'Site security' }
const mod = (s: string) => s.split(',').map(x => MOD[x.trim()] ?? x.trim()).join(', ')

const rank = { high: 3, medium: 2, low: 1 }
const LABEL: Record<Sev, string> = { high: 'strong', medium: 'moderate', low: 'mild' }

// Evidence entries look like:  [high] Request for credentials or sensitive data: ["share OTP"]
// (source_module M3, reference "message"). The [severity] prefix is written by _build_evidence in the backend.
function phraseMarks(evidence: Evidence[]): Mark[] {
  const out: Mark[] = []
  evidence.filter(e => e.source_module === 'M3' && e.reference === 'message').forEach(e => {
    const m = e.description.match(/^\[(critical|high|medium|low|info)\]\s+([^:]+):\s*(.*)$/s)
    if (!m) return
    const level = m[1], title = m[2]
    const sev: Sev = level === 'high' || level === 'critical' ? 'high' : level === 'medium' ? 'medium' : 'low'
    let detail: unknown
    try { detail = JSON.parse(m[3]) } catch { return }
    const needles = (Array.isArray(detail) ? detail : [detail]).filter((x): x is string => typeof x === 'string' && x.trim().length > 0)
    needles.forEach(needle => out.push({
      needle: needle.trim(), title, sev, kind: 'phrase',
      reason: `Marked as a ${LABEL[sev]} signal by message analysis. Wording alone is not proof of fraud.`,
    }))
  })
  return out
}

// Tooltips are position:fixed so the scrollable message box cannot clip them.
const place = (e: SyntheticEvent<HTMLElement>) => {
  const el = e.currentTarget
  const tip = el.querySelector<HTMLElement>('.tip')
  if (!tip) return
  const r = el.getBoundingClientRect(), h = tip.offsetHeight, w = tip.offsetWidth
  tip.style.left = Math.max(8, Math.min(r.left, innerWidth - w - 8)) + 'px'
  tip.style.top = (r.bottom + 8 + h > innerHeight ? Math.max(8, r.top - h - 8) : r.bottom + 8) + 'px'
}

export default function Highlighter({ text, evidence, indicators }: { text: string; evidence: Evidence[]; indicators: Indicator[] }) {
  const marks: Mark[] = phraseMarks(evidence)

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