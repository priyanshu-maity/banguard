import { Component } from 'react'
import type { ReactNode, SyntheticEvent } from 'react'
import type { Evidence, Indicator } from './api'

type Sev = 'high' | 'medium' | 'low'
type Mark = { needle: string; title: string; reason: string; sev: Sev; kind: 'phrase' | 'indicator' }
type Hit = { s: number; e: number; m: Mark }
type Props = { text: string; evidence?: Evidence[]; indicators?: Indicator[] }

const MOD: Record<string, string> = { M1: 'URL analysis', M2: 'Certificate', M3: 'Message analysis', M4: 'Correlation', M5: 'Site security' }
const mod = (s: string) => s.split(',').map(x => MOD[x.trim()] ?? x.trim()).join(', ')

const rank = { high: 3, medium: 2, low: 1 }
const LABEL: Record<Sev, string> = { high: 'strong', medium: 'moderate', low: 'mild' }
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

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

// Indicators come back normalised (scheme added, spacing changed), so match them loosely.
function patternFor(m: Mark): string {
  const v = m.needle
  if (m.kind === 'indicator') {
    if (/^\+?[\d\s().-]{7,}$/.test(v)) {
      const digits = v.replace(/\D/g, '')
      if (digits.length >= 7) return (v.startsWith('+') ? '\\+?' : '') + digits.split('').join('[\\s().-]*')
    }
    if (!v.includes('@') && v.includes('.')) {
      const core = v.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/^www\./i, '').split(/[?#]/)[0].replace(/\/+$/, '')
      if (core) return '(?:https?:\\/\\/)?(?:www\\.)?' + esc(core)
    }
  }
  return esc(v).replace(/\s+/g, '\\s+')
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

function HighlighterInner({ text, evidence, indicators }: Props) {
  const phrases = phraseMarks(Array.isArray(evidence) ? evidence : [])
  const inds: Mark[] = (Array.isArray(indicators) ? indicators : [])
    .filter(x => typeof x?.value === 'string' && x.value.trim())
    .map(x => ({
      needle: x.value.trim(),
      title: 'Extracted ' + x.indicator_type.replace(/_/g, ' '),
      reason: 'Pulled out of the message and checked by ' + mod(x.source_module) + '.',
      sev: 'low' as Sev,
      kind: 'indicator' as const,
    }))

  const locate = (marks: Mark[]) => {
    const hits: Hit[] = [], missed: Mark[] = []
    marks.forEach(m => {
      let re: RegExp
      try { re = new RegExp(patternFor(m), 'gi') } catch { return }
      let found = false
      for (const x of text.matchAll(re)) {
        if (!x[0]) continue
        hits.push({ s: x.index!, e: x.index! + x[0].length, m })
        found = true
      }
      if (!found) missed.push(m)
    })
    return { hits, missed }
  }

  // Strongest, then longest wins when marks of the same kind overlap.
  const resolve = (hits: Hit[], score: (h: Hit) => number) => {
    const keep: Hit[] = []
    ;[...hits].sort((a, b) => score(b) - score(a) || (b.e - b.s) - (a.e - a.s))
      .forEach(c => { if (!keep.some(k => c.s < k.e && c.e > k.s)) keep.push(c) })
    return keep.sort((a, b) => a.s - b.s)
  }

  const P = locate(phrases), I = locate(inds)
  const keepP = resolve(P.hits, h => rank[h.m.sev])
  const keepI = resolve(I.hits, () => 0)

  // Phrases and links are resolved separately, then layered: a link inside a flagged phrase keeps its underline.
  const cuts = [...new Set([0, text.length, ...keepP.flatMap(h => [h.s, h.e]), ...keepI.flatMap(h => [h.s, h.e])])].sort((a, b) => a - b)
  const parts: ReactNode[] = []
  for (let n = 0; n < cuts.length - 1; n++) {
    const a = cuts[n], b = cuts[n + 1], slice = text.slice(a, b)
    const p = keepP.find(h => h.s <= a && h.e >= b)
    const i = keepI.find(h => h.s <= a && h.e >= b)
    if (!p && !i) { parts.push(slice); continue }
    parts.push(
      <mark key={a} tabIndex={0} onMouseEnter={place} onFocus={place} className={'hl ' + (p ? 'h-' + p.m.sev : 'h-ind') + (p && i ? ' u-ind' : '')}>
        {slice}
        <span role="tooltip" className="tip">
          {p && <><b>{p.m.title}</b>{p.m.reason}</>}
          {i && <><b>{i.m.title}</b>{i.m.reason}</>}
        </span>
      </mark>
    )
  }

  const count = (sev: Sev) => keepP.filter(h => h.m.sev === sev).length
  const marked = keepP.length + keepI.length

  return (
    <>
      <div className="legend">
        <span className="lg h-high">strong signal · {count('high')}</span>
        <span className="lg h-medium">moderate · {count('medium')}</span>
        <span className="lg h-low">mild · {count('low')}</span>
        <span className="lg h-ind">link, number or address · {keepI.length}</span>
      </div>
      <p className="msg">{parts}</p>
      <p className="dim sm">Hover or tab to a highlight to see why it was marked. Suspicious wording is a signal, not proof of fraud.</p>
      {marked === 0 && <p className="dim sm">Nothing in the text was marked. That does not mean the message is safe.</p>}
      {P.missed.length > 0 && <p className="dim sm">Flagged by the analyser but not found word for word in your text: {P.missed.map(m => `“${m.needle}”`).join(', ')}.</p>}
    </>
  )
}

// A problem while marking up the text must never blank the whole report: fall back to the plain message.
class Boundary extends Component<{ text: string; children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  componentDidCatch(error: unknown) { console.error('Message highlighter failed', error) }
  render() {
    if (!this.state.failed) return this.props.children
    return (
      <>
        <p className="msg">{this.props.text}</p>
        <p className="dim sm">The highlights could not be shown for this message.</p>
      </>
    )
  }
}

export default function Highlighter(props: Props) {
  return <Boundary text={props.text}><HighlighterInner {...props} /></Boundary>
}