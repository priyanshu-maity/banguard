import { useState } from 'react'
import { ThreatReport, Commit, Verify, Risk, riskOf, commitReport, verifyReport } from './api'

const META: Record<Risk, { label: string; pos: number; note: string }> = {
  low: { label: 'Low risk', pos: 8, note: 'No significant indicators in the checks that ran.' },
  suspicious: { label: 'Suspicious', pos: 36, note: 'Something needs a closer look before you trust it.' },
  high: { label: 'High risk', pos: 64, note: 'Multiple strong signals. Do not enter details.' },
  malicious: { label: 'Confirmed malicious', pos: 93, note: 'Backed by authoritative threat intelligence.' },
  inconclusive: { label: 'Inconclusive', pos: -1, note: 'Not enough data to judge either way.' },
}
const MOD: Record<string, string> = { M1: 'URL analysis', M2: 'Certificate', M3: 'Message analysis', M4: 'Correlation', M5: 'Site security' }
const mod = (s: string) => s.split(',').map(x => MOD[x.trim()] ?? x.trim()).join(', ')
const SEV = ['critical', 'high', 'medium', 'low', 'info']
const FEEDS = ['URLhaus', 'PhishTank', 'OpenPhish', 'VirusTotal']
const has = (e: { description: string }, p: string) => e.description.startsWith(p)

function Strip({ risk }: { risk: Risk }) {
  const m = META[risk]
  return (
    <div className="strip" role="img" aria-label={`Verdict: ${m.label}`}>
      <div className={'bar' + (risk === 'inconclusive' ? ' hatch' : '')} />
      {m.pos >= 0 && <div className="tick" style={{ left: m.pos + '%' }}><i /></div>}
      <div className="scale"><span>safe</span><span>suspicious</span><span>high</span><span>malicious</span></div>
    </div>
  )
}

function Chain({ urls }: { urls: string[] }) {
  const host = (u: string) => { try { return new URL(u).hostname } catch { return u } }
  return (
    <ol className="chain">
      {urls.map((u, i) => <li key={i} className={i === urls.length - 1 && host(u) !== host(urls[0]) ? 'drift' : ''}><b>{host(u)}</b></li>)}
    </ol>
  )
}

function Ledger({ r }: { r: ThreatReport }) {
  const [c, setC] = useState<Commit>(), [v, setV] = useState<Verify>(), [busy, setBusy] = useState(false)
  const run = async (f: () => Promise<void>) => { setBusy(true); try { await f() } finally { setBusy(false) } }
  return (
    <section className="block">
      <h3>Share this finding</h3>
      <p className="dim">Only a fingerprint goes on-chain. The address, message and your details stay off it. A record proves the report was not altered, not that it is true.</p>
      {!c && <button disabled={busy} onClick={() => run(async () => setC(await commitReport(r)))}>{busy ? 'Recording…' : 'Record on ledger'}</button>}
      {c && <dl className="hashes"><dt>Fingerprint</dt><dd>{c.hash}</dd><dt>Transaction</dt><dd>{c.tx_hash}</dd><dt>Contract</dt><dd>{c.contract} · block {c.block}</dd></dl>}
      {c && !v && <button className="ghost" disabled={busy} onClick={() => run(async () => setV(await verifyReport(c)))}>{busy ? 'Checking…' : 'Verify independently'}</button>}
      {v && <p className={'seal ' + (v.intact ? 'ok' : 'bad')}>{v.intact ? 'Intact: on-chain and recomputed fingerprints match.' : 'Mismatch: this report changed after it was recorded.'}</p>}
    </section>
  )
}

type Mark = { needle: string; title: string; reason: string; sev: string; kind: 'phrase' | 'indicator' }
const rank = (s: string) => SEV.length - SEV.indexOf(s)

// tooltips are position:fixed so the scrollable message box cannot clip them
const place = (e: React.SyntheticEvent<HTMLElement>) => {
  const el = e.currentTarget, tip = el.querySelector<HTMLElement>('.tip'); if (!tip) return
  const r = el.getBoundingClientRect(), h = tip.offsetHeight, w = tip.offsetWidth
  tip.style.left = Math.max(8, Math.min(r.left, innerWidth - w - 8)) + 'px'
  tip.style.top = (r.bottom + 8 + h > innerHeight ? Math.max(8, r.top - h - 8) : r.bottom + 8) + 'px'
}

function Highlighter({ text, findings, indicators }: { text: string; findings: ThreatReport['findings']; indicators: ThreatReport['indicators'] }) {
  const marks: Mark[] = []
  findings.filter(f => f.source_module === 'M3').forEach(f => {
    const i = f.description.indexOf('Evidence:'); if (i < 0) return
    const reason = f.description.slice(0, i).trim()
    f.description.slice(i + 9).split('; ').map(s => s.trim()).filter(s => s && !s.startsWith('No exact evidence'))
      .forEach(needle => marks.push({ needle, title: f.title, reason, sev: f.severity.toLowerCase(), kind: 'phrase' }))
  })
  indicators.forEach(x => marks.push({ needle: x.value, title: 'Extracted ' + x.indicator_type.replace(/_/g, ' '), reason: 'Pulled out of the message and checked by ' + mod(x.source_module) + '.', sev: 'info', kind: 'indicator' }))

  const found: { s: number; e: number; m: Mark }[] = [], missed: Mark[] = []
  marks.forEach(m => {
    const re = new RegExp(m.needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+'), 'gi')
    let hit = false
    for (const x of text.matchAll(re)) { if (!x[0]) continue; found.push({ s: x.index!, e: x.index! + x[0].length, m }); hit = true }
    if (!hit && m.kind === 'phrase') missed.push(m)
  })
  // strongest, then longest, wins when marks overlap
  const keep: typeof found = []
  ;[...found].sort((a, b) => rank(b.m.sev) - rank(a.m.sev) || (b.e - b.s) - (a.e - a.s))
    .forEach(c => { if (!keep.some(k => c.s < k.e && c.e > k.s)) keep.push(c) })
  keep.sort((a, b) => a.s - b.s)

  const parts: React.ReactNode[] = []; let pos = 0
  keep.forEach((r, k) => {
    if (r.s > pos) parts.push(text.slice(pos, r.s))
    parts.push(
      <mark key={k} tabIndex={0} onMouseEnter={place} onFocus={place} className={'hl ' + (r.m.kind === 'indicator' ? 'h-ind' : 'h-' + r.m.sev)}>
        {text.slice(r.s, r.e)}<span role="tooltip" className="tip"><b>{r.m.title}</b>{r.m.reason}</span>
      </mark>)
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

export default function Dossier({ a, message }: { a: ThreatReport; message?: string }) {
  const risk = riskOf(a.risk_level), m = META[risk]
  const sorted = [...a.findings].sort((x, y) => SEV.indexOf(x.severity.toLowerCase()) - SEV.indexOf(y.severity.toLowerCase()))
  const cert = sorted.filter(f => f.source_module === 'M2'), other = sorted.filter(f => f.source_module !== 'M2')
  const redirects = a.evidence.filter(e => has(e, 'Redirect observed:')).map(e => e.reference || e.description.replace('Redirect observed:', '').trim())
  const limits = a.evidence.filter(e => has(e, 'Analysis limitation:'))
  const related = a.evidence.filter(e => has(e, 'Historical correlation:'))
  const log = a.evidence.filter(e => !has(e, 'Redirect observed:') && !has(e, 'Analysis limitation:') && !has(e, 'Historical correlation:'))
  const types = [...new Set(a.indicators.map(i => i.indicator_type))]
  const status = Object.entries(a.module_statuses ?? {}).reduce<Record<string, string>>((o, [k, v]) => { const b = k.split(':')[0]; if (!o[b] || v !== 'completed') o[b] = v; return o }, {})
  const certRan = cert.length > 0 || 'M2' in status || a.evidence.some(e => e.source_module === 'M2')
  const feeds: { source: string; match: boolean; off?: boolean }[] = a.intel ?? FEEDS.map(source => ({ source, match: false, off: true }))
  const gaps = Object.entries(status).filter(([, s]) => ['partial', 'failed'].includes(s))
  return (
    <article className="dossier">
      {a.demo && <p className="demo">Demo data. The backend at /api did not respond, so this is a sample result.</p>}
      <header>
        <h2 className={'v-' + risk}>{m.label}</h2>
        <p className="dim">{m.note}</p>
        <Strip risk={risk} />
        <p className="meta">Checked {new Date(a.created_at).toLocaleString()} · report {a.report_id.slice(0, 8)} · investigation {a.investigation_id.slice(0, 8)}</p>
      </header>
      <section className="block"><h3>What we found</h3><p className="lead">{a.summary}</p></section>
      {message && <section className="block"><h3>Your message, marked up</h3><Highlighter text={message} findings={a.findings} indicators={a.indicators} /></section>}
      {Object.keys(status).length > 0 && <section className="block"><h3>Checks that ran</h3>
        <div className="feeds">{Object.entries(status).map(([k, s]) => <span key={k} className={'st-' + s}>{MOD[k] ?? k}: {s.replace(/_/g, ' ')}</span>)}</div></section>}
      {redirects.length > 0 && <section className="block"><h3>Where the link really goes</h3><Chain urls={redirects} /></section>}
      <section className="block"><h3>Findings</h3>
        {other.length === 0 && <p className="dim">No findings recorded. Absence of findings is not proof of safety.</p>}
        <ul className="ev">{other.map((f, k) => (
          <li key={k} className={'s-' + f.severity.toLowerCase()}>
            <div><b>{f.title}</b><span className="sev">{f.severity}</span><p>{f.description}</p>
              {f.impact && <p><em>Impact:</em> {f.impact}</p>}{f.remediation && <p><em>What to do:</em> {f.remediation}</p>}</div>
            <code>{mod(f.source_module)}</code>
          </li>))}</ul>
      </section>
      {certRan && <section className="block"><h3>Certificate</h3>
        <p className="lead">{cert.length ? 'Certificate problems were found.' : 'No certificate problems were recorded.'}</p>
        <p className="dim">A valid certificate only means the connection is encrypted. It does not mean the site is honest.</p>
        <ul className="ev">{cert.map((f, k) => <li key={k} className={'s-' + f.severity.toLowerCase()}><div><b>{f.title}</b><span className="sev">{f.severity}</span><p>{f.description}</p></div></li>)}</ul></section>}
      {a.indicators.length > 0 && <section className="block"><h3>Indicators</h3>
        {types.map(t => <div key={t} className="itype"><span>{t.replace(/_/g, ' ')}</span><div className="chips">{a.indicators.filter(i => i.indicator_type === t).map((i, k) => <code key={k} title={mod(i.source_module)}>{i.value}</code>)}</div></div>)}</section>}
      {related.length > 0 && <section className="block"><h3>Seen before</h3><ul className="lim">{related.map((e, k) => <li key={k}>{e.description.replace('Historical correlation: ', '')}</li>)}</ul></section>}
      <section className="block"><h3>Threat feeds</h3>
        <div className="feeds">{feeds.map(f => (
          <span key={f.source} className={f.off ? 'off' : f.match ? 'hit' : ''}>{f.source}: {f.off ? 'not checked' : f.match ? 'listed' : 'no match'}</span>))}</div>
        {!a.intel && <p className="dim sm">Threat feed lookups are not part of this assessment yet.</p>}
      </section>
      {(limits.length > 0 || gaps.length > 0) && <section className="block"><h3>What we could not check</h3><ul className="lim">
        {limits.map((e, k) => <li key={k}>{e.description.replace('Analysis limitation: ', '')}</li>)}
        {gaps.map(([k, s]) => <li key={k}>{MOD[k] ?? k} was {s}.</li>)}</ul></section>}
      {log.length > 0 && <section className="block"><details><summary>Evidence log ({log.length})</summary>
        <ul className="ev log">{log.map((e, k) => <li key={k}><div><p>{e.description}</p>{e.reference && <code>{e.reference}</code>}</div><code>{mod(e.source_module)}</code></li>)}</ul></details></section>}
      <Ledger r={a} />
    </article>
  )
}
