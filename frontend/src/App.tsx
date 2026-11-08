import { useState } from 'react'
import { analyze, commitReport, verifyReport, Assessment, Commit, Verify, Risk } from './api'

const META: Record<Risk, { label: string; pos: number; note: string }> = {
  low: { label: 'Low risk', pos: 8, note: 'No significant indicators in the checks that ran.' },
  suspicious: { label: 'Suspicious', pos: 36, note: 'Something needs a closer look before you trust it.' },
  high: { label: 'High risk', pos: 64, note: 'Multiple strong signals. Do not enter details.' },
  malicious: { label: 'Confirmed malicious', pos: 93, note: 'Backed by authoritative threat intelligence.' },
  inconclusive: { label: 'Inconclusive', pos: -1, note: 'Not enough data to judge either way.' },
}
const STEPS = ['Normalising the address', 'Following redirects safely', 'Reading the certificate', 'Matching threat feeds', 'Writing the explanation']
const SAMPLES = [
  ['A bank link', 'https://secure-verify-hdfc.top/login?kyc=update'],
  ['A prize text', 'URGENT: you won a prize! Verify KYC and share OTP at bit.ly/claim-now or your account is suspended.'],
  ['A normal site', 'https://www.wikipedia.org'],
]

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

function Chain({ items }: { items: Assessment['redirects'] }) {
  if (!items.length) return null
  const host = (u: string) => { try { return new URL(u).hostname } catch { return u } }
  return (
    <ol className="chain">
      {items.map((r, i) => (
        <li key={i} className={i === items.length - 1 && host(r.url) !== host(items[0].url) ? 'drift' : ''}>
          <b>{host(r.url)}</b><small>{r.status}</small>
        </li>
      ))}
    </ol>
  )
}

function Ledger({ a }: { a: Assessment }) {
  const [c, setC] = useState<Commit>(), [v, setV] = useState<Verify>(), [busy, setBusy] = useState(false)
  const run = async (f: () => Promise<void>) => { setBusy(true); try { await f() } finally { setBusy(false) } }
  return (
    <section className="block">
      <h3>Share this finding</h3>
      <p className="dim">Only a fingerprint goes on-chain. The address, message and your details stay off it. A record proves the report was not altered, not that it is true.</p>
      {!c && <button disabled={busy} onClick={() => run(async () => setC(await commitReport(a)))}>{busy ? 'Recording…' : 'Record on ledger'}</button>}
      {c && <dl className="hashes">
        <dt>Fingerprint</dt><dd>{c.hash}</dd><dt>Transaction</dt><dd>{c.tx_hash}</dd><dt>Contract</dt><dd>{c.contract} · block {c.block}</dd>
      </dl>}
      {c && !v && <button className="ghost" disabled={busy} onClick={() => run(async () => setV(await verifyReport(c)))}>{busy ? 'Checking…' : 'Verify independently'}</button>}
      {v && <p className={'seal ' + (v.intact ? 'ok' : 'bad')}>{v.intact ? 'Intact: on-chain and recomputed fingerprints match.' : 'Mismatch: this report changed after it was recorded.'}</p>}
    </section>
  )
}

function Dossier({ a }: { a: Assessment }) {
  const m = META[a.risk]
  return (
    <article className="dossier">
      {a.demo && <p className="demo">Demo data. The backend at /api did not respond, so this is a sample result.</p>}
      <header>
        <h2 className={'v-' + a.risk}>{m.label}</h2>
        <p className="dim">{m.note}</p>
        <Strip risk={a.risk} />
        <p className="meta">Checked {new Date(a.timestamp).toLocaleString()} · evidence coverage {Math.round(a.confidence * 100)}%</p>
      </header>
      <section className="block"><h3>What we found</h3><p className="lead">{a.summary}</p></section>
      {a.redirects.length > 0 && <section className="block"><h3>Where the link really goes</h3><Chain items={a.redirects} /></section>}
      <section className="block">
        <h3>Evidence</h3>
        {a.indicators.length === 0 && <p className="dim">No indicators found. Absence of evidence is not proof of safety.</p>}
        <ul className="ev">{a.indicators.map((i, k) => (
          <li key={k} className={'s-' + i.severity}><div><b>{i.title}</b><p>{i.detail}</p></div><code>{i.source}</code></li>
        ))}</ul>
      </section>
      {a.tls && <section className="block"><h3>Certificate</h3>
        <p className="lead">{a.tls.distrusted ? 'Issued by a distrusted authority.' : a.tls.valid ? 'Valid, but a valid certificate only means the connection is encrypted.' : 'Invalid or expired.'}</p>
        <dl className="grid"><dt>Issuer</dt><dd>{a.tls.issuer}</dd><dt>Subject</dt><dd>{a.tls.subject}</dd><dt>Expires</dt><dd>{a.tls.expires}</dd><dt>Key</dt><dd>{a.tls.keyBits}-bit · {a.tls.sigAlg}</dd></dl>
      </section>}
      <section className="block"><h3>Threat feeds</h3>
        <div className="feeds">{a.intel.map(f => <span key={f.source} className={f.match ? 'hit' : ''}>{f.source}: {f.match ? 'listed' : 'no match'}</span>)}</div>
      </section>
      {a.limitations.length > 0 && <section className="block"><h3>What we could not check</h3><ul className="lim">{a.limitations.map(l => <li key={l}>{l}</li>)}</ul></section>}
      <Ledger a={a} />
    </article>
  )
}

export default function App() {
  const [kind, setKind] = useState<'url' | 'message'>('url')
  const [text, setText] = useState('')
  const [step, setStep] = useState(-1)
  const [res, setRes] = useState<Assessment>()
  const [err, setErr] = useState('')
  const go = async () => {
    if (!text.trim()) { setErr(kind === 'url' ? 'Paste a link or domain to check.' : 'Paste the message you received.'); return }
    setErr(''); setRes(undefined); setStep(0)
    const t = setInterval(() => setStep(s => Math.min(s + 1, STEPS.length - 1)), 520)
    try { setRes(await analyze(kind, text.trim())) } catch { setErr('The investigation failed. Check that the backend is running.') }
    clearInterval(t); setStep(-1)
  }
  return (
    <div className="shell">
      <aside>
        <h1>Ban<span>Guard</span></h1>
        <p className="tag">Check it before you click it.</p>
        <div className="tabs" role="tablist">
          {(['url', 'message'] as const).map(k => <button key={k} role="tab" aria-selected={kind === k} className={kind === k ? 'on' : ''} onClick={() => { setKind(k); setText('') }}>{k === 'url' ? 'Link or domain' : 'Message'}</button>)}
        </div>
        <textarea value={text} onChange={e => setText(e.target.value)} rows={kind === 'url' ? 3 : 7} spellCheck={false}
          placeholder={kind === 'url' ? 'https://…' : 'Paste the email, SMS or chat text here'} />
        <p className="warn">Never paste passwords, OTPs or seed phrases.</p>
        {err && <p className="err" role="alert">{err}</p>}
        <button className="go" onClick={go} disabled={step >= 0}>{step >= 0 ? 'Investigating…' : 'Investigate'}</button>
        <div className="samples"><span>Try</span>{SAMPLES.map(([n, v]) => <button key={n} className="chip" onClick={() => { setKind(v.startsWith('http') ? 'url' : 'message'); setText(v) }}>{n}</button>)}</div>
      </aside>
      <main>
        {step >= 0 && <ol className="steps">{STEPS.map((s, i) => <li key={s} className={i < step ? 'done' : i === step ? 'now' : ''}>{s}</li>)}</ol>}
        {!res && step < 0 && <div className="empty"><div className="strip big"><div className="bar" /></div><h2>Is it safe?</h2><p className="dim">Submit a link or message. You get a verdict, the evidence behind it, and what we could not check.</p></div>}
        {res && step < 0 && <Dossier a={res} />}
      </main>
    </div>
  )
}
