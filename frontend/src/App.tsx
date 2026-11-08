import { useState } from 'react'
import { analyze, ThreatReport } from './api'
import Dossier from './Report'

const STEPS = ['Normalising the address', 'Following redirects safely', 'Reading the certificate', 'Matching threat feeds', 'Writing the explanation']
const SAMPLES = [
  ['A bank link', 'https://secure-verify-hdfc.top/login?kyc=update'],
  ['A prize text', 'URGENT: you won a prize! Verify KYC and share OTP at bit.ly/claim-now or your account is suspended.'],
  ['A normal site', 'https://www.wikipedia.org'],
]

export default function App() {
  const [kind, setKind] = useState<'url' | 'message'>('url')
  const [text, setText] = useState('')
  const [step, setStep] = useState(-1)
  const [res, setRes] = useState<ThreatReport>()
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
        {step >= 0 && (
          <section className="proc" aria-live="polite" aria-busy="true">
            <header><h2>Investigating</h2><code title={text}>{text.length > 70 ? text.slice(0, 70) + '…' : text}</code></header>
            <ol>{STEPS.map((s, i) => (
              <li key={s} className={i < step ? 'done' : i === step ? 'now' : ''}>
                <span className="ico" aria-hidden="true">{i < step ? '✓' : ''}</span>
                <span className="lbl">{s}</span>
                {i === step && <span className="dots" aria-hidden="true"><i /><i /><i /></span>}
                {i < step && <small>done</small>}
              </li>
            ))}</ol>
            <div className="prog"><div style={{ width: ((step + 1) / STEPS.length) * 100 + '%' }} /></div>
          </section>
        )}
        {!res && step < 0 && <div className="empty"><div className="strip big"><div className="bar" /></div><h2>Is it safe?</h2><p className="dim">Submit a link or message. You get a verdict, the evidence behind it, and what we could not check.</p></div>}
        {res && step < 0 && <Dossier a={res} />}
      </main>
    </div>
  )
}
