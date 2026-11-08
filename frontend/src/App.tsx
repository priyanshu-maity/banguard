
import { useState } from 'react'
import { analyze, InvestigationResult, InvestigationType } from './api'
import Dossier from './Report'

const STEPS = ['Normalising the address', 'Following redirects safely', 'Reading the certificate', 'Matching threat feeds', 'Writing the explanation']

const SAMPLES = [
  { name: 'A bank link', kind: 'url' as const, value: 'https://secure-verify-hdfc.top/login?kyc=update' },
  { name: 'A prize text', kind: 'message' as const, value: 'URGENT: you won a prize! Verify KYC and share OTP at bit.ly/claim-now or your account is suspended.' },
  { name: 'A normal site', kind: 'url' as const, value: 'https://www.wikipedia.org' },
]

export default function App() {
  const [kind, setKind] = useState<InvestigationType>('url')
  const [url, setUrl] = useState('')
  const [message, setMessage] = useState('')
  const [submitToBlockchain, setSubmitToBlockchain] = useState(false)
  const [step, setStep] = useState(-1)
  const [res, setRes] = useState<InvestigationResult>()
  const [err, setErr] = useState('')

  const go = async () => {
    if ((kind === 'url' || kind === 'combined') && !url.trim()) {
      setErr('Enter a link or domain to check.')
      return
    }

    if ((kind === 'message' || kind === 'combined') && !message.trim()) {
      setErr('Paste the message you received.')
      return
    }

    setErr('')
    setRes(undefined)
    setStep(0)

    const timer = setInterval(() => setStep(s => Math.min(s + 1, STEPS.length - 1)), 520)

    try {
      const result = await analyze({
        investigation_type: kind,
        ...(kind !== 'message' ? { url: url.trim() } : {}),
        ...(kind !== 'url' ? { message: message.trim() } : {}),
        submit_to_blockchain: submitToBlockchain,
      })

      setRes(result)
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'The investigation failed. Check that the backend is running.')
    } finally {
      clearInterval(timer)
      setStep(-1)
    }
  }

  const sample = (kind: 'url' | 'message', value: string) => {
    setKind(kind)
    if (kind === 'url') setUrl(value)
    else setMessage(value)
    setErr('')
  }

  return (
    <div className="shell">
      <aside>
        <h1>Ban<span>Guard</span></h1>
        <p className="tag">Check it before you click it.</p>

        <div className="tabs" role="tablist">
          {(['url', 'message', 'combined'] as const).map(k => (
            <button key={k} role="tab" aria-selected={kind === k} className={kind === k ? 'on' : ''} onClick={() => { setKind(k); setErr('') }}>
              {k === 'url' ? 'Link or domain' : k === 'message' ? 'Message' : 'Combined'}
            </button>
          ))}
        </div>

        {(kind === 'url' || kind === 'combined') && (
          <textarea value={url} onChange={e => setUrl(e.target.value)} rows={3} spellCheck={false} placeholder="https://example.com" />
        )}

        {(kind === 'message' || kind === 'combined') && (
          <textarea value={message} onChange={e => setMessage(e.target.value)} rows={kind === 'combined' ? 5 : 7} spellCheck={false} placeholder="Paste the email, SMS or chat text here" />
        )}

        <p className="warn">Never paste passwords, OTPs or seed phrases.</p>

        <label className="blockchain-option">
          <input type="checkbox" checked={submitToBlockchain} onChange={e => setSubmitToBlockchain(e.target.checked)} />
          Record report on Sepolia blockchain
        </label>

        {err && <p className="err" role="alert">{err}</p>}

        <button className="go" onClick={go} disabled={step >= 0}>
          {step >= 0 ? 'Investigating…' : 'Investigate'}
        </button>

        <div className="samples">
          <span>Try</span>
          {SAMPLES.map(s => (
            <button key={s.name} className="chip" onClick={() => sample(s.kind, s.value)}>{s.name}</button>
          ))}
        </div>
      </aside>

      <main>
        {step >= 0 && (
          <section className="proc" aria-live="polite" aria-busy="true">
            <header>
              <h2>Investigating</h2>
              <code title={kind === 'message' ? message : url}>
                {(kind === 'message' ? message : url).slice(0, 70)}
              </code>
            </header>
            <ol>
              {STEPS.map((s, i) => (
                <li key={s} className={i < step ? 'done' : i === step ? 'now' : ''}>
                  <span className="ico" aria-hidden="true">{i < step ? '✓' : ''}</span>
                  <span className="lbl">{s}</span>
                  {i === step && <span className="dots" aria-hidden="true"><i /><i /><i /></span>}
                  {i < step && <small>done</small>}
                </li>
              ))}
            </ol>
            <div className="prog"><div style={{ width: ((step + 1) / STEPS.length) * 100 + '%' }} /></div>
          </section>
        )}

        {!res && step < 0 && (
          <div className="empty">
            <div className="strip big"><div className="bar" /></div>
            <h2>Is it safe?</h2>
            <p className="dim">Submit a link or message. You get a verdict, the evidence behind it, and what we could not check.</p>
          </div>
        )}

        {res && step < 0 && <Dossier a={res} />}
      </main>
    </div>
  )
}
