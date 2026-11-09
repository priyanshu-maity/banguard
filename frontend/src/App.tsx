import { useEffect, useRef, useState } from 'react'
import { analyze, InvestigationResult } from './api'
import { getProgress, newId, percent, InvestigationProgress } from './progress'
import Dossier from './Report'

type Kind = 'url' | 'message'

const MAX_CHARS = 5000

const SAMPLES = [
  { name: 'A bank link', kind: 'url' as const, value: 'https://secure-verify-hffc.top/login?kyc=update' },
  { name: 'A prize text', kind: 'message' as const, value: 'URGENT: you won a prize! Verify KYC and share OTP at bit.ly/claim-now or your account is suspended.' },
  { name: 'A normal site', kind: 'url' as const, value: 'https://www.reddit.com' },
]

const TABS: { kind: Kind; label: string }[] = [
  { kind: 'url', label: 'Link or domain' },
  { kind: 'message', label: 'Message' },
]

// Returns an error message, or '' when the URL is acceptable. A scheme of http or https is mandatory.
function checkUrl(raw: string): string {
  const value = raw.trim()
  if (!value) return 'Enter a link to check.'
  if (value.length > MAX_CHARS) return `The link is too long (maximum ${MAX_CHARS} characters).`
  if (/\s/.test(value)) return 'The link must not contain spaces or line breaks.'
  if (!/^https?:\/\//i.test(value)) return 'The link must start with http:// or https://'

  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return 'That is not a valid link. Example: https://example.com'
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return 'Only http:// and https:// links are accepted.'

  const host = parsed.hostname
  const isIpv6 = host.startsWith('[')
  const validHost = isIpv6 || (host.includes('.') && !host.startsWith('.') && !host.endsWith('.') && !host.includes('..'))
  if (!validHost) return 'The link needs a valid domain name, for example https://example.com'

  return ''
}

export default function App() {
  const [kind, setKind] = useState<Kind>('url')
  const [url, setUrl] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [prog, setProg] = useState<InvestigationProgress>()
  const [pct, setPct] = useState(0)
  const [res, setRes] = useState<InvestigationResult>()
  const [err, setErr] = useState('')
  const listRef = useRef<HTMLOListElement>(null)

  const current = kind === 'url' ? url : message
  const stages = (prog?.stages ?? []).filter(s => s.status !== 'skipped')

  // Keep the stage that is running in view when the list scrolls.
  useEffect(() => {
    const list = listRef.current
    const row = list?.querySelector<HTMLElement>('li.now')
    if (list && row) list.scrollTop = Math.max(0, row.offsetTop - list.clientHeight / 2)
  }, [prog])

  const go = async () => {
    if (kind === 'url') {
      const problem = checkUrl(url)
      if (problem) {
        setErr(problem)
        return
      }
    } else {
      if (!message.trim()) {
        setErr('Paste the message you received.')
        return
      }
      if (message.length > MAX_CHARS) {
        setErr(`The message is too long (maximum ${MAX_CHARS} characters).`)
        return
      }
    }

    // Only the field being investigated keeps its value; the other one is cleared.
    if (kind === 'url') setMessage('')
    else setUrl('')

    setErr('')
    setRes(undefined)
    setProg(undefined)
    setPct(0)
    setBusy(true)

    // The page picks the id so it can ask the backend how far along the investigation is while it runs.
    const id = newId()
    let live = true
    const timer = setInterval(async () => {
      const p = await getProgress(id)
      if (p && live) {
        setProg(p)
        setPct(v => Math.max(v, percent(p))) // never moves backwards when new stages are added
      }
    }, 350)

    try {
      const result = await analyze({
        investigation_type: kind,
        investigation_id: id,
        ...(kind === 'url' ? { url: url.trim() } : { message: message.trim() }),
      })

      setRes(result)
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'The investigation failed. Check that the backend is running.')
    } finally {
      live = false
      clearInterval(timer)
      setBusy(false)
      setProg(undefined)
    }
  }

  const sample = (k: Kind, value: string) => {
    setKind(k)
    if (k === 'url') setUrl(value)
    else setMessage(value)
    setErr('')
  }

  return (
    <div className="shell">
      <aside>
        <h1>Ban<span>Guard</span></h1>
        <p className="tag">Check it before you click it.</p>

        <div className="tabs" role="tablist">
          {TABS.map(t => (
            <button key={t.kind} role="tab" aria-selected={kind === t.kind} className={kind === t.kind ? 'on' : ''} onClick={() => { setKind(t.kind); setErr('') }}>
              {t.label}
            </button>
          ))}
        </div>

        {kind === 'url' ? (
          <textarea value={url} onChange={e => setUrl(e.target.value)} rows={3} maxLength={MAX_CHARS} spellCheck={false} placeholder="https://example.com" />
        ) : (
          <textarea value={message} onChange={e => setMessage(e.target.value)} rows={7} maxLength={MAX_CHARS} spellCheck={false} placeholder="Paste the email, SMS or chat text here" />
        )}

        <p className="warn">Never paste passwords, OTPs or seed phrases. · {current.length}/{MAX_CHARS}</p>

        {err && <p className="err" role="alert">{err}</p>}

        <button className="go" onClick={go} disabled={busy}>
          {busy ? 'Investigating…' : 'Investigate'}
        </button>

        <div className="samples">
          <span>Try</span>
          {SAMPLES.map(s => (
            <button key={s.name} className="chip" onClick={() => sample(s.kind, s.value)}>{s.name}</button>
          ))}
        </div>
      </aside>

      <main>
        {busy && (
          <section className="proc" aria-live="polite" aria-busy="true">
            <header>
              <h2>Investigating</h2>
              <code title={current}>{current.length > 70 ? current.slice(0, 70) + '…' : current}</code>
            </header>
            <ol ref={listRef}>
              {stages.length === 0 && (
                <li className="now">
                  <span className="ico" aria-hidden="true" />
                  <span className="lbl">Starting the investigation</span>
                  <span className="dots" aria-hidden="true"><i /><i /><i /></span>
                </li>
              )}
              {stages.map(s => (
                <li key={s.id} className={s.status === 'done' ? 'done' : s.status === 'running' ? 'now' : ''}>
                  <span className="ico" aria-hidden="true">{s.status === 'done' ? '✓' : ''}</span>
                  <span className="lbl">{s.label}</span>
                  {s.status === 'running' && <span className="dots" aria-hidden="true"><i /><i /><i /></span>}
                  {(s.detail || s.status === 'done') && <small>{s.detail || 'done'}</small>}
                </li>
              ))}
            </ol>
            <div className="prog"><div style={{ width: pct + '%' }} /></div>
          </section>
        )}

        {!res && !busy && (
          <div className="empty">
            <div className="strip big"><div className="bar" /></div>
            <h2>Is it safe?</h2>
            <p className="dim">Investigate suspicious links and messages before they become your next security incident.</p>
          </div>
        )}

        {res && !busy && <Dossier a={res} />}
      </main>
    </div>
  )
}