
import { useState } from 'react'
import { InvestigationResult, ThreatReport, Risk, riskOf, verifyReport, BlockchainVerification } from './api'

const META: Record<Risk, { label: string; pos: number; note: string }> = {
  low: { label: 'Low risk', pos: 8, note: 'No significant indicators in the checks that ran.' },
  suspicious: { label: 'Suspicious', pos: 36, note: 'Something needs a closer look before you trust it.' },
  high: { label: 'High risk', pos: 64, note: 'Multiple strong signals. Do not enter details.' },
  confirmed_malicious: { label: 'Confirmed malicious', pos: 93, note: 'Backed by authoritative threat intelligence.' },
  inconclusive: { label: 'Inconclusive', pos: -1, note: 'Not enough data to judge either way.' },
}

const MOD: Record<string, string> = { M1: 'URL analysis', M2: 'Certificate', M3: 'Message analysis', M4: 'Correlation', M5: 'Site security', M6: 'Threat intelligence' }
const mod = (s: string) => s.split(',').map(x => MOD[x.trim()] ?? x.trim()).join(', ')
const SEV = ['critical', 'high', 'medium', 'low', 'info']
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

function Ledger({ a }: { a: InvestigationResult }) {
  const [v, setV] = useState<BlockchainVerification>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const submission = a.report_submission
  const runVerify = async () => {
    setBusy(true)
    setError('')
    try {
      setV(await verifyReport(a.threat_report.report_id, submission?.version))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Verification request failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="block">
      <h3>Blockchain integrity</h3>
      <p className="dim">Only a report fingerprint is stored on-chain. The original URL, message and personal details remain off-chain. A blockchain record proves integrity, not whether the report itself is true.</p>

      {submission ? (
        <>
          <p className="seal ok">Report submitted to the blockchain.</p>
          <dl className="hashes">
            <dt>Report version</dt><dd>{submission.version}</dd>
            <dt>Fingerprint</dt><dd>{submission.content_hash}</dd>
            <dt>Transaction</dt>
            <dd>
              {submission.blockchain_tx_hash ? (
                <a href={`https://sepolia.etherscan.io/tx/${submission.blockchain_tx_hash}`} target="_blank" rel="noreferrer">{submission.blockchain_tx_hash}</a>
              ) : 'Not available'}
            </dd>
          </dl>
          <button className="ghost" disabled={busy} onClick={runVerify}>{busy ? 'Checking…' : 'Verify independently'}</button>
          {v && (
            <div className={'seal ' + (v.verified ? 'ok' : 'bad')}>
              {v.verified ? 'Verified: local and on-chain fingerprints match.' : `Verification failed: ${v.reason}`}
              {v.blockchain_hash && <p>On-chain hash: <code>{v.blockchain_hash}</code></p>}
              {v.content_hash && <p>Local hash: <code>{v.content_hash}</code></p>}
            </div>
          )}
        </>
      ) : (
        <>
          <p className="dim">This report was not submitted to the blockchain.</p>
          {a.report_submission_error && <p className="err">{a.report_submission_error}</p>}
        </>
      )}
      {error && <p className="err" role="alert">{error}</p>}
    </section>
  )
}

export default function Dossier({ a }: { a: InvestigationResult }) {
  const r: ThreatReport = a.threat_report
  const risk = riskOf(r.risk_level)
  const m = META[risk]
  const sorted = [...(r.findings ?? [])].sort((x, y) => SEV.indexOf(x.severity.toLowerCase()) - SEV.indexOf(y.severity.toLowerCase()))
  const cert = sorted.filter(f => f.source_module === 'M2')
  const other = sorted.filter(f => f.source_module !== 'M2')
  const evidence = r.evidence ?? []
  const indicators = r.indicators ?? []
  const redirects = evidence.filter(e => has(e, 'Redirect observed:')).map(e => e.reference || e.description.replace('Redirect observed:', '').trim())
  const limits = evidence.filter(e => has(e, 'Analysis limitation:'))
  const related = evidence.filter(e => has(e, 'Historical correlation:'))
  const log = evidence.filter(e => !has(e, 'Redirect observed:') && !has(e, 'Analysis limitation:') && !has(e, 'Historical correlation:'))
  const types = [...new Set(indicators.map(i => i.indicator_type))]

  const moduleResults: Record<string, unknown> = {
    ...(a.m1_results ?? {}),
    ...(a.m2_results ?? {}),
    ...(a.m3_result ? { M3: a.m3_result } : {}),
    ...(a.m4_result ? { M4: a.m4_result } : {}),
    ...(a.m5_results ?? {}),
  }

  const statuses = Object.entries(moduleResults).map(([key, value]) => {
    const result = value as { status?: string; error?: string } | null
    return { key: key.split(':')[0], status: result?.status ?? (result?.error ? 'failed' : 'available') }
  })

  const gaps = statuses.filter(x => ['partial', 'failed', 'skipped'].includes(x.status))

  return (
    <article className="dossier">
      <header>
        <h2 className={'v-' + risk}>{m.label}</h2>
        <p className="dim">{m.note}</p>
        <Strip risk={risk} />
        <p className="meta">Checked {new Date(r.created_at).toLocaleString()} · report {r.report_id.slice(0, 8)} · investigation {r.investigation_id.slice(0, 8)}</p>
      </header>

      <section className="block"><h3>What we found</h3><p className="lead">{r.summary}</p></section>

      {statuses.length > 0 && (
        <section className="block">
          <h3>Checks that ran</h3>
          <div className="feeds">
            {statuses.map((s, i) => <span key={`${s.key}-${i}`} className={'st-' + s.status}>{MOD[s.key] ?? s.key}: {s.status.replace(/_/g, ' ')}</span>)}
          </div>
        </section>
      )}

      {redirects.length > 0 && <section className="block"><h3>Where the link really goes</h3><Chain urls={redirects} /></section>}

      <section className="block">
        <h3>Findings</h3>
        {other.length === 0 && <p className="dim">No findings recorded. Absence of findings is not proof of safety.</p>}
        <ul className="ev">
          {other.map((f, k) => (
            <li key={k} className={'s-' + f.severity.toLowerCase()}>
              <div>
                <b>{f.title}</b><span className="sev">{f.severity}</span>
                <p>{f.description}</p>
                {f.impact && <p><em>Impact:</em> {f.impact}</p>}
                {f.remediation && <p><em>What to do:</em> {f.remediation}</p>}
              </div>
              <code>{mod(f.source_module)}</code>
            </li>
          ))}
        </ul>
      </section>

      {(cert.length > 0 || a.m2_results) && (
        <section className="block">
          <h3>Certificate</h3>
          <p className="lead">{cert.length ? 'Certificate problems were found.' : 'No certificate problems were recorded.'}</p>
          <p className="dim">A valid certificate only means the connection is encrypted. It does not mean the site is honest.</p>
          <ul className="ev">
            {cert.map((f, k) => <li key={k} className={'s-' + f.severity.toLowerCase()}><div><b>{f.title}</b><span className="sev">{f.severity}</span><p>{f.description}</p></div></li>)}
          </ul>
        </section>
      )}

      {indicators.length > 0 && (
        <section className="block">
          <h3>Indicators</h3>
          {types.map(t => (
            <div key={t} className="itype">
              <span>{t.replace(/_/g, ' ')}</span>
              <div className="chips">{indicators.filter(i => i.indicator_type === t).map((i, k) => <code key={k} title={mod(i.source_module)}>{i.value}</code>)}</div>
            </div>
          ))}
        </section>
      )}

      {related.length > 0 && <section className="block"><h3>Seen before</h3><ul className="lim">{related.map((e, k) => <li key={k}>{e.description.replace('Historical correlation: ', '')}</li>)}</ul></section>}

      {(limits.length > 0 || gaps.length > 0) && (
        <section className="block">
          <h3>What we could not check</h3>
          <ul className="lim">
            {limits.map((e, k) => <li key={k}>{e.description.replace('Analysis limitation: ', '')}</li>)}
            {gaps.map((g, k) => <li key={k}>{MOD[g.key] ?? g.key} was {g.status}.</li>)}
          </ul>
        </section>
      )}

      {log.length > 0 && (
        <section className="block">
          <details>
            <summary>Evidence log ({log.length})</summary>
            <ul className="ev log">
              {log.map((e, k) => <li key={k}><div><p>{e.description}</p>{e.reference && <code>{e.reference}</code>}</div><code>{mod(e.source_module)}</code></li>)}
            </ul>
          </details>
        </section>
      )}

      <Ledger a={a} />
    </article>
  )
}
