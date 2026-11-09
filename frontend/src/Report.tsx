import { useState } from 'react'
import { InvestigationResult, ThreatReport, Risk, RedirectFlag, RedirectHop, riskOf, verifyReport, BlockchainVerification } from './api'

const META: Record<Risk, { label: string; pos: number; note: string }> = {
  low: { label: 'Low risk', pos: 8, note: 'No significant indicators in the checks that ran.' },
  suspicious: { label: 'Suspicious', pos: 36, note: 'Something needs a closer look before you trust it.' },
  high: { label: 'High risk', pos: 64, note: 'Multiple strong signals. Do not enter details.' },
  confirmed_malicious: { label: 'Confirmed malicious', pos: 93, note: 'Backed by authoritative threat intelligence.' },
  inconclusive: { label: 'Inconclusive', pos: -1, note: 'Not enough data to judge either way.' },
}

const MOD: Record<string, string> = { M1: 'URL analysis', M2: 'Certificate', M3: 'Message analysis', M4: 'Correlation', M5: 'Site security', M6: 'Threat intelligence', ASSESSMENT: 'Assessment' }
const mod = (s: string) => s.split(',').map(x => MOD[x.trim()] ?? x.trim()).join(', ')
const SEV = ['critical', 'high', 'medium', 'low', 'info']
const has = (e: { description: string }, p: string) => e.description.startsWith(p)

const FLAG_TEXT: Record<RedirectFlag, string> = {
  insecure_http: 'unencrypted',
  url_shortener: 'shortener',
  cross_domain: 'different domain',
  internal_address: 'internal address',
}

// Older saved reports only have URLs in the evidence list, so build plain hops from those.
const hopsFromUrls = (urls: string[]): RedirectHop[] =>
  urls.map((url, i) => {
    let host = url
    try { host = new URL(url).hostname } catch { /* keep the raw text */ }
    return { url, host, role: i === 0 ? 'start' : i === urls.length - 1 ? 'final' : 'redirect', flags: [] }
  })

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

function Chain({ hops }: { hops: RedirectHop[] }) {
  const first = hops[0]?.host
  return (
    <ol className="chain">
      {hops.map((h, i) => {
        const drift = h.flags.includes('cross_domain') || (i === hops.length - 1 && h.host !== first)
        return (
          <li key={i} className={drift ? 'drift' : ''} title={h.url}>
            <b>{h.host || h.url}</b>
            {h.flags.map(f => <span key={f} className="sev">{FLAG_TEXT[f] ?? f}</span>)}
          </li>
        )
      })}
    </ol>
  )
}

function Ledger({ a }: { a: InvestigationResult }) {
  const [v, setV] = useState<BlockchainVerification>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const submission = a.report_submission
  const message = a.blockchain_message
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
          <p className={'seal ' + (a.blockchain_status === 'submitted_verification_failed' ? 'bad' : 'ok')}>
            {message || 'Report submitted to the blockchain.'}
          </p>
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
      ) : a.blockchain_status === 'failed' || (!message && a.report_submission_error) ? (
        <p className="err">{message || a.report_submission_error}</p>
      ) : (
        <p className="dim">{message || 'This report was not submitted to the blockchain.'}</p>
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
  const certProblems = cert.filter(f => f.severity.toLowerCase() !== 'info')
  const other = sorted.filter(f => f.source_module !== 'M2')
  const evidence = r.evidence ?? []
  const indicators = r.indicators ?? []
  const flows = a.redirect_flows ?? []
  const legacyRedirects = evidence.filter(e => has(e, 'Redirect observed:')).map(e => e.reference || e.description.replace('Redirect observed:', '').trim())
  const limits = evidence.filter(e => has(e, 'Analysis limitation:'))
  const related = evidence.filter(e => has(e, 'Historical correlation:'))
  const log = evidence.filter(e => !has(e, 'Redirect observed:') && !has(e, 'Analysis limitation:') && !has(e, 'Historical correlation:'))
  const types = [...new Set(indicators.map(i => i.indicator_type))]

  const results: [string, unknown][] = [
    ...Object.values(a.m1_results ?? {}).map(v => ['M1', v] as [string, unknown]),
    ...Object.values(a.m2_results ?? {}).map(v => ['M2', v] as [string, unknown]),
    ...(a.m3_result ? [['M3', a.m3_result] as [string, unknown]] : []),
    ...(a.m4_result ? [['M4', a.m4_result] as [string, unknown]] : []),
    ...Object.values(a.m5_results ?? {}).map(v => ['M5', v] as [string, unknown]),
  ]

  const statuses = results
    .map(([key, value]) => {
      const result = value as { status?: string; error?: string } | null
      return { key, status: result?.status ?? (result?.error ? 'failed' : 'available') }
    })
    .filter((s, i, all) => all.findIndex(x => x.key === s.key && x.status === s.status) === i)

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

      {a.investigation_type !== 'message' && (
        <section className="block">
          <h3>Where the link really goes</h3>
          {flows.map((f, k) => (
            <div key={k}>
              {flows.length > 1 && <p className="dim">{f.submitted_url}</p>}
              <Chain hops={f.hops} />
            </div>
          ))}
          {flows.length === 0 && legacyRedirects.length > 0 && <Chain hops={hopsFromUrls(legacyRedirects)} />}
          {flows.length === 0 && legacyRedirects.length === 0 && (
            <p className="dim">
              {a.redirect_flows === undefined
                ? 'The server did not send redirect data (backend not updated or field not returned).'
                : 'No redirects were observed for the submitted link(s).'}
            </p>
          )}
        </section>
      )}

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
          <p className="lead">{certProblems.length ? 'Certificate problems were found.' : 'No certificate problems were recorded.'}</p>
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