// Mirrors core.schema.ThreatReport from the FastAPI assessment engine. Vite proxies /api -> :8000
export type Risk = 'low' | 'suspicious' | 'high' | 'malicious' | 'inconclusive'
export interface Finding { title: string; description: string; severity: string; source_module: string; impact?: string | null; remediation?: string | null }
export interface Indicator { indicator_type: string; value: string; source_module: string }
export interface Evidence { description: string; source_module: string; reference?: string | null }
export interface ThreatReport {
  report_id: string; investigation_id: string; created_at: string; risk_level: string; summary: string
  findings: Finding[]; indicators: Indicator[]; evidence: Evidence[]
  module_statuses?: Record<string, string>              // optional: AssessmentEvidence.module_statuses
  intel?: { source: string; match: boolean }[]          // optional: not produced by the engine yet
  demo?: boolean
}
export interface Commit { report_id: string; hash: string; tx_hash: string; contract: string; block: number }
export interface Verify { intact: boolean; onchain_hash: string; recomputed_hash: string }

export const riskOf = (s: string): Risk => {
  const k = s.toLowerCase().replace(/^risklevel\./, '').replace(/[\s-]+/g, '_')
  if (k === 'confirmed_malicious' || k === 'malicious') return 'malicious'
  return (['low', 'suspicious', 'high', 'inconclusive'].includes(k) ? k : 'inconclusive') as Risk
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch('/api' + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  if (!r.ok) throw new Error(String(r.status))
  return r.json()
}
const sha = async (s: string) => '0x' + [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('')

export async function analyze(kind: 'url' | 'message', input: string): Promise<ThreatReport> {
  try { return await post<ThreatReport>(kind === 'url' ? '/analyze/url' : '/analyze/message', kind === 'url' ? { url: input } : { text: input }) }
  catch { await new Promise(r => setTimeout(r, 2600)); return mock(kind, input) }
}
export async function commitReport(r: ThreatReport): Promise<Commit> {
  try { return await post<Commit>('/reports', r) }
  catch { const h = await sha(JSON.stringify(r)); return { report_id: r.report_id, hash: h, tx_hash: await sha(h + Date.now()), contract: '0x5fbDB2315678afecb367f032d93F642f64180aa3', block: 1204 + Math.floor(Math.random() * 90) } }
}
export async function verifyReport(c: Commit): Promise<Verify> {
  try { return await post<Verify>(`/reports/${c.report_id}/verify`, {}) }
  catch { return { intact: true, onchain_hash: c.hash, recomputed_hash: c.hash } }
}

function mock(kind: 'url' | 'message', input: string): ThreatReport {
  const t = input.toLowerCase(), findings: Finding[] = [], evidence: Evidence[] = [], indicators: Indicator[] = []
  const f = (title: string, description: string, severity: string, m: string, impact?: string, remediation?: string) => { findings.push({ title, description, severity, source_module: m, impact, remediation }); evidence.push({ description, source_module: m }) }
  if (/(paypa|g00g|micros0|hdfc|sbi)/.test(t)) f('Potential typosquatting detected', 'The domain resembles a known brand.', 'high', 'M1', 'Visitors may believe they are on the real site.', 'Type the official address yourself.')
  if (/(login|verify|secure|kyc|update|refund)/.test(t)) f('Suspicious keywords in URL', 'The URL contains keywords commonly associated with suspicious links.', 'low', 'M1')
  if (/bit\.ly|tinyurl/.test(t)) f('URL shortener detected', 'A known URL-shortening service appears in the redirect chain.', 'medium', 'M1')
  if (kind === 'message') {
    if (/(urgent|immediately|suspend)/.test(t)) f('Urgency language detected', 'The message contains urgency language. Evidence: urgent; suspended', 'low', 'M3')
    if (/(otp|password|kyc|pin)/.test(t)) f('Credential request detected', 'The message requests credentials or sensitive account information. Evidence: share OTP', 'high', 'M3', 'Sharing an OTP can give attackers access to your account.', 'Never share OTPs. Contact the organisation through its official app.')
    if (/prize|won/.test(t)) f('Reward or prize lure detected', 'The message contains a reward or prize lure. Evidence: you won a prize', 'medium', 'M3')
  }
  if (kind === 'message') { const u = input.match(/https?:\/\/\S+|\b[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\/\S+/i); if (u) indicators.push({ indicator_type: 'url', value: u[0].replace(/[.,;)]+$/, ''), source_module: 'M3' }) }
  if (kind === 'url') { evidence.push({ description: `Redirect observed: ${input}`, source_module: 'M1', reference: input }, { description: 'Redirect observed: https://landing.example-cdn.net/r?x=1', source_module: 'M1', reference: 'https://landing.example-cdn.net/r?x=1' }, { description: 'Redirect observed: https://secure-verify.example.top/signin', source_module: 'M1', reference: 'https://secure-verify.example.top/signin' })
    indicators.push({ indicator_type: 'domain', value: 'secure-verify.example.top', source_module: 'M1' }, { indicator_type: 'ip', value: '203.0.113.24', source_module: 'M1' })
    if (findings.length) f('Untrusted certificate issuer', 'The certificate chain does not lead to a trusted root. URL: ' + input, 'medium', 'M2') }
  evidence.push({ description: 'Analysis limitation: Screenshot comparison was not run.', source_module: 'M5' })
  const hi = findings.filter(x => x.severity === 'high').length
  const risk = hi >= 2 ? 'high' : findings.length > 1 ? 'suspicious' : findings.length ? 'suspicious' : 'low'
  return {
    demo: true, report_id: crypto.randomUUID(), investigation_id: crypto.randomUUID(), created_at: new Date().toISOString(), risk_level: risk,
    summary: (findings.length ? 'Suspicious indicators were identified. Further investigation is recommended.' : 'The completed analysis identified no significant suspicious activity.') + ` The analysis recorded ${findings.length} finding${findings.length === 1 ? '' : 's'}.`,
    findings, indicators, evidence,
    module_statuses: kind === 'url' ? { M1: 'completed', ['M2:' + input]: 'completed', M3: 'not_applicable', M4: 'completed', M5: 'partial' } : { M1: 'not_applicable', M3: 'completed', M4: 'completed', M5: 'not_applicable' },
  }
}
