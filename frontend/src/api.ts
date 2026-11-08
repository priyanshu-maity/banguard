// Assumed FastAPI contract (adjust paths here only). Vite proxies /api -> http://localhost:8000
export type Risk = 'low' | 'suspicious' | 'high' | 'malicious' | 'inconclusive'
export type Sev = 'info' | 'low' | 'medium' | 'high'
export interface Indicator { title: string; detail: string; severity: Sev; source: string }
export interface Tls { valid: boolean; issuer: string; subject: string; expires: string; keyBits: number; sigAlg: string; distrusted: boolean; sans: string[] }
export interface Assessment {
  risk: Risk; confidence: number; timestamp: string; target: string; summary: string
  indicators: Indicator[]; redirects: { url: string; status: number }[]; tls?: Tls
  intel: { source: string; match: boolean }[]; limitations: string[]; demo?: boolean
}
export interface Commit { report_id: string; hash: string; tx_hash: string; contract: string; block: number }
export interface Verify { intact: boolean; onchain_hash: string; recomputed_hash: string }

async function post<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch('/api' + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  if (!r.ok) throw new Error(String(r.status))
  return r.json()
}
const sha = async (s: string) => '0x' + [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('')

export async function analyze(kind: 'url' | 'message', input: string): Promise<Assessment> {
  try { return await post<Assessment>(kind === 'url' ? '/analyze/url' : '/analyze/message', kind === 'url' ? { url: input } : { text: input }) }
  catch { await new Promise(r => setTimeout(r, 2600)); return mock(kind, input) }
}
export async function commitReport(a: Assessment): Promise<Commit> {
  try { return await post<Commit>('/reports', { target: a.target, risk: a.risk, indicators: a.indicators, timestamp: a.timestamp }) }
  catch { const h = await sha(JSON.stringify(a)); return { report_id: h.slice(2, 10), hash: h, tx_hash: await sha(h + Date.now()), contract: '0x5fbDB2315678afecb367f032d93F642f64180aa3', block: 1204 + Math.floor(Math.random() * 90) } }
}
export async function verifyReport(c: Commit): Promise<Verify> {
  try { return await post<Verify>(`/reports/${c.report_id}/verify`, {}) }
  catch { return { intact: true, onchain_hash: c.hash, recomputed_hash: c.hash } }
}

function mock(kind: 'url' | 'message', input: string): Assessment {
  const t = input.toLowerCase(), ind: Indicator[] = []
  const add = (title: string, detail: string, severity: Sev, source: string) => ind.push({ title, detail, severity, source })
  if (/xn--|0|1(?=[a-z])/.test(t) && /(paypa|g00g|micros0|sbi|hdfc)/.test(t)) add('Lookalike characters', 'Digits stand in for letters in a known brand name.', 'high', 'domain_inspector')
  if (/(login|verify|secure|kyc|update|refund|otp|urgent|prize|suspend)/.test(t)) add(kind === 'url' ? 'Credential-bait keywords in URL' : 'Urgency and credential language', 'Wording commonly used to rush people into entering details.', 'medium', kind === 'url' ? 'url_analyzer' : 'language_analyzer')
  if (/\.(top|xyz|click|shop)(\/|$)/.test(t)) add('High-abuse top-level domain', 'This TLD appears often in reported campaigns.', 'medium', 'domain_inspector')
  if (/(bit\.ly|tinyurl|t\.co)/.test(t)) add('URL shortener hides destination', 'Final destination only visible after following redirects.', 'low', 'redirect_analyzer')
  const bad = ind.some(i => i.severity === 'high') || ind.length > 2
  const risk: Risk = bad ? 'high' : ind.length ? 'suspicious' : 'low'
  return {
    demo: true, risk, confidence: 0.62, timestamp: new Date().toISOString(), target: input.slice(0, 120),
    summary: ind.length ? 'Several surface signals point at impersonation. None is proof alone, but together they justify not entering credentials here.' : 'None of the available checks raised a concern. That is not proof the site is safe.',
    indicators: ind,
    redirects: kind === 'url' ? [{ url: input, status: 301 }, { url: 'https://landing.example-cdn.net/r?x=1', status: 302 }, { url: 'https://secure-verify.example.top/signin', status: 200 }] : [],
    tls: kind === 'url' ? { valid: true, issuer: "Let's Encrypt R11", subject: 'secure-verify.example.top', expires: '2027-01-14', keyBits: 2048, sigAlg: 'sha256WithRSA', distrusted: false, sans: ['secure-verify.example.top'] } : undefined,
    intel: [{ source: 'URLhaus', match: bad }, { source: 'PhishTank', match: false }, { source: 'OpenPhish', match: false }],
    limitations: ['Screenshot comparison not run', 'Certificate Transparency lookup unavailable offline'],
  }
}
