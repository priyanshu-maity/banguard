const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ?? ''
).replace(/\/$/, '')

if (!API_BASE_URL && import.meta.env.PROD) {
  throw new Error('VITE_API_BASE_URL is not configured.')
}

export type Risk = 'low' | 'suspicious' | 'high' | 'confirmed_malicious' | 'inconclusive'

export type InvestigationType = 'url' | 'message' | 'combined'

export interface Finding {
  title: string
  description: string
  severity: string
  source_module: string
  impact?: string | null
  remediation?: string | null
}

export interface Indicator {
  indicator_type: string
  value: string
  source_module: string
}

export interface Evidence {
  description: string
  source_module: string
  reference?: string | null
}

export interface ThreatReport {
  report_id: string
  investigation_id: string
  created_at: string
  risk_level: Risk
  summary: string
  findings: Finding[]
  indicators: Indicator[]
  evidence: Evidence[]
}

export interface BlockchainSubmission {
  report_id: string
  version: number
  content_hash: string
  blockchain_tx_hash: string | null
}

export interface BlockchainVerification {
  report_id: string
  version?: number
  verified: boolean
  reason: string
  content_hash?: string
  blockchain_hash?: string
  registered_at?: number
  submitter?: string
}

export type BlockchainStatus =
  | 'not_submitted'
  | 'submitted'
  | 'submitted_verified'
  | 'submitted_verification_failed'
  | 'failed'

export type RedirectFlag = 'insecure_http' | 'url_shortener' | 'cross_domain' | 'internal_address'

export interface RedirectHop {
  url: string
  host: string
  role: 'start' | 'redirect' | 'final'
  flags: RedirectFlag[]
}

export interface RedirectFlow {
  submitted_url: string
  hop_count: number
  crosses_domains: boolean
  hops: RedirectHop[]
}

export interface InvestigationResult {
  investigation_id: string
  original_url?: string | null
  investigation_type: InvestigationType
  message?: string | null
  m1_result?: unknown
  m1_results?: Record<string, unknown>
  m2_results?: Record<string, unknown>
  m3_result?: unknown
  m4_result?: unknown
  m5_results?: Record<string, unknown>
  threat_report: ThreatReport
  redirect_flows?: RedirectFlow[]
  report_submission?: BlockchainSubmission | null
  report_verification?: BlockchainVerification | null
  report_submission_error?: string | null
  report_submission_skipped_reason?: string | null
  blockchain_status?: BlockchainStatus
  blockchain_message?: string
}

export interface InvestigationRequest {
  investigation_id: string
  investigation_type: InvestigationType
  url?: string
  message?: string
  /** @deprecated Blockchain submission is now automatic; the backend ignores this. */
  submit_to_blockchain?: boolean
}

export interface InvestigationProgress {
  [key: string]: unknown
}

export function createInvestigationId(): string {
  return crypto.randomUUID()
}

export const riskOf = (value: string): Risk => {
  const risk = value.toLowerCase().replace(/^risklevel\./, '').replace(/[\s-]+/g, '_')

  if (risk === 'malicious' || risk === 'confirmed_malicious') return 'confirmed_malicious'
  if (['low', 'suspicious', 'high', 'inconclusive'].includes(risk)) return risk as Risk

  return 'inconclusive'
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE_URL}/api${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  })

  if (!response.ok) {
    let message = `API request failed (${response.status})`

    try {
      const body = await response.json()
      message = body.detail || message
    } catch {
      // Keep the HTTP status message if the response is not JSON.
    }

    throw new Error(message)
  }

  return response.json()
}

export async function analyze(input: InvestigationRequest): Promise<InvestigationResult> {
  const response = await request<{ success: boolean; data: InvestigationResult }>('/investigate', {
    method: 'POST',
    body: JSON.stringify(input),
  })

  if (!response.success || !response.data?.threat_report) {
    throw new Error('The backend returned an invalid investigation response.')
  }

  return response.data
}

export async function getProgress(investigationId: string): Promise<InvestigationProgress> {
  const response = await request<{ success: boolean; data: InvestigationProgress }>(
    `/investigate/${encodeURIComponent(investigationId)}/progress`
  )

  return response.data
}

export async function getInvestigation(investigationId: string): Promise<InvestigationResult> {
  const response = await request<{ success: boolean; data: InvestigationResult }>(
    `/investigations/${encodeURIComponent(investigationId)}`
  )

  return response.data
}

export async function getReport(reportId: string): Promise<ThreatReport> {
  const response = await request<{ success: boolean; data: ThreatReport }>(
    `/reports/${encodeURIComponent(reportId)}`
  )

  return response.data
}

export async function verifyReport(reportId: string, version?: number): Promise<BlockchainVerification> {
  const query = version === undefined ? '' : `?version=${version}`

  const response = await request<{ success: boolean; data: BlockchainVerification }>(
    `/reports/${encodeURIComponent(reportId)}/verify${query}`
  )

  return response.data
}