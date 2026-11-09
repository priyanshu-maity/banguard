const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

export interface ProgressStage {
  id: string
  label: string
  status: 'pending' | 'running' | 'done' | 'skipped'
  detail?: string | null
  weight: number
}

export interface InvestigationProgress {
  stages: ProgressStage[]
  finished: boolean
  failed: boolean
}

export const newId = (): string =>
  typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : (Date.now().toString(36) + Math.random().toString(36).slice(2, 12)).padEnd(12, '0')

export async function getProgress(id: string): Promise<InvestigationProgress | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/investigate/${encodeURIComponent(id)}/progress`)
    if (!response.ok) return null
    const body = await response.json()
    return body?.data ?? null
  } catch {
    return null
  }
}

export function percent(p: InvestigationProgress): number {
  const live = p.stages.filter(s => s.status !== 'skipped')
  const total = live.reduce((n, s) => n + s.weight, 0)
  if (!total) return 0
  const got = live.reduce((n, s) => n + (s.status === 'done' ? s.weight : s.status === 'running' ? s.weight * 0.4 : 0), 0)
  return Math.min(96, (got / total) * 100)
}