/** 去重调查 API：串联去重命中证据与采样归并入口。 */
import { request } from './client'

export type SourceLocator = {
  source_id: string
  source_name: string
  app_label: string
  log_path: string
  line_number: number
  source_host: string
}

export type FingerprintHit = {
  evidence_id: string
  rule_id: string
  fingerprint: string
  group_id: string
  group_kind: 'duplicate' | 'disputed' | string
  record_id: string
  source: SourceLocator
  event_time: string
  original_content: string
  parsed_fields: Record<string, string>
  is_representative: boolean
  retransmit_count: number
  replay_hit: boolean
}

export type DedupGroup = {
  group_id: string
  rule_id: string
  fingerprint: string
  kind: 'duplicate' | 'disputed' | string
  is_disputed: boolean
  member_count: number
  evidence_ids: string[]
  representative_id: string | null
  representative_record_id: string | null
  anchor_time: string | null
  dispute_reasons: string[]
  sources: SourceLocator[]
  members?: FingerprintHit[]
}

export type Investigation = {
  investigation_id: string
  rule_id: string
  investigator: string
  plan_id: string
  status: 'opened' | 'claimed' | 'submitted' | string
  claimed_group_ids: string[]
  claimed_snapshot: Record<string, string[]>
  delivery_id: string | null
  created_at: string
  updated_at: string
}

export type SampleDelivery = {
  delivery_id: string
  investigation_id: string
  plan_id: string
  representative_ids: string[]
  representatives: FingerprintHit[]
  group_ids: string[]
  scope_sources: string[]
  scope_start: string | null
  scope_end: string | null
  refreshed: boolean
  excluded_sources: string[]
  created_at: string
}

export type HitQuery = {
  rule_id?: string
  fingerprint?: string
  group_id?: string
  source?: string
  start?: string
  end?: string
  include_disputed?: boolean
  page?: number
  size?: number
}

export type HitPage = {
  items: FingerprintHit[]
  total: number
  page: number
  size: number
}

async function readJson<T>(response: Response): Promise<T> {
  const payload = await response.json()
  if (!response.ok) {
    throw new Error(payload?.detail ?? `接口返回 ${response.status}`)
  }
  return payload as T
}

export async function fetchHits(query: HitQuery): Promise<HitPage> {
  const params = new URLSearchParams()
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      params.set(key, String(value))
    }
  })
  const response = await request(`/api/dedup/hits?${params.toString()}`)
  return readJson<HitPage>(response)
}

export async function fetchGroups(ruleId?: string, kind?: string): Promise<DedupGroup[]> {
  const params = new URLSearchParams()
  if (ruleId) params.set('rule_id', ruleId)
  if (kind) params.set('kind', kind)
  const response = await request(`/api/dedup/groups?${params.toString()}`)
  const payload = await readJson<{ items: DedupGroup[] }>(response)
  return payload.items
}

export async function fetchGroupDetail(groupId: string): Promise<DedupGroup> {
  const response = await request(`/api/dedup/groups/${groupId}`)
  return readJson<DedupGroup>(response)
}

export async function locateRecordGroup(recordId: string): Promise<DedupGroup> {
  const response = await request(`/api/dedup/records/${encodeURIComponent(recordId)}/group`)
  return readJson<DedupGroup>(response)
}

export async function openInvestigation(input: {
  rule_id: string
  investigator: string
  plan_id: string
  investigation_id?: string
}): Promise<Investigation> {
  const response = await request('/api/dedup/investigations', {
    method: 'POST',
    body: JSON.stringify(input),
  })
  return readJson<Investigation>(response)
}

export async function fetchInvestigation(investigationId: string): Promise<Investigation> {
  const response = await request(`/api/dedup/investigations/${investigationId}`)
  return readJson<Investigation>(response)
}

export async function claimGroup(
  investigationId: string,
  groupId: string,
): Promise<{ investigation: Investigation; group: DedupGroup }> {
  const response = await request(
    `/api/dedup/investigations/${investigationId}/claims`,
    { method: 'POST', body: JSON.stringify({ group_id: groupId }) },
  )
  return readJson(response)
}

export async function runSampling(
  investigationId: string,
  input: {
    plan_id?: string
    scope_sources: string[]
    scope_start?: string
    scope_end?: string
    refresh_scope: boolean
  },
): Promise<{ delivery: SampleDelivery; investigation: Investigation }> {
  const response = await request(
    `/api/dedup/investigations/${investigationId}/sampling`,
    { method: 'POST', body: JSON.stringify(input) },
  )
  return readJson(response)
}

export async function markSourceError(sourceId: string): Promise<void> {
  const response = await request(`/api/dedup/sources/${encodeURIComponent(sourceId)}/error`, {
    method: 'POST',
  })
  await readJson(response)
}

export async function seedDemoEvidence(): Promise<Record<string, number>> {
  const response = await request('/api/dedup/demo-seed', { method: 'POST' })
  return readJson(response)
}
