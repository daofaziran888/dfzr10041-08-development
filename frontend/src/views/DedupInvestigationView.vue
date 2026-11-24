<template>
  <section class="page dedup-page">
    <header class="page-head">
      <div>
        <h2>去重调查 · 指纹命中明细与采样归并</h2>
        <p class="page-desc">
          从来源和时间范围查询被折叠的原日志，区分真实重复组与争议组；
          调查员领用经核验的重复组，按领用快照或补全范围取最新代表采样。
        </p>
      </div>
      <div class="page-actions">
        <button class="btn" data-testid="demo-seed" type="button" @click="loadDemo">
          装载演示证据
        </button>
        <button class="btn primary" data-testid="refresh-all" type="button" @click="reloadAll">
          刷新
        </button>
      </div>
    </header>

    <div class="stat-row">
      <article class="stat-card">
        <span class="stat-label">命中证据总数</span>
        <strong class="stat-value">{{ hitTotal }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">真实重复组</span>
        <strong class="stat-value">{{ duplicateGroups.length }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">争议组（不折叠）</span>
        <strong class="stat-value">{{ disputedGroups.length }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">当前调查状态</span>
        <strong class="stat-value">{{ investigation?.status ?? '未开启' }}</strong>
      </article>
    </div>

    <p v-if="errorMessage" class="error-text">{{ errorMessage }}</p>

    <!-- 命中明细查询 -->
    <h3 class="section-title">指纹命中明细（可翻页，可按来源 / 时间范围查询被折叠原行）</h3>
    <form class="filter-bar" @submit.prevent="loadHits(1)">
      <label class="filter-item">
        <span>去重规则</span>
        <input v-model="query.rule_id" data-testid="filter-rule" placeholder="如 DEDU-DEMO" />
      </label>
      <label class="filter-item">
        <span>来源关键字</span>
        <input v-model="query.source" data-testid="filter-source" placeholder="来源/应用标识/主机" />
      </label>
      <label class="filter-item">
        <span>开始时间</span>
        <input v-model="query.start" data-testid="filter-start" placeholder="2026-11-24T10:00:00" />
      </label>
      <label class="filter-item">
        <span>结束时间</span>
        <input v-model="query.end" data-testid="filter-end" placeholder="2026-11-24T11:00:00" />
      </label>
      <label class="filter-item">
        <span>指纹</span>
        <input v-model="query.fingerprint" data-testid="filter-fp" placeholder="完整指纹（可选）" />
      </label>
      <label class="filter-item check-item">
        <input v-model="includeDisputed" data-testid="filter-disputed" type="checkbox" />
        <span>包含争议组原行</span>
      </label>
      <button class="btn primary" data-testid="query-hits" type="submit">查询命中</button>
      <button class="btn ghost" type="button" @click="resetHitQuery">重置条件</button>
    </form>

    <table class="data-table">
      <thead>
        <tr>
          <th>原行编号</th>
          <th>所属组</th>
          <th>组类型</th>
          <th>来源位置</th>
          <th>发生时间</th>
          <th>原始请求内容</th>
          <th>代表</th>
          <th>重传</th>
          <th>重放</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="hit in hits"
          :key="hit.evidence_id"
          :data-testid="`hit-${hit.record_id}`"
          :data-kind="hit.group_kind"
        >
          <td>{{ hit.record_id }}</td>
          <td>
            <button class="link" type="button" @click="openGroup(hit.group_id)">
              {{ hit.group_id }}
            </button>
          </td>
          <td>
            <span :class="['kind-tag', hit.group_kind]">
              {{ hit.group_kind === 'disputed' ? '争议' : '真实重复' }}
            </span>
          </td>
          <td>
            {{ hit.source.app_label || hit.source.source_id }}
            <small>{{ hit.source.log_path }}#L{{ hit.source.line_number }}</small>
          </td>
          <td>{{ formatTime(hit.event_time) }}</td>
          <td class="content-cell">{{ hit.original_content }}</td>
          <td>{{ hit.is_representative ? '★ 最新代表' : '—' }}</td>
          <td>{{ hit.retransmit_count }}</td>
          <td>{{ hit.replay_hit ? '是' : '否' }}</td>
        </tr>
        <tr v-if="!hits.length">
          <td class="empty-state" colspan="9">暂无命中证据，可先装载演示证据或调整查询条件</td>
        </tr>
      </tbody>
    </table>

    <footer class="page-foot pagination">
      <span>共 {{ hitTotal }} 条命中，第 {{ page }} / {{ totalPages }} 页</span>
      <span>
        <button class="btn" type="button" :disabled="page <= 1" @click="loadHits(page - 1)">上一页</button>
        <button class="btn" type="button" :disabled="page >= totalPages" @click="loadHits(page + 1)">下一页</button>
      </span>
    </footer>

    <!-- 重复组 / 争议组 -->
    <form class="filter-bar" @submit.prevent="locateRecord">
      <label class="filter-item">
        <span>原行编号反查所属组</span>
        <input v-model="locateRecordId" data-testid="locate-record" placeholder="如 REC-0002" />
      </label>
      <button class="btn primary" data-testid="locate-btn" type="submit">查询所属重复组</button>
    </form>

    <h3 class="section-title">重复组与争议组（争议组原行不折叠，调查采样不可领用）</h3>
    <table class="data-table">
      <thead>
        <tr>
          <th>组编号</th>
          <th>类型</th>
          <th>成员数</th>
          <th>当前代表原行</th>
          <th>来源</th>
          <th>争议原因</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="group in groups" :key="group.group_id" :data-testid="`group-${group.group_id}`">
          <td>{{ group.group_id }}</td>
          <td>
            <span :class="['kind-tag', group.kind]">
              {{ group.kind === 'disputed' ? '争议组' : '真实重复' }}
            </span>
          </td>
          <td>{{ group.member_count }}</td>
          <td>{{ group.representative_record_id ?? '—' }}</td>
          <td>{{ group.sources.map((s) => s.app_label || s.source_id).join('、') }}</td>
          <td class="content-cell">{{ group.dispute_reasons.join('；') || '—' }}</td>
          <td class="row-actions">
            <button class="link" type="button" @click="openGroup(group.group_id)">查看明细</button>
            <button
              v-if="!group.is_disputed"
              class="link"
              type="button"
              data-testid="claim-group"
              @click="claimSelectedGroup(group.group_id)"
            >
              领用本组
            </button>
            <span v-else class="muted-text">未经核验不可领用</span>
          </td>
        </tr>
      </tbody>
    </table>

    <!-- 组明细弹窗 -->
    <div v-if="activeGroup" class="modal-backdrop" data-testid="group-modal" @click.self="activeGroup = null">
      <div class="modal wide-modal">
        <h3>组明细 {{ activeGroup.group_id }}</h3>
        <p class="page-desc">
          类型：
          <span :class="['kind-tag', activeGroup.kind]">
            {{ activeGroup.kind === 'disputed' ? '争议组（全部原行保留）' : '真实重复组' }}
          </span>
          ｜ 代表原行：{{ activeGroup.representative_record_id ?? '—' }}
        </p>
        <ul v-if="activeGroup.dispute_reasons.length" class="dispute-list">
          <li v-for="reason in activeGroup.dispute_reasons" :key="reason">{{ reason }}</li>
        </ul>
        <table class="data-table">
          <thead>
            <tr><th>原行</th><th>来源位置</th><th>时间</th><th>原始内容</th><th>代表</th></tr>
          </thead>
          <tbody>
            <tr v-for="member in activeGroup.members ?? []" :key="member.evidence_id">
              <td>{{ member.record_id }}</td>
              <td>{{ member.source.app_label }} {{ member.source.log_path }}#L{{ member.source.line_number }}</td>
              <td>{{ formatTime(member.event_time) }}</td>
              <td class="content-cell">{{ member.original_content }}</td>
              <td>{{ member.is_representative ? '★' : '—' }}</td>
            </tr>
          </tbody>
        </table>
        <div class="page-actions">
          <button
            v-if="!activeGroup.is_disputed"
            class="btn primary"
            type="button"
            @click="claimSelectedGroup(activeGroup.group_id)"
          >
            领用本组到当前调查
          </button>
          <button class="btn" type="button" @click="activeGroup = null">关闭</button>
        </div>
      </div>
    </div>

    <!-- 调查与采样 -->
    <h3 class="section-title">调查采样（领用快照 → 取样；已交付依据不被迟到原行覆盖）</h3>
    <div class="investigation-panel">
      <form class="filter-bar" @submit.prevent="startOrResume">
        <label class="filter-item">
          <span>调查编号（留空新建，填写则恢复原调查）</span>
          <input v-model="investigationId" data-testid="inv-id" placeholder="如 INV-000001" />
        </label>
        <label class="filter-item">
          <span>去重规则</span>
          <input v-model="invRuleId" data-testid="inv-rule" placeholder="DEDU-DEMO" />
        </label>
        <label class="filter-item">
          <span>采样计划</span>
          <input v-model="planId" data-testid="inv-plan" placeholder="SAMP-0001" />
        </label>
        <label class="filter-item">
          <span>调查员</span>
          <input v-model="investigator" data-testid="inv-user" placeholder="调查员" />
        </label>
        <button class="btn primary" data-testid="open-inv" type="submit">开启 / 恢复调查</button>
      </form>

      <div v-if="investigation" class="inv-detail" data-testid="inv-detail">
        <p>
          调查 <strong>{{ investigation.investigation_id }}</strong>
          状态：<strong>{{ investigation.status }}</strong>
          已领用组：{{ investigation.claimed_group_ids.join('、') || '（无）' }}
          交付依据：{{ investigation.delivery_id ?? '（尚未提交）' }}
        </p>
        <p class="page-desc">
          领用快照：每个组冻结在领用时的命中原行集合；未提交调查刷新范围可取迟到的更新代表，
          已提交调查不会被覆盖。
        </p>
      </div>

      <form class="filter-bar" @submit.prevent="submitSampling(false)">
        <label class="filter-item">
          <span>采样来源（逗号分隔，留空不限）</span>
          <input v-model="scopeSourceText" data-testid="scope-source" placeholder="app-under-review" />
        </label>
        <label class="filter-item">
          <span>范围开始</span>
          <input v-model="scopeStart" data-testid="scope-start" />
        </label>
        <label class="filter-item">
          <span>范围结束</span>
          <input v-model="scopeEnd" data-testid="scope-end" />
        </label>
        <button class="btn primary" data-testid="sample-snapshot" type="submit">
          按领用快照取样
        </button>
        <button class="btn" data-testid="sample-refresh" type="button" @click="submitSampling(true)">
          刷新补全范围取样
        </button>
      </form>

      <div v-if="delivery" class="delivery-box" data-testid="delivery-box">
        <p>
          交付 <strong>{{ delivery.delivery_id }}</strong>
          （{{ delivery.refreshed ? '补全范围' : '领用快照' }}）
          排除错误来源：{{ delivery.excluded_sources.join('、') || '无' }}
        </p>
        <table class="data-table">
          <thead>
            <tr><th>代表原行</th><th>来源位置</th><th>时间</th><th>所属组</th><th>原始内容</th></tr>
          </thead>
          <tbody>
            <tr v-for="rep in delivery.representatives" :key="rep.evidence_id">
              <td>{{ rep.record_id }}</td>
              <td>{{ rep.source.app_label }} {{ rep.source.log_path }}#L{{ rep.source.line_number }}</td>
              <td>{{ formatTime(rep.event_time) }}</td>
              <td>{{ rep.group_id }}</td>
              <td class="content-cell">{{ rep.original_content }}</td>
            </tr>
            <tr v-if="!delivery.representatives.length">
              <td class="empty-state" colspan="5">范围内无有效候选（可能全部属于错误来源或范围外原行）</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import {
  claimGroup,
  fetchGroupDetail,
  fetchGroups,
  fetchHits,
  fetchInvestigation,
  locateRecordGroup,
  openInvestigation,
  runSampling,
  seedDemoEvidence,
  type DedupGroup,
  type FingerprintHit,
  type Investigation,
  type SampleDelivery,
} from '@/api/dedup-service'

const hits = ref<FingerprintHit[]>([])
const groups = ref<DedupGroup[]>([])
const hitTotal = ref(0)
const page = ref(1)
const size = ref(5)
const includeDisputed = ref(true)
const errorMessage = ref('')
const activeGroup = ref<DedupGroup | null>(null)
const investigation = ref<Investigation | null>(null)
const delivery = ref<SampleDelivery | null>(null)

const query = ref({ rule_id: '', source: '', start: '', end: '', fingerprint: '' })
const investigationId = ref('')
const invRuleId = ref('DEDU-DEMO')
const planId = ref('SAMP-0001')
const investigator = ref('调查员')
const scopeSourceText = ref('')
const scopeStart = ref('')
const scopeEnd = ref('')
const locateRecordId = ref('')

const totalPages = computed(() => Math.max(1, Math.ceil(hitTotal.value / size.value)))
const duplicateGroups = computed(() => groups.value.filter((g) => !g.is_disputed))
const disputedGroups = computed(() => groups.value.filter((g) => g.is_disputed))

function formatTime(value: string): string {
  return value ? value.replace('T', ' ').slice(0, 19) : '—'
}

async function loadHits(targetPage: number) {
  errorMessage.value = ''
  try {
    const payload = await fetchHits({
      rule_id: query.value.rule_id || undefined,
      source: query.value.source || undefined,
      start: query.value.start || undefined,
      end: query.value.end || undefined,
      fingerprint: query.value.fingerprint || undefined,
      include_disputed: includeDisputed.value,
      page: targetPage,
      size: size.value,
    })
    hits.value = payload.items
    hitTotal.value = payload.total
    page.value = payload.page
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '命中明细查询失败'
  }
}

async function loadGroups() {
  try {
    groups.value = await fetchGroups(query.value.rule_id || undefined)
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '重复组查询失败'
  }
}

async function reloadAll() {
  await Promise.all([loadHits(page.value), loadGroups()])
  if (investigation.value) {
    investigation.value = await fetchInvestigation(investigation.value.investigation_id)
  }
}

function resetHitQuery() {
  query.value = { rule_id: '', source: '', start: '', end: '', fingerprint: '' }
  void loadHits(1)
}

async function openGroup(groupId: string) {
  errorMessage.value = ''
  try {
    activeGroup.value = await fetchGroupDetail(groupId)
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '组明细查询失败'
  }
}

async function locateRecord() {
  errorMessage.value = ''
  const recordId = locateRecordId.value.trim()
  if (!recordId) {
    errorMessage.value = '请输入要反查的原行编号'
    return
  }
  try {
    activeGroup.value = await locateRecordGroup(recordId)
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '未找到该原行所属的去重组'
  }
}

async function loadDemo() {
  errorMessage.value = ''
  try {
    const result = await seedDemoEvidence()
    window.alert(`演示证据已装载：命中 ${result.total_hits} 条，争议组 ${result.disputed_groups} 个`)
    await reloadAll()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '演示数据装载失败'
  }
}

async function startOrResume() {
  errorMessage.value = ''
  try {
    if (investigationId.value) {
      investigation.value = await fetchInvestigation(investigationId.value.trim())
    } else {
      investigation.value = await openInvestigation({
        rule_id: invRuleId.value,
        investigator: investigator.value,
        plan_id: planId.value,
      })
      investigationId.value = investigation.value.investigation_id
    }
    delivery.value = null
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '调查开启失败'
  }
}

async function claimSelectedGroup(groupId: string) {
  errorMessage.value = ''
  if (!investigation.value) {
    errorMessage.value = '请先开启或恢复调查，再领用重复组'
    return
  }
  try {
    const result = await claimGroup(investigation.value.investigation_id, groupId)
    investigation.value = result.investigation
    await loadGroups()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '领用失败'
  }
}

async function submitSampling(refresh: boolean) {
  errorMessage.value = ''
  if (!investigation.value) {
    errorMessage.value = '请先开启或恢复调查'
    return
  }
  try {
    const result = await runSampling(investigation.value.investigation_id, {
      scope_sources: scopeSourceText.value
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean),
      scope_start: scopeStart.value || undefined,
      scope_end: scopeEnd.value || undefined,
      refresh_scope: refresh,
    })
    delivery.value = result.delivery
    investigation.value = result.investigation
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '采样失败'
  }
}

onMounted(() => {
  void loadHits(1)
  void loadGroups()
})
</script>

<style scoped>
.section-title {
  margin: 20px 0 8px;
  font-size: 15px;
}
.kind-tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 12px;
}
.kind-tag.duplicate {
  background: #e0f2fe;
  color: #0369a1;
}
.kind-tag.disputed {
  background: #fee2e2;
  color: #b91c1c;
}
.content-cell {
  max-width: 320px;
  word-break: break-all;
}
.check-item {
  display: flex;
  align-items: center;
  gap: 6px;
}
.check-item input {
  width: auto;
}
.pagination {
  align-items: center;
}
.wide-modal {
  width: min(880px, 96vw);
}
.dispute-list {
  color: #b91c1c;
  font-size: 13px;
}
.investigation-panel {
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
}
.inv-detail {
  background: #f8fafc;
  border-radius: 6px;
  padding: 8px 12px;
  margin-bottom: 10px;
}
.delivery-box {
  margin-top: 12px;
  border-top: 1px dashed var(--border);
  padding-top: 10px;
}
.muted-text {
  color: var(--muted);
  font-size: 12px;
}
small {
  color: var(--muted);
}
</style>
