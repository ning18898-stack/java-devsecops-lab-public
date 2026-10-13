<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { api } from './api'
import { statuses, risks, executions, formatTime } from './labels'
import RunCard from './components/RunCard.vue'
import FindingDetail from './components/FindingDetail.vue'

const view = ref('overview')
const summary = ref(null)
const runs = ref([])
const runTotal = ref(0)
const runPage = ref(1)
const findings = ref([])
const total = ref(0)
const detail = ref(null)
const selectedRun = ref(null)
const allRuns = ref([])
const loading = ref(false)
const busy = ref(false)
const error = ref('')
const notice = ref('')
const evidence = ref(null)
const evidenceLoading = ref(false)
const evidenceError = ref('')
const runId = ref('')
const filterTool = ref('')
const filterRisk = ref('')
const filterStatus = ref('')
const query = ref('')
const sort = ref('updated_at')
const page = ref(1)
let loadVersion = 0

function navigate(target) { window.location.hash = target }
async function load() {
  const ticket = ++loadVersion
  loading.value = true
  error.value = ''
  notice.value = ''
  detail.value = null
  selectedRun.value = null
  const route = window.location.hash.slice(1) || 'overview'
  view.value = route.split('/')[0]
  try {
    if (view.value === 'overview') summary.value = await api('/summary')
    else if (view.value === 'runs') {
      const response = await api('/runs?page=' + runPage.value)
      if (ticket === loadVersion) { runs.value = response.items; runTotal.value = response.total }
    } else if (view.value === 'run') selectedRun.value = await api('/runs/' + encodeURIComponent(route.slice(4)))
    else if (view.value === 'findings') {
      const params = new URLSearchParams({ page: page.value, sort: sort.value, order: 'desc' })
      for (const [key, value] of [['tool', filterTool.value], ['severity', filterRisk.value], ['status', filterStatus.value], ['query', query.value]]) if (value) params.set(key, value)
      const response = await api('/findings?' + params)
      if (ticket === loadVersion) { findings.value = response.items; total.value = response.total }
    } else if (view.value === 'finding') {
      const [finding, scanRuns] = await Promise.all([api('/findings/' + encodeURIComponent(route.slice(8))), api('/runs?page_size=100')])
      if (ticket === loadVersion) { detail.value = finding; allRuns.value = scanRuns.items }
    } else throw new Error('页面不存在')
  } catch (failure) { if (ticket === loadVersion) error.value = failure.message }
  finally { if (ticket === loadVersion) loading.value = false }
}
async function importRun() {
  busy.value = true
  error.value = ''
  try {
    const response = await api('/imports', { run_id: runId.value })
    await load()
    notice.value = (response.imported ? '扫描报告已导入' : '该运行已导入，记录保持不变') + (response.warnings.length ? '；存在缺失证据，请查看运行详情' : '')
  } catch (failure) { error.value = failure.message }
  finally { busy.value = false }
}
async function mutate(action, body) {
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    detail.value = await api(`/findings/${detail.value.id}/${action}`, body)
    if (action === 'associations') navigate('finding/' + detail.value.id)
    notice.value = '操作已持久化并保留审计记录'
  } catch (failure) { error.value = failure.message }
  finally { busy.value = false }
}
async function showEvidence(id) {
  evidence.value = { id }
  evidenceLoading.value = true
  evidenceError.value = ''
  try { evidence.value = await api('/evidence/' + id) }
  catch (failure) { evidenceError.value = failure.message }
  finally { evidenceLoading.value = false }
}
function applyFilter() { page.value = 1; load() }
function changePage(delta) { page.value += delta; load() }
function changeRunPage(delta) { runPage.value += delta; load() }
onMounted(() => { window.addEventListener('hashchange', load); load() })
onUnmounted(() => window.removeEventListener('hashchange', load))
</script>

<template>
  <div class="shell">
    <aside class="sidebar">
      <a href="#overview" class="brand"><span class="brand-mark">S</span><span>安全观察台<small>JAVA DEVSECOPS LAB</small></span></a>
      <div class="nav-caption">工作空间 / LOCAL LAB</div>
      <nav aria-label="主导航"><a href="#overview" :class="{ active: view === 'overview' }">◈ 总览</a><a href="#runs" :class="{ active: ['runs', 'run'].includes(view) }">◷ 扫描历史</a><a href="#findings" :class="{ active: ['findings', 'finding'].includes(view) }">◎ 发现与漏洞管理</a></nav>
      <div class="sidebar-footer"><span class="live-dot"></span> 本机单用户模式<p>检测证据 → 人工研判 → 修复复测</p><small>仅回环访问 · 无生产认证能力</small></div>
    </aside>
    <main>
      <header class="topbar"><span>本地安全实验平台</span><span class="secondary">扫描报告 · 审计可追踪</span></header>
      <div class="content">
        <div class="page-heading"><div><p class="eyebrow">SECURITY WORKSPACE</p><h1>{{ { overview: '安全态势总览', runs: '扫描历史', run: '运行详情', findings: '发现与漏洞管理', finding: '发现详情与处置' }[view] }}</h1></div><button class="secondary-button" :disabled="loading" @click="load">刷新数据</button></div>
        <p v-if="notice" role="status" class="notice">{{ notice }}</p>
        <div v-if="error" role="alert" class="error">{{ error }}<button class="text-button" @click="load">重新加载</button></div>
        <div v-if="loading" role="status" class="loading">正在加载真实检测数据…</div>
        <template v-else-if="!error || detail">
          <template v-if="view === 'overview' && summary">
            <div class="hero"><div><span class="eyebrow">从检测结果到可追踪的处置</span><h2>证据先行，研判留痕。</h2><p>保留每个工具的原始观察，明确区分报告、修复声明与复测结论。</p></div><span class="hero-symbol" aria-hidden="true">◎</span></div>
            <div class="metric-grid"><article class="metric"><span>扫描运行</span><strong>{{ summary.runs }}</strong><small>导入的历史执行记录</small></article><article class="metric"><span>工具观察项</span><strong>{{ summary.observations }}</strong><small>各工具报告点，可能重叠</small></article><article class="metric"><span>管理项</span><strong>{{ summary.managed_findings }}</strong><small>按指纹跟踪 · 可人工关联</small></article><article class="metric"><span>独立漏洞数</span><strong class="text-metric">待确认</strong><small>不将报告数视为独立漏洞数</small></article></div>
            <div class="overview-grid"><section class="panel"><h3>管理项风险分布</h3><div v-if="!summary.managed_findings" class="empty">暂无发现数据</div><div v-for="(count, risk) in summary.risk" :key="risk" class="risk-row"><span class="badge" :class="risk">{{ risks[risk] }}</span><div class="risk-track"><div :style="{ width: `${count / summary.managed_findings * 100}%` }"></div></div><b>{{ count }}</b></div></section><section class="panel"><h3>处置进度</h3><div v-if="!summary.managed_findings" class="empty">导入运行后开始研判</div><div v-for="(count, status) in summary.statuses" :key="status" class="status-row"><span>{{ statuses[status] }}</span><b>{{ count }}</b></div></section></div>
            <section class="panel import-panel"><div><h3>导入扫描报告</h3><p class="secondary">从配置的允许目录读取 report.json 与证据；同一运行重复导入保持幂等。</p></div><form @submit.prevent="importRun"><label class="sr-only" for="run-import">运行标识</label><input id="run-import" v-model="runId" required pattern="[A-Za-z0-9_-]{1,100}" maxlength="100" placeholder="输入 run_id"><button :disabled="busy">{{ busy ? '导入中…' : '导入运行' }}</button></form></section>
            <div class="section-heading"><h3>近期运行</h3><a href="#runs">查看全部 →</a></div><p v-if="!summary.recent_runs.length" class="empty panel">尚未导入扫描运行</p><RunCard v-for="run in summary.recent_runs" :key="run.id" :run="run" @open="navigate('run/' + $event)" />
          </template>
          <template v-if="view === 'runs'"><p class="secondary">{{ runTotal }} 次运行 · 工具执行状态与报告数量分别展示，零告警也可以执行成功。</p><p v-if="!runs.length" class="empty panel">尚无扫描运行，请从总览导入真实记录</p><RunCard v-for="run in runs" :key="run.id" :run="run" @open="navigate('run/' + $event)" /><div class="pagination"><button class="secondary-button" :disabled="runPage === 1" @click="changeRunPage(-1)">上一页</button><span>第 {{ runPage }} 页 · 共 {{ runTotal }} 次运行</span><button class="secondary-button" :disabled="runPage * 20 >= runTotal" @click="changeRunPage(1)">下一页</button></div></template>
          <template v-if="view === 'run' && selectedRun"><RunCard :run="selectedRun" @open="() => {}" /><section class="panel"><h3>运行身份与关联</h3><p class="mono wrap">源码指纹：{{ selectedRun.source_fingerprint }}<br>原始报告 SHA-256：{{ selectedRun.report_sha256 }}</p><p>该运行共有 {{ selectedRun.observation_count }} 个观察项；独立漏洞数量尚未确认。</p><div class="button-row"><button v-for="id in selectedRun.finding_ids" :key="id" class="secondary-button" @click="navigate('finding/' + id)">管理项 #{{ id }}</button></div><h3>工具版本</h3><p v-for="(version, tool) in selectedRun.tool_versions" :key="tool">{{ tool }}：{{ version || '未提供' }}</p><h3>原始证据引用 · {{ selectedRun.evidence.length }}</h3><p class="secondary">仅允许扫描报告的脱敏文本预览；运维日志只保留引用。</p><div class="evidence-list"><button v-for="e in selectedRun.evidence" :key="e.id" class="secondary-button wrap" @click="showEvidence(e.id)">{{ e.path }} · {{ e.availability === 'available' ? '已校验' : '缺失' }}</button></div></section></template>
          <template v-if="view === 'findings'"><p class="secondary">管理项按同工具指纹跨运行追踪。跨工具关联需人工确认，不自动推断独立漏洞。</p><form class="filter-panel panel" @submit.prevent="applyFilter"><label>来源<select v-model="filterTool" aria-label="来源"><option value="">全部工具</option><option value="semgrep">Semgrep</option><option value="codeql">CodeQL</option><option value="zap">ZAP</option></select></label><label>风险<select v-model="filterRisk" aria-label="风险"><option value="">全部风险</option><option v-for="(label, value) in risks" v-show="value !== 'unknown'" :key="value" :value="value">{{ label }}</option></select></label><label>状态<select v-model="filterStatus" aria-label="状态"><option value="">全部状态</option><option v-for="(label, value) in statuses" :key="value" :value="value">{{ label }}</option></select></label><label>排序<select v-model="sort" aria-label="排序"><option value="updated_at">最近更新</option><option value="created_at">最近创建</option><option value="severity">风险优先</option></select></label><label>搜索<input aria-label="搜索" v-model="query" maxlength="200" placeholder="搜索描述"></label><button>筛选</button></form><div class="finding-list panel"><div class="section-heading"><h3>管理项列表</h3><span>{{ total }} 项</span></div><p v-if="!findings.length" class="empty">没有符合条件的发现项</p><button v-for="f in findings" :key="f.id" class="finding-row" @click="navigate('finding/' + f.id)"><span class="finding-id">#{{ f.id }}</span><span class="finding-title">{{ f.title }}<small>{{ f.tools.join(' / ').toUpperCase() }} · {{ f.observation_count }} 个观察项</small></span><span class="badge" :class="f.severity">{{ risks[f.severity] || '未知风险' }}</span><span class="badge">{{ statuses[f.status] }}</span><span aria-hidden="true">→</span></button></div><div class="pagination"><button class="secondary-button" :disabled="page === 1" @click="changePage(-1)">上一页</button><span>第 {{ page }} 页 · 共 {{ total }} 项</span><button class="secondary-button" :disabled="page * 20 >= total" @click="changePage(1)">下一页</button></div></template>
          <FindingDetail v-if="view === 'finding' && detail" :key="detail.id" :finding="detail" :runs="allRuns" :busy="busy" @mutate="mutate" @evidence="showEvidence" @open-finding="navigate('finding/' + $event)" />
        </template>
        <footer>Java DevSecOps Lab · 所有处置都应回到证据 · 时间显示为 Asia/Shanghai</footer>
      </div>
    </main>
    <div v-if="evidence" class="modal-backdrop" @click.self="evidence = null"><section class="evidence-modal" role="dialog" aria-modal="true" aria-label="原始证据预览"><div class="section-heading"><h3>证据预览</h3><button class="secondary-button" @click="evidence = null">关闭预览</button></div><p v-if="evidenceLoading" role="status">正在读取已校验的证据…</p><p v-else-if="evidenceError" role="alert">{{ evidenceError }}</p><template v-else><p>{{ evidence.path }}</p><p class="mono wrap">SHA-256：{{ evidence.sha256 }}</p><p class="secondary">脱敏文本预览 · {{ evidence.truncated ? '内容已截断' : '完整预览' }} · 原始快照不可修改</p><pre>{{ evidence.content }}</pre></template></section></div>
  </div>
</template>
