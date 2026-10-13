<script setup>
import { ref } from 'vue'
import { api } from '../api'
import { statuses, risks, conclusions, formatTime } from '../labels'
const props = defineProps({ finding: Object, runs: Array, busy: Boolean })
const emit = defineEmits(['mutate', 'evidence', 'openFinding'])
const status = ref('')
const note = ref('')
const repairReference = ref('')
const repairNote = ref('')
const targetId = ref('')
const associateNote = ref('')
const verificationRun = ref('')
const repairId = ref('')
const conclusion = ref('inconclusive')
const scope = ref('')
const verificationNote = ref('')
const verificationId = ref('')
const availableEvidence = ref([])
const evidenceIds = ref([])
const evidenceError = ref('')

async function loadEvidence() {
  availableEvidence.value = []
  evidenceIds.value = []
  evidenceError.value = ''
  if (!verificationRun.value) return
  try {
    const run = await api('/runs/' + encodeURIComponent(verificationRun.value))
    availableEvidence.value = run.evidence.filter(e => e.availability === 'available')
  } catch (error) { evidenceError.value = error.message }
}
function mutate(action, body) { emit('mutate', action, body) }
</script>

<template>
  <div class="detail-layout">
    <section class="panel">
      <div class="section-heading"><span class="eyebrow">FINDING #{{ finding.id }}</span><span class="badge" :class="finding.severity">{{ risks[finding.severity] || '未知风险' }}</span></div>
      <h2>{{ finding.title }}</h2>
      <p><span class="badge">{{ statuses[finding.status] }}</span><span class="secondary"> · 管理项，不代表已验证的独立漏洞</span></p>
      <p v-if="finding.merged_into">已关联至 <button class="text-button" @click="$emit('openFinding', finding.merged_into)">管理项 #{{ finding.merged_into }}</button></p>
      <p v-if="finding.associated_from.length" class="secondary">人工关联来源：<button v-for="id in finding.associated_from" :key="id" class="text-button" @click="$emit('openFinding', id)">#{{ id }} </button></p>
      <h3>工具观察项 · {{ finding.observations.length }}</h3>
      <article v-for="observation in finding.observations" :key="observation.id" class="observation">
        <div class="section-heading"><strong>{{ observation.tool.toUpperCase() }}</strong><span class="secondary">{{ observation.rule_id }}</span></div>
        <p>{{ observation.title }}</p>
        <p class="mono wrap">{{ observation.source_location ? observation.source_location.path + ':' + observation.source_location.line : observation.target_url || '工具未提供源码位置' }}</p>
        <pre v-if="observation.source_snippet">{{ observation.source_snippet }}</pre>
        <p v-else class="secondary">该源码版本的代码片段不可用</p>
        <details><summary>执行与身份信息</summary><p class="mono wrap">运行：{{ observation.run_id }}<br>fingerprint：{{ observation.fingerprint }}<br>源码：{{ observation.source_revision }}</p><p class="secondary">置信度：{{ observation.confidence || '未提供' }} · {{ formatTime(observation.timestamp) }}</p></details>
        <div class="evidence-list"><button v-for="e in observation.evidence" :key="e.id" class="secondary-button" @click="$emit('evidence', e.id)">{{ e.path }} · {{ e.availability === 'available' ? '查看证据' : '证据缺失' }}</button></div>
      </article>
    </section>
    <aside>
      <section v-if="!finding.merged_into" class="panel">
        <h3>研判与生命周期</h3>
        <p class="secondary">每次处置须说明依据。待复测表示修复声明已登记，复测结论仍待确认。</p>
        <form @submit.prevent="mutate('status', { status, version: finding.version, note, verification_id: verificationId ? Number(verificationId) : null })">
          <label>下一状态<select aria-label="下一状态" v-model="status" required><option value="" disabled>选择允许的状态</option><option v-for="s in finding.allowed_transitions" :key="s" :value="s">{{ statuses[s] }}</option></select></label>
          <label v-if="status === 'closed'">关闭复测记录<select aria-label="关闭复测记录" v-model="verificationId" required><option value="">选择复测依据</option><option v-for="v in finding.verifications.filter(v => v.conclusion === 'remediated')" :key="v.id" :value="v.id">#{{ v.id }} · {{ conclusions[v.conclusion] }}</option></select></label>
          <label>操作依据<textarea aria-label="操作依据" v-model="note" required minlength="3" maxlength="4000" placeholder="描述研判依据、影响与处置理由"></textarea></label>
          <div class="button-row"><button :disabled="busy || !status">更新状态</button><button type="button" class="secondary-button" :disabled="busy || note.trim().length < 3" @click="mutate('notes', { note })">仅保存备注</button></div>
        </form>
      </section>
      <section v-if="finding.status === 'fixing' && !finding.merged_into" class="panel">
        <h3>登记修复声明</h3>
        <form @submit.prevent="mutate('repairs', { reference: repairReference, note: repairNote })">
          <label>修复引用<input aria-label="修复引用" v-model="repairReference" required minlength="3" maxlength="300" placeholder="提交 ID、补丁路径或修复说明引用"></label>
          <label>修复说明<textarea aria-label="修复说明" v-model="repairNote" required minlength="3" maxlength="4000"></textarea></label>
          <button :disabled="busy">保存修复声明</button>
        </form>
      </section>
      <section v-if="finding.status === 'pending_verification' && !finding.merged_into" class="panel">
        <h3>登记实际复测</h3>
        <p class="secondary">一次未报告不自动证明修复。须说明测试范围与证据如何验证根因；历史运行不能验证新修复。</p>
        <form @submit.prevent="mutate('verifications', { run_id: verificationRun, repair_id: Number(repairId), evidence_ids: evidenceIds.map(Number), conclusion, scope, note: verificationNote })">
          <label>修复声明<select aria-label="修复声明" v-model="repairId" required><option value="">选择修复声明</option><option v-for="r in finding.repairs" :key="r.id" :value="r.id">#{{ r.id }} · {{ r.reference }}</option></select></label>
          <label>复测运行<select aria-label="复测运行" v-model="verificationRun" required @change="loadEvidence"><option value="">选择已有扫描运行</option><option v-for="r in runs" :key="r.id" :value="r.id">{{ r.id }}</option></select></label>
          <label>证据引用<select v-model="evidenceIds" multiple required aria-label="复测证据"><option v-for="e in availableEvidence" :key="e.id" :value="e.id">{{ e.path }}</option></select></label>
          <p v-if="evidenceError" role="alert">{{ evidenceError }}</p>
          <label>复测结论<select aria-label="复测结论" v-model="conclusion"><option v-for="(label, value) in conclusions" :key="value" :value="value">{{ label }}</option></select></label>
          <label>测试范围<textarea aria-label="测试范围" v-model="scope" required minlength="10" maxlength="2000" placeholder="覆盖哪些根因、输入与路径，证据和剩余限制是什么"></textarea></label>
          <label>复测说明<textarea aria-label="复测说明" v-model="verificationNote" required minlength="3" maxlength="4000"></textarea></label>
          <button :disabled="busy">保存复测记录</button>
        </form>
      </section>
      <section v-if="finding.status === 'unreviewed' && !finding.merged_into" class="panel">
        <h3>人工确认关联</h3>
        <p class="secondary">仅在有依据确认同一安全问题时关联。所有原始观察项及来源历史均保留。</p>
        <form @submit.prevent="mutate('associations', { target_id: Number(targetId), version: finding.version, note: associateNote })">
          <label>目标管理项 ID<input aria-label="目标管理项 ID" v-model="targetId" type="number" min="1" required></label>
          <label>关联依据<textarea aria-label="关联依据" v-model="associateNote" required minlength="3" maxlength="4000"></textarea></label>
          <button class="secondary-button" :disabled="busy">确认关联</button>
        </form>
      </section>
    </aside>
    <section class="panel full-width">
      <h3>修复声明与复测结论</h3>
      <p v-if="!finding.repairs.length" class="empty">尚未登记修复声明</p>
      <article v-for="r in finding.repairs" :key="r.id" class="record"><strong>修复声明 #{{ r.id }} · {{ r.reference }}</strong><p>{{ r.note }}</p><small>{{ formatTime(r.timestamp) }} · 声明尚需实际复测</small></article>
      <p v-if="!finding.verifications.length" class="secondary">尚无实际复测结论；未宣称已修复</p>
      <article v-for="v in finding.verifications" :key="v.id" class="record"><strong>复测 #{{ v.id }} · {{ conclusions[v.conclusion] }}</strong><p>{{ v.scope }}</p><p>{{ v.note }}</p><p class="mono wrap">{{ v.run_id }} · 修复声明 #{{ v.repair_id }}</p><button v-for="id in v.evidence_ids" :key="id" class="text-button" @click="$emit('evidence', id)">证据 #{{ id }} </button><small>{{ formatTime(v.timestamp) }}</small></article>
    </section>
    <section class="panel full-width">
      <h3>完整操作历史</h3>
      <ol class="timeline"><li v-for="h in finding.history" :key="h.id"><span class="timeline-dot"></span><strong>{{ h.action === 'status' ? (statuses[h.from_status] + ' → ' + statuses[h.to_status]) : ({ import: '首次导入', note: '人工备注', repair: '修复声明', verification: '复测记录', associate: '人工关联' }[h.action] || h.action) }}</strong><p>{{ h.note }}</p><small>{{ formatTime(h.timestamp) }} · {{ h.actor }}</small></li></ol>
    </section>
  </div>
</template>
