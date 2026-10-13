<script setup>
import { executions, formatTime } from '../labels'
defineProps({ run: Object })
defineEmits(['open'])
</script>

<template>
  <article class="run-card">
    <div class="run-heading">
      <button class="text-button mono" @click="$emit('open', run.id)">{{ run.id }}</button>
      <span class="badge" :class="run.status === 'COMPLETED' ? 'success' : 'muted'">{{ executions[run.status] }}</span>
    </div>
    <p v-if="run.id?.startsWith('release-example-')" class="secondary">脱敏演示数据，不代表公开候选的新扫描；时间已替换。</p>
    <p class="secondary">{{ run.id?.startsWith('release-example-') ? '示例时间（已脱敏）' : formatTime(run.timestamp) }} · 源码 {{ run.source_revision.slice(0, 8) }}</p>
    <div class="tool-grid">
      <div v-for="step in run.steps" :key="step.tool" class="tool-result">
        <strong>{{ step.tool.toUpperCase() }}</strong>
        <span>{{ executions[step.execution_status] }}</span>
        <b>{{ step.finding_count === null ? '—' : step.finding_count }} <small>观察项</small></b>
        <small>{{ run.id?.startsWith('release-example-') ? '演示报告内容' : step.execution_mode === 'historical-reuse' ? '历史结果复用' : step.execution_mode === 'actual-execution' ? '实际执行' : '未执行' }}</small>
      </div>
    </div>
  </article>
</template>
