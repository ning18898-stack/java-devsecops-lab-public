import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import RunCard from '../src/components/RunCard.vue'
import FindingDetail from '../src/components/FindingDetail.vue'
import { api, resetSession } from '../src/api'

const finding = {
  id: 1, title: '<img src=x onerror="alert(1)">', severity: 'high', status: 'unreviewed', version: 1,
  allowed_transitions: ['confirmed', 'false_positive', 'accepted_risk'],
  observations: [{ id: 1, tool: 'semgrep', rule_id: 'unit-test', title: '<script>alert(1)</script>',
    run_id: 'unit-test', fingerprint: 'x', source_revision: 'x', timestamp: '2026-10-12T12:00:00Z',
    source_location: { path: 'apps/vulnerable-app/src/main/java/Test.java', line: 10 },
    source_snippet: '<script>window.xss=true</script>', evidence: [] }],
  history: [], repairs: [], verifications: [], associated_from: [], merged_into: null
}

afterEach(() => { vi.unstubAllGlobals(); resetSession() })

describe('真实接口组件的数据语义', () => {
  it('ZAP 零告警仍展示执行成功', () => {
    const wrapper = mount(RunCard, { props: { run: { id: 'unit-test', status: 'COMPLETED', timestamp: '2026-10-12T12:00:00Z', source_revision: '123456789', steps: [{ tool: 'zap', execution_status: 'COMPLETED', finding_count: 0, execution_mode: 'actual-execution' }] } } })
    expect(wrapper.text()).toContain('执行成功')
    expect(wrapper.text()).toContain('0 观察项')
    expect(wrapper.text()).not.toContain('执行失败')
  })
  it('失败数量为未知，历史复用有标记', () => {
    const wrapper = mount(RunCard, { props: { run: { id: 'unit-test', status: 'PARTIAL', timestamp: '2026-10-12T12:00:00Z', source_revision: '123456789', steps: [{ tool: 'codeql', execution_status: 'FAILED', finding_count: null, execution_mode: 'historical-reuse' }] } } })
    expect(wrapper.text()).toContain('— 观察项')
    expect(wrapper.text()).toContain('历史结果复用')
  })
  it('报告、源码、标题以文本转义，不能执行 HTML', () => {
    const wrapper = mount(FindingDetail, { props: { finding, runs: [], busy: false } })
    expect(wrapper.find('img').exists()).toBe(false)
    expect(wrapper.find('script').exists()).toBe(false)
    expect(wrapper.text()).toContain('<script>window.xss=true</script>')
    expect(wrapper.text()).toContain('管理项，不代表已验证的独立漏洞')
  })
  it('状态提交含版本与操作依据，独立状态保留', async () => {
    const wrapper = mount(FindingDetail, { props: { finding, runs: [], busy: false } })
    await wrapper.find('select').setValue('confirmed')
    await wrapper.find('textarea').setValue('明确的人工研判依据')
    await wrapper.find('form').trigger('submit.prevent')
    expect(wrapper.emitted('mutate')[0]).toEqual(['status', { status: 'confirmed', version: 1, note: '明确的人工研判依据', verification_id: null }])
    expect(wrapper.text()).toContain('接受风险')
    expect(wrapper.text()).toContain('误报')
  })
  it('修复声明与未定复测结论分别展示', () => {
    const wrapper = mount(FindingDetail, { props: { finding: { ...finding, status: 'pending_verification', repairs: [{ id: 1, reference: 'unit-test', note: '测试声明', timestamp: '2026-10-12T12:00:00Z' }], verifications: [{ id: 1, conclusion: 'inconclusive', scope: '仅测试展示', note: '测试结论未定', evidence_ids: [], timestamp: '2026-10-12T12:00:00Z' }] }, runs: [], busy: false } })
    expect(wrapper.text()).toContain('修复声明 #1')
    expect(wrapper.text()).toContain('复测 #1 · 结论未定')
    expect(wrapper.text()).toContain('声明尚需实际复测')
  })
})

describe('API 客户端', () => {
  it('写请求取得会话令牌，发往真实 API 路径', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ write_token: 'unit-test-token' }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ imported: true }) })
    vi.stubGlobal('fetch', fetcher)
    await api('/imports', { run_id: 'unit-test' })
    expect(fetcher.mock.calls[0][0]).toBe('/api/session')
    expect(fetcher.mock.calls[1][1].headers['X-Dashboard-Token']).toBe('unit-test-token')
    expect(fetcher.mock.calls[1][0]).toBe('/api/imports')
  })
  it('服务错误与无效响应可显示，不静默返回假数据', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 409, json: async () => ({ error: { message: '不允许状态转换' } }) }))
    await expect(api('/findings')).rejects.toThrow('不允许状态转换')
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => { throw new Error('invalid') } }))
    await expect(api('/findings')).rejects.toThrow('服务返回无效响应')
  })
})
