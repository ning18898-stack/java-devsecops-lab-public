export const statuses = {
  unreviewed: '待研判', confirmed: '已确认', fixing: '修复中',
  pending_verification: '待复测', closed: '已关闭', false_positive: '误报', accepted_risk: '接受风险'
}
export const risks = { critical: '严重', high: '高风险', medium: '中风险', low: '低风险', informational: '信息', unknown: '未知' }
export const executions = {
  COMPLETED: '执行成功', FAILED: '执行失败', PARTIAL: '部分完成', NOT_EXECUTED: '未执行',
  INTERRUPTED: '已中断', TIMED_OUT: '超时', TARGET_UNREACHABLE: '目标不可达'
}
export const conclusions = { inconclusive: '结论未定', still_present: '仍然存在', remediated: '人工确认已修复' }
export const formatTime = value => new Date(value).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false })
