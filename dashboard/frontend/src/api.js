let writeToken

export async function api(path, body) {
  if (body && !writeToken) {
    const session = await api('/session')
    writeToken = session.write_token
  }
  const response = await fetch('/api' + path, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'Content-Type': 'application/json', 'X-Dashboard-Token': writeToken } : {},
    body: body ? JSON.stringify(body) : undefined
  })
  let data
  try { data = await response.json() } catch { throw new Error('服务返回无效响应，请检查后端') }
  if (!response.ok) {
    if (response.status === 403) writeToken = undefined
    throw new Error(data.error?.message || '请求失败')
  }
  return data
}

export function resetSession() { writeToken = undefined }
