import axios from 'axios'
import { storage } from '@/lib/storage'
import type {
  CredentialsStatusResponse,
  BalanceResponse,
  AvailableModelsResponse,
  SuccessResponse,
  SetDisabledRequest,
  SetPriorityRequest,
  AddCredentialRequest,
  AddCredentialResponse,
  UpdateCredentialRequest,
  UpdateRefreshTokenRequest,
  ProxyPoolEntry,
  ProxyPoolResponse,
  AddProxyRequest,
  BatchAddProxyRequest,
  BatchAddProxyResponse,
  AssignProxyRequest,
  ProxyCheckResponse,
  ProxyCheckAllResponse,
  AssignRoundRobinResponse,
  StartIdcLoginRequest,
  StartIdcLoginResponse,
  PollIdcLoginResponse,
  StartSocialLoginRequest,
  StartSocialLoginResponse,
  PollSocialLoginResponse,
  CompleteSocialLoginRequest,
  GlobalProxyResponse,
  SetGlobalProxyRequest,
  UpdateConfigResponse,
  SetUpdateConfigRequest,
  ImageUpdateResponse,
  UpdateCheckInfo,
  GitHubRateLimitInfo,
  UpdateAdminKeyRequest,
} from '@/types/api'

// 创建 axios 实例
const api = axios.create({
  baseURL: '/api/admin',
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
})

/**
 * 按当前浏览器访问地址自动派生 OAuth 回调公网地址。
 *
 * 面板与 API 同源（API 用相对 /api/admin 前缀），故浏览器自身知道的 origin 就是最可信的公网地址。
 * 浏览器授权后会落到 `${origin}/api/admin/auth/callback/oauth/callback`，由服务端公网回调路由接收。
 * 远程部署（Render / VPS / Docker）零配置即可用；若需强制覆盖，在后端 config.json 配 callbackBaseUrl。
 */
function deriveCallbackBaseUrl(): string {
  return `${window.location.origin}/api/admin/auth/callback`
}

// 请求拦截器添加 API Key
api.interceptors.request.use((config) => {
  const apiKey = storage.getApiKey()
  if (apiKey) {
    config.headers['x-api-key'] = apiKey
  }
  return config
})

// 获取所有凭据状态
export async function getCredentials(): Promise<CredentialsStatusResponse> {
  const { data } = await api.get<CredentialsStatusResponse>('/credentials')
  return data
}

// ============ KAM 导出 ============

/** KAM 导出账号（KAM 1.8.3+ 平铺格式） */
export interface KamExportAccount {
  email?: string
  nickname?: string
  idp?: string
  provider?: string
  status?: string
  authMethod?: string
  region?: string
  startUrl?: string
  clientId?: string
  clientSecret?: string
  refreshToken?: string
  accessToken?: string
  profileArn?: string
  expiresAt?: string
  machineId?: string
}

export interface KamExportResponse {
  version: string
  exportedAt: string
  accounts: KamExportAccount[]
}

/** 导出凭据为 KAM 兼容 JSON（含 refreshToken 等敏感字段）。
 *  传入 `ids` 时仅导出这些凭据；省略则导出全部。 */
export async function exportKamCredentials(
  ids?: number[]
): Promise<KamExportResponse> {
  const params = ids && ids.length > 0 ? { ids: ids.join(',') } : undefined
  const { data } = await api.get<KamExportResponse>('/credentials/export', { params })
  return data
}

// 设置凭据禁用状态
export async function setCredentialDisabled(
  id: number,
  disabled: boolean
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(
    `/credentials/${id}/disabled`,
    { disabled } as SetDisabledRequest
  )
  return data
}

// 设置凭据优先级
export async function setCredentialPriority(
  id: number,
  priority: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(
    `/credentials/${id}/priority`,
    { priority } as SetPriorityRequest
  )
  return data
}

// 重置失败计数
export async function resetCredentialFailure(
  id: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/reset`)
  return data
}

// 强制刷新 Token
export async function forceRefreshToken(
  id: number
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/refresh`)
  return data
}

// 解除凭据的账号级风控冷却
export async function clearThrottle(id: number): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/clear-throttle`)
  return data
}

// 强制清零凭据的并发计数（处理卡死/泄漏的槽位）
export async function clearConcurrency(id: number): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/clear-concurrency`)
  return data
}

// 获取凭据余额
//
// `force=true` 时附带 ?force=true 查询参数，让后端跳过 5 分钟内存缓存直接拉上游。
// 用于用户主动点「刷新余额」/ 验活 / 导入后等期望立即拿到真实状态的场景。
export async function getCredentialBalance(
  id: number,
  force = false,
): Promise<BalanceResponse> {
  const url = force
    ? `/credentials/${id}/balance?force=true`
    : `/credentials/${id}/balance`
  const { data } = await api.get<BalanceResponse>(url)
  return data
}

// 获取凭据当前可用的模型列表（按需实时查询上游）
export async function getCredentialModels(id: number): Promise<AvailableModelsResponse> {
  const { data } = await api.get<AvailableModelsResponse>(`/credentials/${id}/models`)
  return data
}

// 添加新凭据
export async function addCredential(
  req: AddCredentialRequest
): Promise<AddCredentialResponse> {
  const { data } = await api.post<AddCredentialResponse>('/credentials', req)
  return data
}

// ── 批量导入（SSE） ──────────────────────────────────────────────────────────

/** 批量导入 SSE 单条事件（对应请求数组下标 index） */
export interface BatchImportItemEvent {
  index: number
  status: 'verified' | 'imported' | 'duplicate' | 'failed'
  credentialId?: number
  email?: string
  usage?: string
  subscription?: string
  error?: string
  /** failed 且已回滚（删除）时为 true */
  rolledBack?: boolean
}

/** 批量导入末尾汇总事件 */
export interface BatchImportSummary {
  total: number
  /** 直接导入（未验活）成功数 */
  imported: number
  verified: number
  duplicate: number
  failed: number
  rolledBack: number
}

export interface BatchImportCredentialsRequest {
  credentials: AddCredentialRequest[]
  /** 并发度，缺省 8，服务端 clamp 到 [1, 16] */
  concurrency?: number
  /** 是否验活。true（缺省）：add 后取余额校验 + 失败回滚；false：仅 add 落库（直接导入） */
  verify?: boolean
}

/**
 * 批量导入凭据并验活（SSE 流）。
 *
 * 服务端有界并发地逐条 add + 取余额验活 + 失败回滚，每条完成即通过 SSE 推送
 * 一条 `BatchImportItemEvent`（乱序，带 index），全部完成后推送一条汇总。
 *
 * 用 fetch 读流而非 EventSource：EventSource 不支持 POST/自定义 header，
 * 而本端点需带 x-api-key 鉴权并 POST 大 body。
 *
 * @param onEvent      每条凭据结果
 * @param onSummary    末尾汇总
 * @param signal       AbortSignal，取消时中断流读取
 */
export async function batchImportCredentials(
  req: BatchImportCredentialsRequest,
  onEvent: (e: BatchImportItemEvent) => void,
  onSummary: (s: BatchImportSummary) => void,
  signal?: AbortSignal,
): Promise<void> {
  const apiKey = storage.getApiKey()
  const resp = await fetch('/api/admin/credentials/batch-import', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(apiKey ? { 'x-api-key': apiKey } : {}),
    },
    body: JSON.stringify(req),
    signal,
  })

  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`
    try {
      const body = await resp.json()
      msg = body?.message || body?.error || msg
    } catch {
      /* 忽略 JSON 解析失败，回退到状态码 */
    }
    throw new Error(msg)
  }
  if (!resp.body) throw new Error('响应缺少可读流')

  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })

    // SSE 事件以空行（\n\n）分隔
    let sep: number
    while ((sep = buffer.indexOf('\n\n')) !== -1) {
      const raw = buffer.slice(0, sep)
      buffer = buffer.slice(sep + 2)
      const dataLine = raw.split('\n').find((l) => l.startsWith('data:'))
      if (!dataLine) continue
      const jsonStr = dataLine.slice(5).trim()
      if (!jsonStr) continue
      let ev: Record<string, unknown>
      try {
        ev = JSON.parse(jsonStr)
      } catch {
        continue
      }
      if (ev.status === 'summary') {
        onSummary(ev.summary as BatchImportSummary)
      } else {
        onEvent(ev as unknown as BatchImportItemEvent)
      }
    }
  }
}

// 删除凭据
export async function deleteCredential(id: number): Promise<SuccessResponse> {
  const { data } = await api.delete<SuccessResponse>(`/credentials/${id}`)
  return data
}

// 重置单个凭据的成功次数
export async function resetSuccessCount(id: number): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/reset-stats`)
  return data
}

// 重置所有凭据的成功次数
export async function resetAllSuccessCount(): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>('/credentials/reset-stats')
  return data
}

// 一键禁用所有"已超额"凭据
export interface QuotaExceededResult {
  disabledIds: number[]
  skippedIds: number[]
}
export async function disableQuotaExceeded(): Promise<QuotaExceededResult> {
  const { data } = await api.post<QuotaExceededResult>('/credentials/disable-quota-exceeded')
  return data
}

// 设置单个凭据的超额开关
export async function setCredentialOverage(id: number, enabled: boolean): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/overage`, { enabled })
  return data
}

// 一键开启所有可开启超额的凭据
export interface EnableOverageAllResult {
  enabledIds: number[]
  skippedIds: number[]
  failedIds: number[]
  failureMessages: string[]
}
export async function enableOverageForAllCapable(): Promise<EnableOverageAllResult> {
  const { data } = await api.post<EnableOverageAllResult>('/credentials/overage/enable-all')
  return data
}

// 更新已禁用凭据的 refreshToken
export async function updateRefreshToken(
  id: number,
  req: UpdateRefreshTokenRequest
): Promise<SuccessResponse> {
  const { data } = await api.put<SuccessResponse>(`/credentials/${id}/refresh-token`, req)
  return data
}

// 更新凭据可编辑字段
export async function updateCredential(
  id: number,
  req: UpdateCredentialRequest
): Promise<SuccessResponse> {
  const { data } = await api.put<SuccessResponse>(`/credentials/${id}`, req)
  return data
}

// ============ 代理池 ============

// 获取代理池列表
export async function getProxyPool(): Promise<ProxyPoolResponse> {
  const { data } = await api.get<ProxyPoolResponse>('/proxy-pool')
  return data
}

// 添加代理
export async function addProxy(req: AddProxyRequest): Promise<ProxyPoolEntry> {
  const { data } = await api.post<ProxyPoolEntry>('/proxy-pool', req)
  return data
}

// 批量添加代理
export async function batchAddProxies(req: BatchAddProxyRequest): Promise<BatchAddProxyResponse> {
  const { data } = await api.post<BatchAddProxyResponse>('/proxy-pool/batch', req)
  return data
}

// 删除代理
export async function deleteProxy(id: number): Promise<SuccessResponse> {
  const { data } = await api.delete<SuccessResponse>(`/proxy-pool/${id}`)
  return data
}

// 设置代理启用/禁用
export async function setProxyEnabled(id: number, enabled: boolean): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/proxy-pool/${id}/enabled`, { enabled })
  return data
}

// 分配代理给凭据
export async function assignProxyToCredential(
  credentialId: number,
  req: AssignProxyRequest
): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${credentialId}/proxy`, req)
  return data
}

// 即时探测单个代理连通性
export async function checkProxy(id: number): Promise<ProxyCheckResponse> {
  const { data } = await api.post<ProxyCheckResponse>(`/proxy-pool/${id}/check`)
  return data
}

// 触发全部代理健康检查
export async function checkAllProxies(): Promise<ProxyCheckAllResponse> {
  const { data } = await api.post<ProxyCheckAllResponse>('/proxy-pool/check-all')
  return data
}

// 轮询批量分配可用代理给凭据
export async function assignProxiesRoundRobin(
  credentialIds?: number[] | null
): Promise<AssignRoundRobinResponse> {
  const { data } = await api.post<AssignRoundRobinResponse>('/proxy-pool/assign-round-robin', {
    credentialIds: credentialIds ?? null,
  })
  return data
}

// 获取负载均衡模式
export async function getLoadBalancingMode(): Promise<{ mode: 'priority' | 'balanced' }> {
  const { data } = await api.get<{ mode: 'priority' | 'balanced' }>('/config/load-balancing')
  return data
}

// 设置负载均衡模式
export async function setLoadBalancingMode(mode: 'priority' | 'balanced'): Promise<{ mode: 'priority' | 'balanced' }> {
  const { data } = await api.put<{ mode: 'priority' | 'balanced' }>('/config/load-balancing', { mode })
  return data
}

export interface AccountThrottleConfig {
  failover: boolean
  cooldownSecs: number
}

// 获取账号级风控故障转移配置
export async function getAccountThrottleConfig(): Promise<AccountThrottleConfig> {
  const { data } = await api.get<AccountThrottleConfig>('/config/account-throttle')
  return data
}

// 更新账号级风控故障转移配置
export async function setAccountThrottleConfig(
  patch: Partial<AccountThrottleConfig>,
): Promise<AccountThrottleConfig> {
  const { data } = await api.put<AccountThrottleConfig>('/config/account-throttle', patch)
  return data
}

// ============ 端点策略（起点 + runtime 降级 + 当前分布）============

export interface EndpointDistributionItem {
  endpoint: string
  count: number
}

export interface EndpointPolicy {
  defaultEndpoint: string
  runtimeFallbackEnabled: boolean
  distribution: EndpointDistributionItem[]
}

export async function getEndpointPolicy(): Promise<EndpointPolicy> {
  const { data } = await api.get<EndpointPolicy>('/config/endpoint-policy')
  return data
}

export async function setEndpointPolicy(
  patch: Partial<Pick<EndpointPolicy, 'defaultEndpoint' | 'runtimeFallbackEnabled'>>,
): Promise<EndpointPolicy> {
  const { data } = await api.put<EndpointPolicy>('/config/endpoint-policy', patch)
  return data
}

// 全局错误冷却策略（所有字段都是必填，由后端默认值兜底）
export interface ErrorCooldownPolicy {
  errorWindowSecs: number
  errorThreshold: number
  cooldownSecs: number
  autoDisableAfterTrips: number
  disableWindowSecs: number
}

export async function getErrorCooldownPolicy(): Promise<ErrorCooldownPolicy> {
  const { data } = await api.get<ErrorCooldownPolicy>('/config/cooldown-policy')
  return data
}

export async function setErrorCooldownPolicy(
  patch: Partial<ErrorCooldownPolicy>,
): Promise<ErrorCooldownPolicy> {
  const { data } = await api.put<ErrorCooldownPolicy>('/config/cooldown-policy', patch)
  return data
}

/**
 * 凭据级端点策略 PATCH 请求
 *
 * 三态语义（双层 Option）：
 * - 字段缺省 = 不更新
 * - 字段值 null = 重置为"跟随全局"
 * - 字段值具体值 = 强制覆盖
 */
export interface CredentialEndpointPolicyPatch {
  endpoint?: 'ide' | 'runtime' | null
  runtimeFallback?: boolean | null
}

export async function setCredentialEndpointPolicy(
  id: number,
  patch: CredentialEndpointPolicyPatch,
): Promise<void> {
  await api.patch(`/credentials/${id}/endpoint-policy`, patch)
}

/**
 * 凭据级冷却策略覆盖 PATCH 请求
 *
 * 子字段三态：缺省 = 不改；null = 重置；具体值 = 强制。
 * 设 clearAll=true 一键清空整个 override（凭据所有冷却字段都跟随全局）。
 */
export interface CredentialCooldownPolicyPatch {
  errorWindowSecs?: number | null
  errorThreshold?: number | null
  cooldownSecs?: number | null
  autoDisableAfterTrips?: number | null
  disableWindowSecs?: number | null
  clearAll?: boolean
}

export async function setCredentialCooldownPolicy(
  id: number,
  patch: CredentialCooldownPolicyPatch,
): Promise<void> {
  await api.patch(`/credentials/${id}/cooldown-policy`, patch)
}

export interface LogGovernanceConfig {
  traceEnabled: boolean
  traceRetentionDays: number
  usageLogRetentionDays: number
}

// 获取日志治理配置
export async function getLogGovernanceConfig(): Promise<LogGovernanceConfig> {
  const { data } = await api.get<LogGovernanceConfig>('/config/log-governance')
  return data
}

// 更新日志治理配置
export async function setLogGovernanceConfig(
  patch: Partial<LogGovernanceConfig>,
): Promise<LogGovernanceConfig> {
  const { data } = await api.put<LogGovernanceConfig>('/config/log-governance', patch)
  return data
}

// 发起 IdC 设备授权登录
export async function startIdcLogin(
  req: StartIdcLoginRequest
): Promise<StartIdcLoginResponse> {
  const { data } = await api.post<StartIdcLoginResponse>('/auth/idc/start', req)
  return data
}

// 轮询 IdC 登录状态
export async function pollIdcLogin(sessionId: string): Promise<PollIdcLoginResponse> {
  const { data } = await api.post<PollIdcLoginResponse>(`/auth/idc/poll/${sessionId}`)
  return data
}

// 获取全局代理配置
export async function getGlobalProxy(): Promise<GlobalProxyResponse> {
  const { data } = await api.get<GlobalProxyResponse>('/config/global-proxy')
  return data
}

// 设置全局代理配置
export async function setGlobalProxy(req: SetGlobalProxyRequest): Promise<SuccessResponse> {
  const { data } = await api.put<SuccessResponse>('/config/global-proxy', req)
  return data
}

// 获取镜像在线更新配置
export async function getUpdateConfig(): Promise<UpdateConfigResponse> {
  const { data } = await api.get<UpdateConfigResponse>('/config/update')
  return data
}

// 设置镜像在线更新配置
export async function setUpdateConfig(req: SetUpdateConfigRequest): Promise<UpdateConfigResponse> {
  const { data } = await api.put<UpdateConfigResponse>('/config/update', req)
  return data
}

// 拉取配置的 GHCR 镜像
export async function pullUpdateImage(): Promise<ImageUpdateResponse> {
  const { data } = await api.post<ImageUpdateResponse>('/system/update/pull')
  return data
}

// 拉取镜像并通过 Docker Compose 应用更新
export async function applyImageUpdate(): Promise<ImageUpdateResponse> {
  const { data } = await api.post<ImageUpdateResponse>('/system/update/apply')
  return data
}

// 通过本地备份 tag 回退到上一次更新前的镜像版本
export async function rollbackImageUpdate(): Promise<ImageUpdateResponse> {
  const { data } = await api.post<ImageUpdateResponse>('/system/update/rollback')
  return data
}

// 检查 GitHub Releases 是否有新版本（带后端 30 分钟缓存；force=true 强制刷新）
export async function checkSystemUpdate(force = false): Promise<UpdateCheckInfo> {
  const { data } = await api.get<UpdateCheckInfo>('/system/update/check', {
    params: force ? { force: 'true' } : undefined,
  })
  return data
}

// 查询 GitHub API 当前限流状态（可附带 token 用于"保存前先验证"）
export async function checkGitHubRateLimit(
  githubToken?: string,
): Promise<GitHubRateLimitInfo> {
  const body = githubToken ? { githubToken } : {}
  const { data } = await api.post<GitHubRateLimitInfo>(
    '/system/update/rate-limit',
    body,
  )
  return data
}

// 修改登录API密钥（adminApiKey —— 管理面板登录密钥）
export async function updateAdminKey(req: UpdateAdminKeyRequest): Promise<SuccessResponse> {
  const { data } = await api.put<SuccessResponse>('/config/admin-key', req)
  return data
}

// 发起 Social 登录
export async function startSocialLogin(
  req: StartSocialLoginRequest
): Promise<StartSocialLoginResponse> {
  const { data } = await api.post<StartSocialLoginResponse>('/auth/social/start', {
    callbackBaseUrl: deriveCallbackBaseUrl(),
    ...req,
  })
  return data
}

// 轮询 Social 登录状态
export async function pollSocialLogin(sessionId: string): Promise<PollSocialLoginResponse> {
  const { data } = await api.post<PollSocialLoginResponse>(`/auth/social/poll/${sessionId}`)
  return data
}

// 手动完成 Social 登录（远程访问时粘贴回调 URL）
export async function completeSocialLogin(
  sessionId: string,
  req: CompleteSocialLoginRequest
): Promise<PollSocialLoginResponse> {
  const { data } = await api.post<PollSocialLoginResponse>(`/auth/social/complete/${sessionId}`, req)
  return data
}

// ============ 重新登录（更新已有凭据 Token） ============

// 发起 Social 重新登录
export async function startSocialRelogin(
  credentialId: number,
  req: StartSocialLoginRequest
): Promise<StartSocialLoginResponse> {
  const { data } = await api.post<StartSocialLoginResponse>(
    `/credentials/${credentialId}/relogin/social/start`,
    {
      callbackBaseUrl: deriveCallbackBaseUrl(),
      ...req,
    }
  )
  return data
}

// 轮询 Social 重新登录状态
export async function pollSocialRelogin(
  credentialId: number,
  sessionId: string
): Promise<PollSocialLoginResponse> {
  const { data } = await api.post<PollSocialLoginResponse>(
    `/credentials/${credentialId}/relogin/social/poll/${sessionId}`
  )
  return data
}

// 手动完成 Social 重新登录（远程访问时粘贴回调 URL）
export async function completeSocialRelogin(
  credentialId: number,
  sessionId: string,
  req: CompleteSocialLoginRequest
): Promise<PollSocialLoginResponse> {
  const { data } = await api.post<PollSocialLoginResponse>(
    `/credentials/${credentialId}/relogin/social/complete/${sessionId}`,
    req
  )
  return data
}

// 发起 IdC 重新登录
export async function startIdcRelogin(
  credentialId: number,
  req: StartIdcLoginRequest
): Promise<StartIdcLoginResponse> {
  const { data } = await api.post<StartIdcLoginResponse>(
    `/credentials/${credentialId}/relogin/idc/start`,
    req
  )
  return data
}

// 轮询 IdC 重新登录状态
export async function pollIdcRelogin(
  credentialId: number,
  sessionId: string
): Promise<PollIdcLoginResponse> {
  const { data } = await api.post<PollIdcLoginResponse>(
    `/credentials/${credentialId}/relogin/idc/poll/${sessionId}`
  )
  return data
}

/** 对话测活：对该凭据发一条最小对话请求，验证能否正常对话（不只是余额查询） */
export async function testCredential(id: number): Promise<SuccessResponse> {
  const { data } = await api.post<SuccessResponse>(`/credentials/${id}/test`)
  return data
}

/** 预热结果 */
export interface WarmupResult {
  total: number
  success: number
  failed: number
  lastError?: string
}

/** 预热：对该凭据串行连发 count 次最小对话请求，唤醒冷启动慢的模型 */
export async function warmupCredential(id: number, count = 10): Promise<WarmupResult> {
  const { data } = await api.post<WarmupResult>(`/credentials/${id}/warmup?count=${count}`)
  return data
}
