import { useState, useMemo, useRef } from 'react'
import { toast } from 'sonner'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, XCircle, AlertCircle, Loader2, Upload } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { useCredentials } from '@/hooks/use-credentials'
import {
  batchImportCredentials,
  getProxyPool,
  type BatchImportItemEvent,
  type BatchImportSummary,
} from '@/api/credentials'
import type { AddCredentialRequest } from '@/types/api'
import { extractErrorMessage, sha256Hex } from '@/lib/utils'

interface KamImportDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

// KAM 导出 JSON 中的账号结构
interface KamAccount {
  email?: string
  userId?: string | null
  nickname?: string
  idp?: string
  credentials: {
    refreshToken: string
    accessToken?: string
    profileArn?: string
    // KAM 1.6.9+ 新版导出为毫秒时间戳数字，旧版为 RFC3339 字符串
    expiresAt?: string | number
    clientId?: string
    clientSecret?: string
    region?: string
    authMethod?: string
    provider?: string
    startUrl?: string
    /** External IdP token 端点（Microsoft Entra 等） */
    tokenEndpoint?: string
    /** External IdP OAuth 作用域 */
    scopes?: string
    /** External IdP Issuer URL（可选元数据） */
    issuerUrl?: string
  }
  machineId?: string
  status?: string
}

// 把 KAM 的 expiresAt 字段统一规范化为 RFC3339 字符串
// - 数字（毫秒时间戳）→ 转 ISO 字符串
// - 字符串 → trim 后返回，空串视为 undefined
// - 其他 → undefined
function normalizeExpiresAt(value: unknown): string | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    const date = new Date(value)
    return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
  }
  if (typeof value === 'string') {
    const trimmed = value.trim()
    return trimmed.length > 0 ? trimmed : undefined
  }
  return undefined
}

/**
 * 从 accessToken（JWT）的 iss / scp / azp 字段反推 External IdP 元数据。
 *
 * 适用场景：KAM 导出 Microsoft Entra 账号时只填了 accessToken / refreshToken / clientId，
 * 没填 tokenEndpoint / issuerUrl / scopes（KAM 的导出格式缺陷）。这些信息其实都已经
 * 编码在 accessToken 的 payload 里，本函数无网络解码 JWT、推导出完整元数据。
 *
 * 输入：accessToken 字符串（无效 JWT 直接返回 null）
 * 输出：{ tokenEndpoint, issuerUrl, scopes, clientIdHint } 或 null
 *
 * 只支持 Microsoft（iss 含 login.microsoftonline.com）。其它 OIDC 提供商以后可以扩展。
 */
function detectEntraFromAccessToken(
  accessToken: string | undefined,
): { tokenEndpoint: string; issuerUrl: string; scopes: string; clientIdHint?: string } | null {
  if (!accessToken) return null
  const parts = accessToken.split('.')
  if (parts.length !== 3) return null
  let payload: Record<string, unknown>
  try {
    // Base64URL → Base64 → UTF-8。浏览器 atob 不接 base64url，先替换。
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = b64 + '==='.slice((b64.length + 3) % 4)
    const json = decodeURIComponent(
      atob(padded)
        .split('')
        .map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(''),
    )
    payload = JSON.parse(json)
  } catch {
    return null
  }
  const iss = typeof payload.iss === 'string' ? payload.iss : ''
  if (!iss.includes('login.microsoftonline.com')) return null
  // iss 格式：https://login.microsoftonline.com/{tenant}/v2.0 或 .../v1.0
  // 推导：
  //   issuerUrl   = iss
  //   tokenEndpoint = https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
  const tenantMatch = iss.match(/login\.microsoftonline\.com\/([^/]+)\//)
  const tenant = tenantMatch?.[1]
  if (!tenant) return null
  const tokenEndpoint = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`
  // scopes：优先用 JWT 自带的 scp（空格分隔的 scope 列表）；总是追加 offline_access 拿 refresh_token。
  // azp 是接收方 application ID（公共客户端通常 = aud），可用作 clientId 兜底。
  const scp = typeof payload.scp === 'string' ? payload.scp.trim() : ''
  const azp = typeof payload.azp === 'string' ? payload.azp.trim() : ''
  const aud = typeof payload.aud === 'string' ? payload.aud.trim() : ''
  // scp 形如 "codewhisperer:conversations codewhisperer:completions"；
  // 但 token 刷新需要带完整 audience 前缀的 scope（如 "api://{appId}/codewhisperer:conversations"）+ offline_access
  const appId = azp || aud
  let fullScopes: string
  if (scp && appId) {
    fullScopes =
      scp
        .split(/\s+/)
        .filter(Boolean)
        .map((s) => (s.includes('://') || s === 'offline_access' ? s : `api://${appId}/${s}`))
        .join(' ') + ' offline_access'
  } else if (appId) {
    fullScopes = `api://${appId}/codewhisperer:conversations api://${appId}/codewhisperer:completions offline_access`
  } else {
    fullScopes = 'codewhisperer:conversations codewhisperer:completions offline_access'
  }
  return {
    tokenEndpoint,
    issuerUrl: iss,
    scopes: fullScopes,
    clientIdHint: appId || undefined,
  }
}

interface VerificationResult {
  index: number
  status: 'pending' | 'checking' | 'verifying' | 'verified' | 'imported' | 'duplicate' | 'failed' | 'skipped'
  error?: string
  usage?: string
  email?: string
  credentialId?: number
  rollbackStatus?: 'success' | 'failed' | 'skipped'
  rollbackError?: string
}



// 兼容 KAM 1.8.3 新版平铺格式，统一转换为旧格式（credentials 嵌套结构）
function normalizeKamAccount(item: unknown): unknown {
  if (typeof item !== 'object' || item === null) return item
  const obj = item as Record<string, unknown>
  // 新格式：refreshToken 直接在账号对象上，无 credentials 嵌套
  if (typeof obj.refreshToken === 'string' && typeof obj.credentials === 'undefined') {
    const email = typeof obj.email === 'string' ? obj.email : undefined
    const userId =
      typeof obj.userId === 'string' || obj.userId === null ? (obj.userId as string | null) : undefined
    const nickname =
      typeof obj.nickname === 'string'
        ? obj.nickname
        : typeof obj.label === 'string'
          ? (obj.label as string)
          : undefined
    const status = typeof obj.status === 'string' ? obj.status : undefined
    const idp = typeof obj.idp === 'string' ? obj.idp : undefined
    const machineId = typeof obj.machineId === 'string' ? obj.machineId : undefined
    const accessToken = typeof obj.accessToken === 'string' ? obj.accessToken : undefined
    const profileArn = typeof obj.profileArn === 'string' ? obj.profileArn : undefined
    const expiresAt =
      typeof obj.expiresAt === 'string' || typeof obj.expiresAt === 'number'
        ? (obj.expiresAt as string | number)
        : undefined
    const clientId = typeof obj.clientId === 'string' ? obj.clientId : undefined
    const clientSecret = typeof obj.clientSecret === 'string' ? obj.clientSecret : undefined
    const region = typeof obj.region === 'string' ? obj.region : undefined
    const authMethod = typeof obj.authMethod === 'string' ? obj.authMethod : undefined
    const provider = typeof obj.provider === 'string' ? obj.provider : undefined
    const startUrl = typeof obj.startUrl === 'string' ? obj.startUrl : undefined
    const tokenEndpoint = typeof obj.tokenEndpoint === 'string' ? obj.tokenEndpoint : undefined
    const scopes = typeof obj.scopes === 'string' ? obj.scopes : undefined
    const issuerUrl = typeof obj.issuerUrl === 'string' ? obj.issuerUrl : undefined

    return {
      email,
      userId,
      nickname,
      idp,
      status,
      machineId,
      credentials: {
        refreshToken: obj.refreshToken,
        accessToken,
        profileArn,
        expiresAt,
        clientId,
        clientSecret,
        region,
        authMethod,
        provider,
        startUrl,
        tokenEndpoint,
        scopes,
        issuerUrl,
      },
    }
  }
  return item
}

// 校验元素是否为有效的 KAM 账号结构
function isValidKamAccount(item: unknown): item is KamAccount {
  if (typeof item !== 'object' || item === null) return false
  const obj = item as Record<string, unknown>
  if (typeof obj.credentials !== 'object' || obj.credentials === null) return false
  const cred = obj.credentials as Record<string, unknown>
  return typeof cred.refreshToken === 'string' && cred.refreshToken.trim().length > 0
}

// 解析 KAM 导出 JSON，支持单账号和多账号格式
function parseKamJson(raw: string): KamAccount[] {
  const parsed = JSON.parse(raw)

  let rawItems: unknown[]

  // 标准 KAM 导出格式：{ version, accounts: [...] }
  if (parsed.accounts && Array.isArray(parsed.accounts)) {
    rawItems = parsed.accounts
  }
  // 直接数组（含 KAM 1.8.3 新版平铺格式）
  else if (Array.isArray(parsed)) {
    rawItems = parsed
  }
  // 单个账号对象（旧格式，有 credentials 字段）
  else if (parsed.credentials && typeof parsed.credentials === 'object') {
    rawItems = [parsed]
  }
  // 单个账号对象（新格式，refreshToken 平铺）
  else if (typeof parsed.refreshToken === 'string') {
    rawItems = [parsed]
  }
  else {
    throw new Error('无法识别的 KAM JSON 格式')
  }

  // 兼容新格式：将平铺账号统一转换为 credentials 嵌套结构
  const normalizedItems = rawItems.map(normalizeKamAccount)
  const validAccounts = normalizedItems.filter(isValidKamAccount)

  if (rawItems.length > 0 && validAccounts.length === 0) {
    throw new Error(`共 ${rawItems.length} 条记录，但均缺少有效的 credentials.refreshToken`)
  }

  if (validAccounts.length < rawItems.length) {
    const skipped = rawItems.length - validAccounts.length
    console.warn(`KAM 导入：跳过 ${skipped} 条缺少有效 credentials.refreshToken 的记录`)
  }

  return validAccounts
}

export function KamImportDialog({ open, onOpenChange }: KamImportDialogProps) {
  const [jsonInput, setJsonInput] = useState('')
  const [importing, setImporting] = useState(false)
  const [skipErrorAccounts, setSkipErrorAccounts] = useState(true)
  const [progress, setProgress] = useState({ current: 0, total: 0 })
  const [currentProcessing, setCurrentProcessing] = useState<string>('')
  const [results, setResults] = useState<VerificationResult[]>([])
  const fileInputRef = useRef<HTMLInputElement>(null)
  // 进行中的 AbortController，用于"停止导入"：abort 让 fetch 流中断，
  // 服务端在下次写回事件时检测到接收端关闭即停止处理剩余账号。
  const abortRef = useRef<AbortController | null>(null)

  const { data: existingCredentials } = useCredentials()
  const queryClient = useQueryClient()
  const { data: proxyPool } = useQuery({
    queryKey: ['proxy-pool'],
    queryFn: getProxyPool,
    enabled: open,
  })

  const resetForm = () => {
    setJsonInput('')
    setProgress({ current: 0, total: 0 })
    setCurrentProcessing('')
    setResults([])
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  // 按原始下标局部更新单行结果
  const updateResult = (i: number, patch: Partial<VerificationResult>) => {
    setResults(prev => {
      const next = [...prev]
      next[i] = { ...next[i], ...patch }
      return next
    })
  }

  const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files ?? [])
    if (files.length === 0) return

    try {
      // 读取所有文件并合并 accounts，保留各自版本元信息以便排错
      const fileTexts = await Promise.all(
        files.map(async (f) => ({ name: f.name, text: await f.text() }))
      )

      const merged: unknown[] = []
      const failed: { name: string; reason: string }[] = []

      for (const { name, text } of fileTexts) {
        try {
          const parsed = JSON.parse(text)
          if (parsed && Array.isArray(parsed.accounts)) {
            merged.push(...parsed.accounts)
          } else if (Array.isArray(parsed)) {
            merged.push(...parsed)
          } else if (parsed && typeof parsed === 'object') {
            // 单账号对象（新/旧格式）
            merged.push(parsed)
          } else {
            failed.push({ name, reason: '无法识别的 JSON 结构' })
          }
        } catch (e) {
          failed.push({ name, reason: extractErrorMessage(e) })
        }
      }

      if (merged.length === 0) {
        toast.error(`所有文件均解析失败：${failed.map((f) => `${f.name}（${f.reason}）`).join('；')}`)
        return
      }

      // 合并后按统一格式输出，复用 textarea 现有的解析与预览逻辑
      const mergedJson = JSON.stringify({ version: 'merged', accounts: merged }, null, 2)
      setJsonInput(mergedJson)
      setResults([])

      const fileSummary = files.length === 1 ? files[0].name : `${files.length} 个文件`
      if (failed.length > 0) {
        toast.warning(
          `已加载 ${fileSummary}，合并 ${merged.length} 条记录；${failed.length} 个文件解析失败：${failed.map((f) => f.name).join('、')}`
        )
      } else {
        toast.success(`已加载 ${fileSummary}，合并 ${merged.length} 条记录`)
      }
    } catch (error) {
      toast.error('读取文件失败: ' + extractErrorMessage(error))
    } finally {
      // 清空 value 以便再次选择同名文件也能触发 onChange
      event.target.value = ''
    }
  }

  const handleImport = async (verify: boolean) => {
    // 先单独解析 JSON，给出精准的错误提示
    let validAccounts: KamAccount[]
    try {
      const accounts = parseKamJson(jsonInput)

      if (accounts.length === 0) {
        toast.error('没有可导入的账号')
        return
      }

      validAccounts = accounts.filter(a => a.credentials?.refreshToken)
      if (validAccounts.length === 0) {
        toast.error('没有包含有效 refreshToken 的账号')
        return
      }
    } catch (error) {
      toast.error('JSON 格式错误: ' + extractErrorMessage(error))
      return
    }

    try {
      setImporting(true)
      setProgress({ current: 0, total: validAccounts.length })

      // 初始化结果，标记 error 状态的账号为 skipped（不上传）
      const initialResults: VerificationResult[] = validAccounts.map((account, i) => {
        if (skipErrorAccounts && account.status === 'error') {
          return { index: i + 1, status: 'skipped' as const, email: account.email || account.nickname }
        }
        return { index: i + 1, status: 'pending' as const, email: account.email || account.nickname }
      })
      setResults(initialResults)

      // 客户端去重
      const existingTokenHashes = new Set(
        existingCredentials?.credentials
          .map(c => c.refreshTokenHash)
          .filter((hash): hash is string => Boolean(hash)) || []
      )

      const enabledProxies = proxyPool?.proxies.filter(p => p.enabled) ?? []

      // 本地预处理：跳过 error 账号、去重、校验、构造请求。
      // 通过的收集进 toImport（记录原始下标），不通过的行直接标终态。
      const toImport: { index: number; req: AddCredentialRequest }[] = []

      for (let i = 0; i < validAccounts.length; i++) {
        const account = validAccounts[i]

        // 跳过 error 状态的账号（initialResults 里已标 skipped）
        if (skipErrorAccounts && account.status === 'error') {
          continue
        }

        const cred = account.credentials
        const token = cred.refreshToken.trim()
        const tokenHash = await sha256Hex(token)

        updateResult(i, { status: 'checking' })

        // 检查重复
        if (existingTokenHashes.has(tokenHash)) {
          const existingCred = existingCredentials?.credentials.find(c => c.refreshTokenHash === tokenHash)
          updateResult(i, {
            status: 'duplicate',
            error: '该凭据已存在',
            email: existingCred?.email || account.email,
          })
          continue
        }
        existingTokenHashes.add(tokenHash)

        const rawClientId = cred.clientId?.trim() || undefined
        const clientSecret = cred.clientSecret?.trim() || undefined
        let tokenEndpoint = cred.tokenEndpoint?.trim() || undefined
        let scopes = cred.scopes?.trim() || undefined
        let issuerUrl = cred.issuerUrl?.trim() || undefined
        let rawAuthMethod = cred.authMethod?.trim().toLowerCase()
        const rawProvider = cred.provider?.trim()

        // KAM 导出 Entra 账号时常常丢字段（authMethod=social / provider=Google /
        // 缺 tokenEndpoint / issuerUrl / scopes），但 accessToken 的 iss 仍然指向
        // login.microsoftonline.com。这里反解 JWT 自动补齐元数据，把它正确识别为
        // external_idp，避免掉进 social 路径触发"social 不该带 clientId"的报错。
        const entra = detectEntraFromAccessToken(cred.accessToken?.trim())
        let clientId = rawClientId
        if (entra) {
          if (!tokenEndpoint) tokenEndpoint = entra.tokenEndpoint
          if (!issuerUrl) issuerUrl = entra.issuerUrl
          if (!scopes) scopes = entra.scopes
          if (!clientId && entra.clientIdHint) clientId = entra.clientIdHint
          // 强制覆盖 authMethod：KAM 把 Entra 标记成 'social' 是错的
          if (rawAuthMethod !== 'external_idp' && rawAuthMethod !== 'external-idp') {
            rawAuthMethod = 'external_idp'
          }
        }

        // 三路识别认证方式：
        // 1) 显式 authMethod=external_idp / provider=ExternalIdp / 携带 tokenEndpoint
        //    → external_idp（Microsoft Entra 等，公共客户端可没有 clientSecret）
        // 2) 同时有 clientId + clientSecret → idc（AWS SSO OIDC）
        // 3) 其余 → social
        const isExternalIdp =
          rawAuthMethod === 'external_idp' ||
          rawAuthMethod === 'external-idp' ||
          rawAuthMethod === 'externalidp' ||
          rawProvider?.toLowerCase() === 'externalidp' ||
          !!tokenEndpoint
        const authMethod: 'external_idp' | 'idc' | 'social' = isExternalIdp
          ? 'external_idp'
          : clientId && clientSecret
            ? 'idc'
            : 'social'
        const provider = rawProvider || account.idp?.trim() || undefined

        // External IdP 必须有 clientId + tokenEndpoint，否则刷新无门路
        if (isExternalIdp && (!clientId || !tokenEndpoint)) {
          updateResult(i, {
            status: 'failed',
            error: 'External IdP 凭据需要 clientId 与 tokenEndpoint',
          })
          continue
        }
        // social 模式不应携带 clientId / clientSecret（KAM 偶尔会把 Entra 账号
        // 错标 social 但带 clientId，detectEntraFromAccessToken 已覆盖大多数场景；
        // 走到这里说明既不是 Entra 也不是 idc，多余字段是数据噪音，明确拒绝）
        if (authMethod === 'social' && (clientId || clientSecret)) {
          updateResult(i, {
            status: 'failed',
            error: 'social 模式不应携带 clientId / clientSecret（如果是 idc 请同时提供两者；如果是 External IdP 请补 tokenEndpoint）',
          })
          continue
        }

        // KAM 账号无 proxyUrl 字段，无代理时从池中随机分配一个
        const proxyUrl = enabledProxies.length > 0
          ? enabledProxies[Math.floor(Math.random() * enabledProxies.length)].url
          : undefined

        toImport.push({
          index: i,
          req: {
            refreshToken: token,
            accessToken: cred.accessToken?.trim() || undefined,
            profileArn: cred.profileArn?.trim() || undefined,
            expiresAt: normalizeExpiresAt(cred.expiresAt),
            authMethod,
            provider,
            // KAM 的 region 同时用于 token 刷新与 API 请求；仅映射 authRegion
            // 会导致 API 请求回退到全局默认 region，跨 region 403
            authRegion: cred.region?.trim() || undefined,
            apiRegion: cred.region?.trim() || undefined,
            startUrl: cred.startUrl?.trim() || undefined,
            clientId,
            clientSecret,
            tokenEndpoint,
            scopes,
            issuerUrl,
            machineId: account.machineId?.trim() || undefined,
            email: account.email?.trim() || undefined,
            proxyUrl,
          },
        })
      }

      // 待上传的行标记为处理中
      for (const item of toImport) {
        updateResult(item.index, { status: 'verifying' })
      }

      if (toImport.length === 0) {
        setCurrentProcessing('没有需要上传的账号（全部跳过、重复或校验失败）')
      } else {
        setCurrentProcessing(
          `${verify ? '批量验活' : '直接导入'}中（${toImport.length} 个）…`,
        )
        // 一次性 POST，服务端有界并发处理，逐条通过 SSE 回传结果。
        // 事件 ev.index 是 toImport 内的位置，需映射回原始账号下标。
        const controller = new AbortController()
        abortRef.current = controller
        await batchImportCredentials(
          { credentials: toImport.map(t => t.req), concurrency: 8, verify },
          (ev: BatchImportItemEvent) => {
            const orig = toImport[ev.index]?.index ?? -1
            if (orig < 0) return
            if (ev.status === 'verified') {
              updateResult(orig, {
                status: 'verified',
                usage: ev.usage,
                email: ev.email,
                credentialId: ev.credentialId,
              })
              setCurrentProcessing(ev.email ? `验活成功: ${ev.email}` : '验活成功')
            } else if (ev.status === 'imported') {
              updateResult(orig, {
                status: 'imported',
                email: ev.email,
                credentialId: ev.credentialId,
              })
              setCurrentProcessing(ev.email ? `已导入: ${ev.email}` : '已导入')
            } else if (ev.status === 'duplicate') {
              updateResult(orig, { status: 'duplicate', error: ev.error || '该凭据已存在' })
            } else {
              updateResult(orig, {
                status: 'failed',
                error: ev.error,
                rollbackStatus: ev.rolledBack ? 'success' : undefined,
              })
            }
          },
          (s: BatchImportSummary) => {
            const importedTotal = s.imported + s.verified
            if (verify) {
              if (s.failed === 0 && s.duplicate === 0) {
                toast.success(`成功导入并验活 ${s.verified} 个凭据`)
              } else {
                toast.info(
                  `验活完成：成功 ${s.verified} 个，重复 ${s.duplicate} 个，失败 ${s.failed} 个（已排除 ${s.rolledBack}）`
                )
                if (s.rolledBack < s.failed) {
                  toast.warning(`有 ${s.failed - s.rolledBack} 个失败凭据回滚未完成，请手动处理`)
                }
              }
            } else {
              if (s.failed === 0 && s.duplicate === 0) {
                toast.success(`直接导入 ${importedTotal} 个凭据（未验活）`)
              } else {
                toast.info(
                  `导入完成：成功 ${importedTotal} 个，重复 ${s.duplicate} 个，失败 ${s.failed} 个`
                )
              }
            }
          },
          controller.signal,
        )
      }

      // 刷新凭据列表
      await queryClient.invalidateQueries({ queryKey: ['credentials'] })
    } catch (error) {
      // 用户点击"停止"→ AbortError，服务端停止处理剩余账号；已完成的保留。
      if (error instanceof DOMException && error.name === 'AbortError') {
        toast.info('已停止导入（已完成的账号保留）')
        await queryClient.invalidateQueries({ queryKey: ['credentials'] })
      } else {
        toast.error('导入失败: ' + extractErrorMessage(error))
      }
    } finally {
      abortRef.current = null
      setImporting(false)
    }
  }

  const getStatusIcon = (status: VerificationResult['status']) => {
    switch (status) {
      case 'pending':
        return <div className="w-5 h-5 rounded-full border-2 border-gray-300" />
      case 'checking':
      case 'verifying':
        return <Loader2 className="w-5 h-5 animate-spin text-blue-500" />
      case 'verified':
        return <CheckCircle2 className="w-5 h-5 text-green-500" />
      case 'imported':
        return <CheckCircle2 className="w-5 h-5 text-sky-500" />
      case 'duplicate':
        return <AlertCircle className="w-5 h-5 text-yellow-500" />
      case 'skipped':
        return <AlertCircle className="w-5 h-5 text-gray-400" />
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-500" />
    }
  }

  const getStatusText = (result: VerificationResult) => {
    switch (result.status) {
      case 'pending': return '等待中'
      case 'checking': return '检查重复...'
      case 'verifying': return '处理中...'
      case 'verified': return '验活成功'
      case 'imported': return '已导入（未验活）'
      case 'duplicate': return '重复凭据'
      case 'skipped': return '已跳过（error 状态）'
      case 'failed':
        if (result.rollbackStatus === 'success') return '验活失败（已排除）'
        if (result.rollbackStatus === 'failed') return '验活失败（未排除）'
        return '处理失败（未创建）'
    }
  }

  // 预览解析结果
  const { previewAccounts, parseError } = useMemo(() => {
    if (!jsonInput.trim()) return { previewAccounts: [] as KamAccount[], parseError: '' }
    try {
      return { previewAccounts: parseKamJson(jsonInput), parseError: '' }
    } catch (e) {
      return { previewAccounts: [] as KamAccount[], parseError: extractErrorMessage(e) }
    }
  }, [jsonInput])

  const errorAccountCount = previewAccounts.filter(a => a.status === 'error').length

  // 已终结（verified/imported/duplicate/failed/skipped）的行数，驱动进度条
  const finalizedCount = results.filter(
    r =>
      r.status === 'verified' ||
      r.status === 'imported' ||
      r.status === 'duplicate' ||
      r.status === 'failed' ||
      r.status === 'skipped'
  ).length

  return (
    <Dialog
      open={open}
      onOpenChange={(newOpen) => {
        if (!newOpen) {
          if (importing) {
            // 导入过程中关闭 = 停止导入（abort 服务端流）
            abortRef.current?.abort()
          } else {
            resetForm()
          }
        }
        onOpenChange(newOpen)
      }}
    >
      <DialogContent className="sm:max-w-2xl max-h-[80vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>KAM 账号导入</DialogTitle>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 py-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium">KAM 导出 JSON</label>
              <div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="application/json,.json"
                  multiple
                  className="hidden"
                  onChange={handleFileSelect}
                />
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={importing}
                >
                  <Upload className="w-4 h-4 mr-1.5" />
                  选择文件
                </Button>
              </div>
            </div>
            <textarea
              placeholder={'粘贴 Kiro Account Manager 导出的 JSON，或点击右上角“选择文件”导入\n\n支持 KAM 1.8.3+ 新版平铺格式：\n[\n  {\n    "email": "...",\n    "refreshToken": "...",\n    "clientId": "...",\n    "clientSecret": "...",\n    "region": "us-east-1"\n  }\n]\n\n（可选的 authMethod 字段会被忽略，系统会根据 clientId/clientSecret 自动判断）\n\n也支持旧版嵌套格式：\n{\n  "version": "1.5.0",\n  "accounts": [\n    {\n      "email": "...",\n      "credentials": {\n        "refreshToken": "...",\n        "clientId": "...",\n        "clientSecret": "...",\n        "region": "us-east-1"\n      }\n    }\n  ]\n}'}
              value={jsonInput}
              onChange={(e) => setJsonInput(e.target.value)}
              disabled={importing}
              className="flex min-h-[200px] w-full rounded-xl border border-input bg-background/60 px-3.5 py-2.5 text-sm transition-[border-color,background-color,box-shadow] duration-150 ease-apple placeholder:text-muted-foreground/70 hover:border-border focus-visible:outline-none focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring/30 focus-visible:bg-background disabled:cursor-not-allowed disabled:opacity-50 font-mono"
            />
          </div>

          {/* 解析预览 */}
          {parseError && (
            <div className="text-sm text-red-600 dark:text-red-400">解析失败: {parseError}</div>
          )}
          {previewAccounts.length > 0 && !importing && results.length === 0 && (
            <div className="space-y-2">
              <div className="text-sm text-muted-foreground">
                识别到 {previewAccounts.length} 个账号
                {errorAccountCount > 0 && `（其中 ${errorAccountCount} 个为 error 状态）`}
              </div>
              {errorAccountCount > 0 && (
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={skipErrorAccounts}
                    onChange={(e) => setSkipErrorAccounts(e.target.checked)}
                    className="rounded border-gray-300"
                  />
                  跳过 error 状态的账号
                </label>
              )}
            </div>
          )}

          {/* 导入进度和结果 */}
          {(importing || results.length > 0) && (
            <>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>{importing ? '导入进度' : '导入完成'}</span>
                  <span>{finalizedCount} / {progress.total}</span>
                </div>
                <div className="w-full bg-secondary rounded-full h-2">
                  <div
                    className="bg-primary h-2 rounded-full transition-all"
                    style={{ width: `${progress.total > 0 ? (finalizedCount / progress.total) * 100 : 0}%` }}
                  />
                </div>
                {importing && currentProcessing && (
                  <div className="text-xs text-muted-foreground">{currentProcessing}</div>
                )}
              </div>

              <div className="flex gap-4 text-sm">
                <span className="text-green-600 dark:text-green-400">
                  ✓ 验活成功: {results.filter(r => r.status === 'verified').length}
                </span>
                <span className="text-sky-600 dark:text-sky-400">
                  ✓ 已导入: {results.filter(r => r.status === 'imported').length}
                </span>
                <span className="text-yellow-600 dark:text-yellow-400">
                  ⚠ 重复: {results.filter(r => r.status === 'duplicate').length}
                </span>
                <span className="text-red-600 dark:text-red-400">
                  ✗ 失败: {results.filter(r => r.status === 'failed').length}
                </span>
                <span className="text-gray-500">
                  ○ 跳过: {results.filter(r => r.status === 'skipped').length}
                </span>
              </div>

              <div className="border rounded-md divide-y max-h-[300px] overflow-y-auto">
                {results.map((result) => (
                  <div key={result.index} className="p-3">
                    <div className="flex items-start gap-3">
                      {getStatusIcon(result.status)}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">
                            {result.email || `账号 #${result.index}`}
                          </span>
                          <span className="text-xs text-muted-foreground">
                            {getStatusText(result)}
                          </span>
                        </div>
                        {result.usage && (
                          <div className="text-xs text-muted-foreground mt-1">用量: {result.usage}</div>
                        )}
                        {result.error && (
                          <div className="text-xs text-red-600 dark:text-red-400 mt-1">{result.error}</div>
                        )}
                        {result.rollbackError && (
                          <div className="text-xs text-red-600 dark:text-red-400 mt-1">回滚失败: {result.rollbackError}</div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        <DialogFooter>
          {importing ? (
            <Button
              type="button"
              variant="destructive"
              onClick={() => abortRef.current?.abort()}
            >
              停止导入
            </Button>
          ) : (
            <>
              <Button
                type="button"
                variant="outline"
                onClick={() => { onOpenChange(false); resetForm() }}
              >
                {results.length > 0 ? '关闭' : '取消'}
              </Button>
              {results.length === 0 && (
                <>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => handleImport(false)}
                    disabled={!jsonInput.trim() || previewAccounts.length === 0 || !!parseError}
                  >
                    直接导入（不验活）
                  </Button>
                  <Button
                    type="button"
                    onClick={() => handleImport(true)}
                    disabled={!jsonInput.trim() || previewAccounts.length === 0 || !!parseError}
                  >
                    开始导入并验活
                  </Button>
                </>
              )}
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
