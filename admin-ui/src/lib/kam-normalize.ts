// KAM / kiro-durable 导出 JSON 的归一化工具
//
// 解耦自 kam-import-dialog.tsx，统一处理三种已知导出格式：
//   1. KAM 旧版嵌套：{ version, accounts: [{ email, credentials: {...} }] }
//   2. KAM 1.8.3+ 平铺 camelCase：[{ email, refreshToken, ... }]
//   3. kiro-durable 平铺 snake_case：[{ email, refresh_token, ... }]
//
// 归一化目标：所有结构在 parseKamJson 出口处一律是 KamAccount[]：
//   - credentials 嵌套（旧版结构）
//   - credentials 内部全部 camelCase

// KAM 导出 JSON 中的账号结构（归一化后的目标形态）
export interface KamAccount {
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
  }
  machineId?: string
  status?: string
}

// 把 KAM 的 expiresAt 字段统一规范化为 RFC3339 字符串
// - 数字（毫秒时间戳）→ 转 ISO 字符串
// - 字符串 → trim 后返回，空串视为 undefined
// - 其他 → undefined
export function normalizeExpiresAt(value: unknown): string | undefined {
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

// 把 snake_case 字段统一映射到 camelCase（不删除原字段，仅追加）
// 兼容 kiro-durable 平铺导出格式
export function normalizeSnakeCase(
  obj: Record<string, unknown>,
): Record<string, unknown> {
  const need = (snake: string, camel: string) =>
    typeof obj[snake] === 'string' && typeof obj[camel] !== 'string'
  const pick = (snake: string, camel: string) => {
    if (need(snake, camel)) obj[camel] = obj[snake]
  }
  pick('refresh_token', 'refreshToken')
  pick('client_id', 'clientId')
  pick('client_secret', 'clientSecret')
  pick('access_token', 'accessToken')
  pick('auth_method', 'authMethod')
  pick('profile_arn', 'profileArn')
  // expires_at 可以是字符串也可以是数字，都要兼容
  if (
    typeof obj['expires_at'] !== 'undefined' &&
    typeof obj['expiresAt'] === 'undefined'
  ) {
    obj['expiresAt'] = obj['expires_at']
  }
  return obj
}

// 把单条记录归一化为 KamAccount 形态：
// - 顶层 / credentials 子对象都做 snake → camel 映射
// - 平铺格式（refreshToken 在根）封装到 credentials 嵌套结构
export function normalizeKamAccount(item: unknown): unknown {
  if (typeof item !== 'object' || item === null) return item
  const obj = item as Record<string, unknown>
  // 顶层 snake → camel
  normalizeSnakeCase(obj)
  // 旧版嵌套结构里 credentials 子对象也可能是 snake_case
  if (obj.credentials && typeof obj.credentials === 'object') {
    normalizeSnakeCase(obj.credentials as Record<string, unknown>)
  }
  // 新格式：refreshToken 直接在账号对象上，无 credentials 嵌套 → 封装一层
  if (typeof obj.refreshToken === 'string' && typeof obj.credentials === 'undefined') {
    const email = typeof obj.email === 'string' ? obj.email : undefined
    const userId =
      typeof obj.userId === 'string' || obj.userId === null
        ? (obj.userId as string | null)
        : undefined
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
    const clientSecret =
      typeof obj.clientSecret === 'string' ? obj.clientSecret : undefined
    const region = typeof obj.region === 'string' ? obj.region : undefined
    const authMethod = typeof obj.authMethod === 'string' ? obj.authMethod : undefined
    const provider = typeof obj.provider === 'string' ? obj.provider : undefined
    const startUrl = typeof obj.startUrl === 'string' ? obj.startUrl : undefined

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
      },
    }
  }
  return item
}

// 校验单条记录归一化后是否构成可导入的 KamAccount
export function isValidKamAccount(item: unknown): item is KamAccount {
  if (typeof item !== 'object' || item === null) return false
  const obj = item as Record<string, unknown>
  if (typeof obj.credentials !== 'object' || obj.credentials === null) return false
  const cred = obj.credentials as Record<string, unknown>
  return typeof cred.refreshToken === 'string' && cred.refreshToken.trim().length > 0
}

// 解析 KAM / durable JSON 字符串，输出归一化后的 KamAccount[]
//
// 支持的顶层结构：
//   - { version, accounts: [...] }      KAM 标准导出
//   - [...]                              直接数组（KAM 1.8.3+ / durable）
//   - { credentials: {...}, ... }        单账号旧格式
//   - { refreshToken: '...', ... }       单账号 KAM 平铺
//   - { refresh_token: '...', ... }      单账号 durable
export function parseKamJson(raw: string): KamAccount[] {
  const parsed = JSON.parse(raw)

  let rawItems: unknown[]
  if (parsed && Array.isArray(parsed.accounts)) {
    rawItems = parsed.accounts
  } else if (Array.isArray(parsed)) {
    rawItems = parsed
  } else if (parsed && parsed.credentials && typeof parsed.credentials === 'object') {
    rawItems = [parsed]
  } else if (parsed && typeof parsed.refreshToken === 'string') {
    rawItems = [parsed]
  } else if (parsed && typeof parsed.refresh_token === 'string') {
    rawItems = [parsed]
  } else {
    throw new Error('无法识别的 KAM / durable JSON 格式')
  }

  const normalizedItems = rawItems.map(normalizeKamAccount)
  const validAccounts = normalizedItems.filter(isValidKamAccount)

  if (rawItems.length > 0 && validAccounts.length === 0) {
    throw new Error(
      `共 ${rawItems.length} 条记录，但均缺少有效的 credentials.refreshToken`,
    )
  }

  if (validAccounts.length < rawItems.length) {
    const skipped = rawItems.length - validAccounts.length
    console.warn(`KAM 导入：跳过 ${skipped} 条缺少有效 credentials.refreshToken 的记录`)
  }

  return validAccounts
}
